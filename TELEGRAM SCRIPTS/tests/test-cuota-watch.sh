#!/usr/bin/env bash
# test-cuota-watch.sh — pruebas del vigilante de la cuota diaria.
#
#   bash "TELEGRAM SCRIPTS/tests/test-cuota-watch.sh"
#
# No manda nada a Telegram ni lee la base de verdad: se le pasan por entorno un
# send-alert.sh de mentira, que apunta los avisos en un fichero, y un sqlite3
# de mentira que devuelve lo que queramos. Los limites tambien van por entorno,
# asi que la prueba no depende de que ratelimit.py este instalado ni de lo que
# diga hoy.
#
# Lo que se comprueba es lo unico que puede salir mal de verdad en un
# vigilante: que avise cuando toca, que NO avise cuando no toca, que no se
# ponga a repetir, y que al cambiar el dia vuelva a contar como nuevo.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VIGILANTE="$AQUI/../cuota-watch.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

OK=0; MAL=0
comprueba() {
    local que="$1" esperado="$2" obtenido="$3"
    if [ "$esperado" = "$obtenido" ]; then
        OK=$((OK + 1)); printf '  ok    %s\n' "$que"
    else
        MAL=$((MAL + 1))
        printf '  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>\n' \
            "$que" "$esperado" "$obtenido"
    fi
}

cat > "$TMP/alert.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n---\n' "$1" >> "$AVISOS"
EOF
chmod +x "$TMP/alert.sh"

# sqlite3 de mentira: devuelve lo que diga $FILAS_USO, en formato "plat|n".
mkdir -p "$TMP/bin"
cat > "$TMP/bin/sqlite3" <<'EOF'
#!/usr/bin/env bash
[ -n "${FILAS_USO:-}" ] && printf '%s\n' "$FILAS_USO"
exit 0
EOF
chmod +x "$TMP/bin/sqlite3"

: > "$TMP/state.sqlite3"

# $1 = filas de uso   $2 = dia (opcional)
correr() {
    AVISOS="$TMP/avisos.txt" \
    FILAS_USO="${1:-}" \
    HOY="${2:-2026-09-11}" \
    LIMITES="abuseipdb 1000
virustotal 500" \
    PATH="$TMP/bin:$PATH" \
    ALERT="$TMP/alert.sh" \
    STATE_DB="$TMP/state.sqlite3" \
    STATE_DIR="$TMP" \
    STATE="$TMP/cuota.state" \
    bash "$VIGILANTE" 2>&1
}
avisos() {
    local n
    n=$(grep -c '^---$' "$TMP/avisos.txt" 2>/dev/null) || true
    printf '%s' "${n:-0}"
}

echo
echo "Por debajo del cupo"
: > "$TMP/avisos.txt"; rm -f "$TMP/cuota.state"
salida=$(correr "abuseipdb|979")
comprueba "979 de 1000 no manda nada" "0" "$(avisos)"
comprueba "y lo dice por la salida" "si" \
    "$( case "$salida" in *"sin novedad"*) echo si;; *) echo no;; esac )"

echo
echo "Se agota el cupo"
: > "$TMP/avisos.txt"; rm -f "$TMP/cuota.state"
correr "abuseipdb|1000" >/dev/null
comprueba "manda un aviso" "1" "$(avisos)"
comprueba "dice que la cuota se supero" "si" \
    "$( grep -q 'Cuota superada' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "nombra la plataforma en bonito" "si" \
    "$( grep -q 'AbuseIPDB' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "no la nombra en crudo" "0" \
    "$(grep -c '>abuseipdb<' "$TMP/avisos.txt" || true)"
comprueba "lleva las cifras" "si" \
    "$( grep -q '1000/1000' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "dice cuando vuelve" "si" \
    "$( grep -q 'Vuelve dentro de' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "y que el reinicio es en UTC" "si" \
    "$( grep -q '00:00 UTC' "$TMP/avisos.txt" && echo si || echo no )"

echo
echo "No se repite"
# Con cron cada pocos minutos, seguir avisando mientras siga agotado serian
# cientos de mensajes iguales al dia. A la tercera ya no los lee nadie.
: > "$TMP/avisos.txt"
correr "abuseipdb|1000" >/dev/null
correr "abuseipdb|1001" >/dev/null
correr "abuseipdb|1200" >/dev/null
comprueba "tres pasadas mas el mismo dia no mandan nada" "0" "$(avisos)"

echo
echo "Cambia el dia"
# La huella lleva la fecha: manana el cupo vuelve a agotarse y eso es una
# transicion NUEVA. Sin fecha en la huella, esto solo avisaria el primer dia.
: > "$TMP/avisos.txt"
correr "abuseipdb|20" "2026-09-12" >/dev/null
comprueba "el cupo restablecido se avisa" "1" "$(avisos)"
comprueba "y dice que vuelve a publicar" "si" \
    "$( grep -q 'Cuota restablecida' "$TMP/avisos.txt" && echo si || echo no )"
: > "$TMP/avisos.txt"
correr "abuseipdb|1000" "2026-09-12" >/dev/null
comprueba "y al agotarse otra vez, avisa de nuevo" "1" "$(avisos)"

echo
echo "Varias plataformas a la vez"
: > "$TMP/avisos.txt"; rm -f "$TMP/cuota.state"
correr "abuseipdb|1000
virustotal|500" >/dev/null
comprueba "dos plataformas agotadas son dos avisos" "2" "$(avisos)"
comprueba "sale VirusTotal" "si" \
    "$( grep -q 'VirusTotal' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "con SU limite, no el de la otra" "si" \
    "$( grep -q '500/500' "$TMP/avisos.txt" && echo si || echo no )"
: > "$TMP/avisos.txt"
correr "abuseipdb|1000
virustotal|12" >/dev/null
comprueba "si una se recupera y la otra no, solo avisa una" "1" "$(avisos)"
comprueba "y es la que se recupero" "si" \
    "$( grep -q 'restablecida' "$TMP/avisos.txt" && echo si || echo no )"

echo
echo "Se mira api_calls, no quota"
# El tropiezo facil: quota cuenta lo PUBLICADO y api_calls las LLAMADAS, que es
# contra lo que compara el limitador. En VirusTotal la mayoria de llamadas son
# consultas de hash que no publican nada; mirando quota el aviso no llegaria.
comprueba "la consulta pide api_calls" "si" \
    "$( grep -q 'FROM api_calls' "$VIGILANTE" && echo si || echo no )"
comprueba "y en solo lectura" "si" \
    "$( grep -q 'mode=ro' "$VIGILANTE" && echo si || echo no )"

echo
echo "Los limites salen de ratelimit.py"
# NO se comprueba "que no aparezca ningun 1000 en el fichero": el mensaje de
# --test es un EJEMPLO y ahi el literal es correcto. Lo que importa es que el
# aviso de verdad use el limite leido, y que se lea de la unica fuente buena.
comprueba "se importan de common.ratelimit" "si" \
    "$( grep -q 'from common.ratelimit import LIMITS' "$VIGILANTE" && echo si || echo no )"
comprueba "y el aviso de verdad usa el limite leido" "si" \
    "$( grep -q 'cuota de <code>${limite} llamadas/dia' "$VIGILANTE" && echo si || echo no )"

echo
echo "Casos de borde"
: > "$TMP/avisos.txt"; rm -f "$TMP/cuota.state"
salida=$(correr "")
comprueba "sin filas de uso no manda nada" "0" "$(avisos)"
: > "$TMP/avisos.txt"; rm -f "$TMP/state.sqlite3" "$TMP/cuota.state"
correr "abuseipdb|1000" >/dev/null
comprueba "sin base todavia no es un error" "0" "$?"
comprueba "y no manda nada" "0" "$(avisos)"

echo
echo "-------------------------------------"
printf 'ok: %d   fallos: %d\n' "$OK" "$MAL"
[ "$MAL" -eq 0 ] || exit 1
