#!/usr/bin/env bash
# test-breaker-watch.sh — pruebas del vigilante del cortacircuitos.
#
#   bash "TELEGRAM SCRIPTS/tests/test-breaker-watch.sh"
#
# No manda nada a Telegram ni lee la base de verdad: se le pasan por entorno
# un send-alert.sh de mentira, que apunta los avisos en un fichero, y un
# sqlite3 de mentira que devuelve lo que queramos. Lo que se comprueba es lo
# unico que puede salir mal de verdad en un vigilante: que avise cuando toca,
# que NO avise cuando no toca, y que no se ponga a repetir.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VIGILANTE="$AQUI/../breaker-watch.sh"

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

# send-alert.sh de mentira: apunta cada aviso en un fichero, uno por linea.
cat > "$TMP/alert.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n---\n' "$1" >> "$AVISOS"
EOF
chmod +x "$TMP/alert.sh"

# sqlite3 de mentira: devuelve lo que diga $FILA_BREAKER.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/sqlite3" <<'EOF'
#!/usr/bin/env bash
printf '%s' "${FILA_BREAKER:-}"
[ -n "${FILA_BREAKER:-}" ] && echo
exit 0
EOF
chmod +x "$TMP/bin/sqlite3"

: > "$TMP/state.sqlite3"          # tiene que existir para que no se salga

correr() {
    AVISOS="$TMP/avisos.txt" \
    FILA_BREAKER="${1:-}" \
    PATH="$TMP/bin:$PATH" \
    ALERT="$TMP/alert.sh" \
    STATE_DB="$TMP/state.sqlite3" \
    STATE_DIR="$TMP" \
    STATE="$TMP/breaker.state" \
    bash "$VIGILANTE" 2>&1
}
# Nada de "|| echo 0" al final: grep -c YA imprime 0 cuando no encuentra nada,
# y ademas sale con codigo 1, asi que ese "|| echo 0" anade un segundo cero y
# la funcion devuelve "0\n0". Es exactamente el mismo tropiezo que hubo en
# daily-digest.sh, y cae igual de bien la segunda vez.
avisos() {
    local n
    n=$(grep -c '^---$' "$TMP/avisos.txt" 2>/dev/null) || true
    printf '%s' "${n:-0}"
}

echo
echo "Sin novedad"
: > "$TMP/avisos.txt"
salida=$(correr "")
comprueba "sin salto no manda nada" "0" "$(avisos)"
comprueba "y lo dice por la salida" "si" \
    "$( case "$salida" in *"sin novedad"*) echo si;; *) echo no;; esac )"

echo
echo "Salta el cortacircuitos"
: > "$TMP/avisos.txt"
FILA="2026-08-21 04:12:07|3 rechazos de abuse.ch en 24 h; el ultimo, en malwarebazaar: query_status=file_not_allowed"
correr "$FILA" >/dev/null
comprueba "manda un aviso" "1" "$(avisos)"
comprueba "dice que ha saltado" "si" \
    "$( grep -q 'Cortacircuitos SALTADO' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "nombra las tres plataformas" "si" \
    "$( grep -q 'MalwareBazaar, ThreatFox y URLhaus' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "lleva la fecha del salto" "si" \
    "$( grep -q '2026-08-21 04:12:07' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "lleva el motivo, que es lo que hay que entender" "si" \
    "$( grep -q 'file_not_allowed' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "y el comando de rearme, entero" "si" \
    "$( grep -q -- '--reset-breaker' "$TMP/avisos.txt" && echo si || echo no )"

echo
echo "No se repite"
# Lo que arruina un vigilante: con cron cada pocos minutos, seguir avisando
# mientras siga saltado son cientos de mensajes iguales, y a la tercera vez ya
# no los lee nadie. Eso es lo mismo que no avisar, pero molestando.
: > "$TMP/avisos.txt"
correr "$FILA" >/dev/null
correr "$FILA" >/dev/null
correr "$FILA" >/dev/null
comprueba "tres pasadas mas con el mismo salto no mandan nada" "0" "$(avisos)"

echo
echo "Vuelve a saltar despues de rearmar"
: > "$TMP/avisos.txt"
correr "" >/dev/null                       # rearmado a mano
comprueba "el rearme se avisa" "1" "$(avisos)"
comprueba "y dice que vuelve a publicar" "si" \
    "$( grep -q 'rearmado' "$TMP/avisos.txt" && echo si || echo no )"
: > "$TMP/avisos.txt"
correr "" >/dev/null
comprueba "pero solo una vez" "0" "$(avisos)"
: > "$TMP/avisos.txt"
correr "2026-08-22 09:00:00|otro motivo" >/dev/null
comprueba "un salto NUEVO si vuelve a avisar" "1" "$(avisos)"

echo
echo "Texto de fuera"
# El motivo arrastra la respuesta de abuse.ch, que viene de fuera. Un "<"
# dentro dejaria el aviso en un 400 de Telegram --- y este es precisamente el
# aviso que menos nos podemos permitir perder.
: > "$TMP/avisos.txt"
rm -f "$TMP/breaker.state"
correr '2026-08-23 01:00:00|rechazo <b>raro</b> con & dentro' >/dev/null
comprueba "el motivo se escapa" "si" \
    "$( grep -q '&lt;b&gt;raro&lt;/b&gt;' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "y el & tambien" "si" \
    "$( grep -q 'con &amp; dentro' "$TMP/avisos.txt" && echo si || echo no )"
comprueba "no queda ningun < de fuera suelto" "0" \
    "$(sed -e 's/<\/\?\(strong\|code\|u\|b\)>//g' "$TMP/avisos.txt" | grep -c '<' || true)"

echo
echo "Casos de borde"
: > "$TMP/avisos.txt"
rm -f "$TMP/state.sqlite3" "$TMP/breaker.state"
salida=$(correr "")
comprueba "sin base todavia no es un error" "0" "$?"
comprueba "y no manda nada" "0" "$(avisos)"

echo
echo "-------------------------------------"
printf 'ok: %d   fallos: %d\n' "$OK" "$MAL"
[ "$MAL" -eq 0 ] || exit 1
