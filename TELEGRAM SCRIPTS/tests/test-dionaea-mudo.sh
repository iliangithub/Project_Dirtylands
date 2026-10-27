#!/usr/bin/env bash
# test-dionaea-mudo.sh — el vigilante de "Dionaea vivo pero mudo".
#
#   bash "TELEGRAM SCRIPTS/tests/test-dionaea-mudo.sh"
#
# ESTO NO ES UNA PRUEBA DE FORMATO, es la prueba de un control, y de uno que
# ya fallo dos veces en una semana:
#
#   - El 2026-08-23 a las 17:11 Dionaea se quedo en bucle. No volvio a anotar
#     una sola conexion hasta el 28. Cinco dias.
#   - Se reinicio el 28 a las 21:16. A las 21:17:31 recibio trafico MSSQL,
#     escribio dos "Incomplete TDS_Header" en el mismo milisegundo y se volvio
#     a quedar colgado. Diez horas de CPU quemada la mañana siguiente.
#
# Las dos veces TODO lo que se suele mirar decia que estaba bien: "docker ps"
# daba Up, el proceso existia, y el DNAT contaba los paquetes que entraban.
# dionaea-watch.sh se ejecutaba puntual cada cinco minutos y escribia "sin
# actividad nueva", que es lo mismo que escribe un dia tranquilo.
#
# Lo unico que distingue "no le ataca nadie" de "esta bloqueado" es CUANDO
# anoto la ultima conexion. Eso es lo que se comprueba aqui.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FUENTE="$AQUI/../DIONAEA/dionaea-watch.sh"

# El binario de verdad, no un doble: la funcion le pasa SQL y hay que saber
# que ese SQL le vale. Si falta, la suite se PARA en vez de ponerse verde ---
# casi todo lo de abajo es "no debe salir tal aviso", y sin base que leer no
# saldria nada y todo pasaria sin haber probado nada.
if ! command -v sqlite3 >/dev/null; then
    echo "NO SE PUEDE PROBAR: falta el binario sqlite3 (apt install sqlite3)." >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# La funcion se saca del fichero DESPLEGADO, no se copia aqui: una copia se
# queda vieja y la prueba seguiria en verde sobre codigo que ya no existe.
extraer() {
    awk -v n="$1" '
        $0 ~ "^"n"\\(\\) \\{" {dentro=1}
        dentro {print}
        dentro && /^}$/ {exit}
    ' "$FUENTE"
}

# Y los umbrales tambien salen del fichero, por lo mismo: si alguien cambia el
# valor por defecto alla, esta prueba tiene que verlo.
grep -E '^DIONAEA_MUDO_(HORAS|REPETIR)=' "$FUENTE" > "$TMP/fn.sh"
extraer vigilar_silencio >> "$TMP/fn.sh"

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

base() {   # $1 = fichero; $2... = horas de antiguedad de cada conexion
    local f="$1"; shift
    rm -f "$f"
    python3 - "$f" "$@" <<'FIN_PY'
import sqlite3
import sys
import time

db = sqlite3.connect(sys.argv[1])
db.execute("CREATE TABLE connections (connection INTEGER PRIMARY KEY,"
           " connection_type TEXT, connection_protocol TEXT,"
           " connection_timestamp INTEGER, local_port INTEGER, remote_host TEXT)")
ahora = int(time.time())
for i, horas in enumerate(sys.argv[2:], 1):
    db.execute("INSERT INTO connections VALUES (?,?,?,?,?,?)",
               (i, "accept", "smbd", ahora - int(float(horas) * 3600), 445,
                "1.2.3.%d" % i))
db.commit()
FIN_PY
}

# Se ejecuta la funcion con un send_telegram de mentira que apunta lo que se
# habria mandado. Devuelve el mensaje, y el MUDO_AVISADO resultante por la
# ultima linea, para poder encadenar pasadas.
correr() {   # $1 = base, $2 = MUDO_AVISADO de entrada, $3.. = variables extra
    local db="$1" avisado="$2"; shift 2
    ( export "$@" 2>/dev/null || true
      DB="$db"; SENSOR="pruebas"; MUDO_AVISADO="$avisado"
      send_telegram() { printf '%s\n' "$1" >> "$TMP/enviado.txt"; }
      # shellcheck source=/dev/null
      . "$TMP/fn.sh"
      vigilar_silencio
      printf 'AVISADO=%s\n' "$MUDO_AVISADO" )
}

enviado() { cat "$TMP/enviado.txt" 2>/dev/null; }
limpiar() { rm -f "$TMP/enviado.txt"; }

echo
echo "Un dia normal no dice nada"
base "$TMP/vivo.sqlite" 0.1 0.5
limpiar
correr "$TMP/vivo.sqlite" 0 >/dev/null
comprueba "con actividad reciente no se avisa" "0" "$(enviado | grep -c 'SIN ANOTAR')"

echo
echo "El incidente: vivo pero sin anotar nada"
base "$TMP/mudo.sqlite" 120 121
limpiar
avisado=$(correr "$TMP/mudo.sqlite" 0 | sed -n 's/^AVISADO=//p')
comprueba "cinco dias sin anotar se avisan" "1" "$(enviado | grep -c 'SIN ANOTAR NADA DESDE HACE 120 h')"
comprueba "y se dice cuando fue la ultima" "1" "$(enviado | grep -c 'Ultima conexion')"
# El sintoma no se parece a la causa. Sin la orden escrita, uno mira
# "docker ps", ve "Up", y se va tranquilo: las dos veces paso eso.
comprueba "la orden que lo diagnostica va en el aviso" "1" \
    "$(enviado | grep -c 'docker top dirtyland_dionaea')"
comprueba "y la que lo levanta, tambien" "1" \
    "$(enviado | grep -c 'docker restart dirtyland_dionaea')"
comprueba "queda anotado que ya se aviso" "no-cero" \
    "$( [ "${avisado:-0}" -ne 0 ] && echo no-cero || echo cero )"

echo
echo "Pero no 288 veces al dia"
# Un aviso que sale cada cinco minutos se silencia, y silenciado no avisa de
# nada. Esta es la razon de que exista la marca en el estado.
limpiar
correr "$TMP/mudo.sqlite" "$avisado" >/dev/null
comprueba "la siguiente pasada no repite el aviso" "0" "$(enviado | grep -c 'SIN ANOTAR')"

limpiar
hace_siete_horas=$(( $(date -u +%s) - 7 * 3600 ))
correr "$TMP/mudo.sqlite" "$hace_siete_horas" >/dev/null
comprueba "pero pasadas las horas de repeticion, insiste" "1" \
    "$(enviado | grep -c 'SIN ANOTAR')"

echo
echo "Y avisa de que ha vuelto"
# Sin esto, quien recibio la alarma no sabe si sigue caido o ya se arreglo, y
# acaba yendo a mirarlo a mano --- que es lo que veniamos a evitar.
limpiar
vuelto=$(correr "$TMP/vivo.sqlite" "$hace_siete_horas" | sed -n 's/^AVISADO=//p')
comprueba "al volver la actividad se dice" "1" "$(enviado | grep -c 'Vuelve a anotar')"
comprueba "y se borra la marca, para poder volver a avisar" "0" "${vuelto:-nada}"

limpiar
correr "$TMP/vivo.sqlite" 0 >/dev/null
comprueba "sin haber avisado antes, no se felicita solo" "0" \
    "$(enviado | grep -c 'Vuelve a anotar')"

echo
echo "Lo que no puede dar una alarma falsa"
# El dia de la instalacion la base esta vacia. Sin este caso diria "hace
# 500000 horas" y se aprenderia a ignorar el aviso desde el primer dia.
base "$TMP/nueva.sqlite"
limpiar
correr "$TMP/nueva.sqlite" 0 >/dev/null
comprueba "una base recien creada no alarma" "0" "$(enviado | grep -c 'SIN ANOTAR')"

limpiar
correr "$TMP/no-existe.sqlite" 0 >/dev/null
comprueba "si no se puede leer la base, se calla en vez de reventar" "0" \
    "$(enviado | grep -c 'SIN ANOTAR')"

# Justo por debajo del umbral: el limite se comprueba en los dos lados, que es
# donde se esconden los "mayor que" que debian ser "mayor o igual".
base "$TMP/justo.sqlite" 1.9
limpiar
correr "$TMP/justo.sqlite" 0 >/dev/null
comprueba "por debajo del umbral no se avisa" "0" "$(enviado | grep -c 'SIN ANOTAR')"
base "$TMP/pasado.sqlite" 2.1
limpiar
correr "$TMP/pasado.sqlite" 0 >/dev/null
comprueba "y en cuanto se pasa, si" "1" "$(enviado | grep -c 'SIN ANOTAR')"

echo
echo "El umbral se puede mover"
limpiar
correr "$TMP/justo.sqlite" 0 DIONAEA_MUDO_HORAS=1 >/dev/null
comprueba "bajandolo, lo que antes callaba ahora avisa" "1" \
    "$(enviado | grep -c 'SIN ANOTAR')"

echo
echo "El umbral por defecto es el que creemos"
# Si alguien lo sube a 48 h "por probar" y se olvida, volvemos a estar dos
# dias ciegos. Que la prueba lo cante.
comprueba "avisa a las 2 h, no mas tarde" "1" \
    "$(grep -c '^DIONAEA_MUDO_HORAS="${DIONAEA_MUDO_HORAS:-2}"' "$FUENTE")"
comprueba "y repite cada 6 h" "1" \
    "$(grep -c '^DIONAEA_MUDO_REPETIR="${DIONAEA_MUDO_REPETIR:-6}"' "$FUENTE")"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
