#!/usr/bin/env bash
# test-probar-avisos.sh --- el ensayo de TODOS los avisos, en seco.
#
#   bash "TELEGRAM SCRIPTS/tests/test-probar-avisos.sh"
#
# probar-avisos.sh existe para ver llegar al movil cada uno de los avisos
# antes de exponer. Esta suite comprueba lo que no se puede ver mirando el
# movil: que el ensayo sigue cubriendo TODOS los avisos, y que no se ha
# quedado ninguno por el camino al tocar un vigilante.
#
# Lo que se comprueba:
#   - Que cada aviso sale, y sale con su cabecera de verdad. Si alguien
#     cambia un titulo en un vigilante y no aqui, esto se pone rojo: es la
#     unica atadura entre el ensayo y los mensajes reales.
#   - Que en seco NO se manda nada a Telegram (ni un curl, ni un token).
#   - Que no escribe fuera de su directorio temporal: el ensayo no puede
#     mover un contador de produccion ni marcar una IP como ya avisada.
#   - Que las banderas de los proxys salen de proxys.conf y no escritas a
#     mano, que es lo que hace que valga con otros relays manana.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO="$AQUI/.."
GUION="$REPO/probar-avisos.sh"
OK=0; MAL=0

comprueba() {
    if [ "$2" = "$3" ]; then OK=$((OK+1)); else
        MAL=$((MAL+1)); printf '  FALLO: %s\n    esperado [%s]  obtenido [%s]\n' "$1" "$2" "$3"
    fi
}
contiene() {
    if grep -qF -- "$2" "$3" 2>/dev/null; then OK=$((OK+1)); else
        MAL=$((MAL+1)); printf '  FALLO: %s\n    no aparece [%s]\n' "$1" "$2"
    fi
}
no_contiene() {
    if grep -qF -- "$2" "$3" 2>/dev/null; then
        MAL=$((MAL+1)); printf '  FALLO: %s\n    aparece y no debia [%s]\n' "$1" "$2"
    else OK=$((OK+1)); fi
}

BASE=$(mktemp -d); trap 'rm -rf "$BASE"' EXIT
SALIDA="$BASE/salida.txt"

[ -x "$GUION" ] || chmod +x "$GUION" 2>/dev/null

echo "Ensayo completo en seco"

# Una sola pasada, y todas las comprobaciones sobre su salida. Correrlo una
# vez por comprobacion tardaria un minuto largo: el resumen diario consulta
# docker, el journal y el disco.
PROBAR_MONITOR="$REPO" bash "$GUION" --seco > "$SALIDA" 2>&1
comprueba "el ensayo entero termina bien" "0" "$?"

# --- Que estan TODOS -------------------------------------------------------
#
# Las cabeceras van tal cual las escribe cada vigilante. Es la atadura: si
# alguien cambia una y no pasa por aqui, la suite lo dice.
contiene "avisa del login SSH al anfitrion" \
    "<strong>[Host] Login SSH exitoso</strong>" "$SALIDA"
contiene "y del intento contra root" \
    "<strong>[Host] INTENTO DE ACCESO A ROOT</strong>" "$SALIDA"
contiene "y del login fallido" \
    "<strong>[Host] Intento de login SSH FALLIDO</strong>" "$SALIDA"
contiene "de las ordenes tecleadas" "Esto NO son los senuelos" "$SALIDA"
contiene "del cortacircuitos al saltar" \
    "<strong>[Dirtyland] 🚨 Cortacircuitos SALTADO</strong>" "$SALIDA"
contiene "de la cuota al agotarse" \
    "<strong>[cuota-watch] 🚨 Cuota superada 🚨</strong>" "$SALIDA"
contiene "y de la cuota al volver" \
    "<strong>[cuota-watch] ✅ Cuota restablecida</strong>" "$SALIDA"
contiene "de las IPs baneadas" "IP's baneadas:" "$SALIDA"
contiene "del resumen diario" \
    "<strong>[Dirtyland] Resumen diario</strong>" "$SALIDA"
contiene "de la tabla de paises que no se pudo rehacer" \
    "No se pudo regenerar" "$SALIDA"

# Los seis del vigilante de proxys, uno por uno.
contiene "proxy: inactivo al arrancar" "inactivo (estado inicial)" "$SALIDA"
contiene "proxy: caido"       "» caído</strong>" "$SALIDA"
contiene "proxy: recuperado"  "» recuperado</strong>" "$SALIDA"
contiene "proxy: fuera de la lista" "» fuera de la lista</strong>" "$SALIDA"
contiene "proxy: sin respaldo" "Acceso sin respaldo" "$SALIDA"
contiene "proxy: sin acceso"   "🚨 SIN ACCESO" "$SALIDA"

# --- La IP del aviso es la de sshd, no la que escribio el atacante ---------
#
# La linea de prueba lleva un "from 10.0.0.1 port 22" DENTRO del nombre de
# usuario. Es el ataque que se describe en la cabecera de ssh-watch.sh: si el
# extractor cogiera la primera coincidencia, el aviso senalaria a 10.0.0.1 y
# el atacante elegiria que IP aparece. Aqui se ve ya montado el mensaje.
contiene "el aviso senala la IP que anade sshd" \
    "Source: <code>192.0.2.55</code>" "$SALIDA"
no_contiene "y no la que escribio el atacante en el nombre de usuario" \
    "Source: <code>10.0.0.1</code>" "$SALIDA"

# --- Las banderas salen de proxys.conf, no de una lista escrita a mano ----
#
# Se comprueba contra el fichero de verdad: para cada relay declarado, su
# bandera tiene que aparecer en la salida. Asi, el dia que se cambien los
# relays por otros de otros paises, esta prueba sigue valiendo --- y si
# alguien escribiera las banderas a mano en el ensayo, fallaria.
bandera_de() {   # bandera_de cc -> el emoji
    local cc="${1:0:2}" a b
    a=$(printf '%d' "'${cc:0:1}"); b=$(printf '%d' "'${cc:1:1}")
    printf "\\U$(printf '%08x' $((0x1F1E6 + a - 97)))\\U$(printf '%08x' $((0x1F1E6 + b - 97)))"
}
mapfile -t RELAYS < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$REPO/proxys.conf" | grep .)
comprueba "proxys.conf declara al menos un relay" \
    "si" "$( [ "${#RELAYS[@]}" -ge 1 ] && echo si || echo no )"
faltan=0
for r in "${RELAYS[@]}"; do
    printf "$(bandera_de "$r")" > "$BASE/f"
    grep -qF -- "$(cat "$BASE/f")" "$SALIDA" || faltan=$((faltan+1))
    grep -qF -- "$r" "$SALIDA" || faltan=$((faltan+1))
done
comprueba "cada relay de proxys.conf sale con su bandera" "0" "$faltan"

# --- En seco no se manda nada ---------------------------------------------
#
# No basta con que no aparezca un error: lo que no puede pasar es que en una
# prueba salga un mensaje de verdad. Se comprueba por donde se veria ---la
# respuesta de la API de Telegram--- y ademas que el doble de send-alert se
# ha usado de verdad.
no_contiene "en seco no contesta la API de Telegram" '"ok":true' "$SALIDA"
no_contiene "ni aparece un token" "api.telegram.org/bot" "$SALIDA"
contiene "el doble de send-alert es el que recoge los avisos" \
    "===AVISO===" "$SALIDA"
contiene "y lo dice al terminar" "no se ha mandado nada a Telegram" "$SALIDA"

# --- No toca produccion ---------------------------------------------------
#
# El ensayo apunta todos los estados a su directorio temporal. Si alguna
# ruta de produccion se colara en el guion, este grep la caza: son las
# cuatro carpetas donde viven los contadores que no se pueden mover.
#
# Se miran solo las lineas que EJECUTAN algo (asignaciones de variables de
# entorno de estado), no los comentarios ni el valor por defecto de MONITOR,
# que tiene que seguir siendo la ruta de la VPS.
for v in DIONAEA_STATE_DIR PROXY_WATCH_STATE_DIR STATE_DIR AUDIT_LOG; do
    malas=$(grep -E "^[[:space:]]*$v=" "$GUION" | grep -cv '\$TMP' || true)
    comprueba "$v apunta al directorio temporal" "0" "$malas"
done

# --- --solo N hace uno y nada mas -----------------------------------------
PROBAR_MONITOR="$REPO" bash "$GUION" --seco --solo 2 > "$BASE/uno.txt" 2>&1
contiene "--solo lanza el paso pedido" \
    "<strong>[Host] INTENTO DE ACCESO A ROOT</strong>" "$BASE/uno.txt"
no_contiene "y no los demas" \
    "<strong>[Host] Login SSH exitoso</strong>" "$BASE/uno.txt"

# --- El bloque del senuelo y el silencio -----------------------------------
#
# En seco, los tres de Cowrie no se hacen: los manda el plugin por su propio
# bot y no habria nada que interceptar. Y con una ventana de silencio abierta
# el ensayo entero tiene que pararse antes de mandar nada, porque
# send-alert.sh se callaria y pareceria que el canal esta roto.
contiene "en seco se saltan los de Cowrie, y lo dice"     "en seco no van los tres de Cowrie" "$SALIDA"
no_contiene "y no se abre ninguna sesion contra el senuelo"     "Avisos del bot de Cowrie" "$SALIDA"

printf '#!/usr/bin/env bash
true
' > "$BASE/send-alert.sh"
chmod +x "$BASE/send-alert.sh"
printf 'hasta=%s
' "$(( $(date +%s) + 3600 ))" > "$BASE/silencio"
SILENCIO="$BASE/silencio" PROBAR_MONITOR="$BASE" bash "$GUION" > "$BASE/mudo.txt" 2>&1
comprueba "con silencio abierto no se lanza" "1" "$?"
contiene "y lo explica" "VENTANA DE SILENCIO" "$BASE/mudo.txt"

# --- La lista del ensayo y la del README no se separan ---------------------
#
# El README enumera los avisos en su apartado. Si se anade uno al guion y no
# a la guia, el dia del formateo faltaria por probar y nadie lo sabria.
PASOS=$(grep -c '^if paso "' "$GUION")
comprueba "el ensayo tiene los pasos que dice el resumen final" \
    "$PASOS" "$(grep -oE '^probar-avisos: [0-9]+ avisos' "$SALIDA" | grep -oE '[0-9]+')"

README="$REPO/../README.md"
if [ -r "$README" ]; then
    # Cada titulo del guion tiene que estar escrito en la guia, tal cual. No
    # se cuentan lineas: se comparan los textos, que es lo que caza tambien
    # un cambio de nombre --- una lista con el numero correcto y un aviso
    # renombrado seria una lista mentirosa.
    sinescribir=0
    while IFS= read -r t; do
        grep -qF -- "$t" "$README" || {
            sinescribir=$((sinescribir+1))
            printf '    sin listar en el README: %s\n' "$t"
        }
    done < <(grep -oP '^if paso "\K[^"]+' "$GUION")
    comprueba "el README lista los veintidos avisos, con su nombre" \
        "0" "$sinescribir"
    comprueba "y no lista de mas" "$PASOS" \
        "$(grep -cP '^\s*[0-9]+  \[(Host|Dirtyland|Proxy|Dionaea)\]' "$README")"
else
    echo "  (sin README a mano, no se compara la lista)"
fi

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
