#!/usr/bin/env bash
# test-montajes-dionaea.sh — poner una linea en un YAML sin torcerlo.
#
#   bash DOCKER-COMPOSE/tests/test-montajes-dionaea.sh
#
# El 2026-08-29, actualizando una instalacion en marcha, hubo que anadir a
# mano el montaje del mssql.py parcheado. A la primera salio "-       - /opt/..."
# ---con el guion duplicado--- y se vio porque alguien miro el fichero.
#
# Lo que se pierde si eso pasa desapercibido no es poco: sin ese montaje,
# Dionaea vuelve a colgarse con el primer paquete MSSQL malformado, y el
# compose sigue siendo YAML valido, asi que nada lo dice.
#
# El `docker` de estas pruebas es de mentira, y hay dos: uno que da por buena
# la validacion y otro que la rechaza siempre. El segundo no es un capricho:
# es la unica forma de comprobar que la vuelta atras funciona, y una vuelta
# atras que nunca se ha probado es una que no se sabe si existe.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUION="$AQUI/../montajes-dionaea.sh"
MODELO_REAL="$AQUI/../PART 1/docker-compose.yml"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bien" "$TMP/mal"

cat > "$TMP/bien/docker" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$TMP/mal/docker" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$TMP/bien/docker" "$TMP/mal/docker"

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

# El compose "de la maquina": el del repositorio con las IPs sustituidas, que
# es lo que hace que no se pueda copiar el del repositorio encima y haya que
# insertar.
preparar() {   # $1 = destino; $2 = si es "sin-mssql", se le quita esa linea
    sed -e 's/\[IP VPS 2\]/198.51.100.161/g' -e 's/\[IP VPS\]/198.51.100.146/g' \
        "$MODELO_REAL" > "$1"
    if [ "${2:-}" = "sin-mssql" ]; then
        grep -v 'dionaea/mssql.py:' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
    fi
}

correr() {   # $1 = compose, $2 = carpeta del docker falso, $3.. = argumentos
    local compose="$1" doble="$2"; shift 2
    ( PATH="$doble:$PATH"; COMPOSE="$compose"; export COMPOSE
      bash "$GUION" "$@" 2>&1 )
}

MONTAJE='/opt/dirtyland/dionaea/mssql.py:/opt/dionaea/lib/dionaea/python/dionaea/mssql/mssql.py:ro'

echo
echo "Sin --apply no toca nada"
preparar "$TMP/c1.yml" sin-mssql
antes=$(md5sum < "$TMP/c1.yml")
salida=$(correr "$TMP/c1.yml" "$TMP/bien"); rc=$?
comprueba "dice que falta uno" "1" "$(printf '%s' "$salida" | grep -c 'FALTA')"
comprueba "y sale con error, para que se note en un guion" "1" "$rc"
comprueba "sin tocar el fichero" "$antes" "$(md5sum < "$TMP/c1.yml")"

echo
echo "Con --apply lo pone bien"
salida=$(correr "$TMP/c1.yml" "$TMP/bien" --apply); rc=$?
comprueba "sale bien" "0" "$rc"
comprueba "y el montaje esta" "1" "$(grep -cF "$MONTAJE" "$TMP/c1.yml")"
# LA SANGRIA ES EL FALLO QUE ESTO VIENE A EVITAR. Seis espacios, un guion, un
# espacio. Nada de "-       - /opt/...".
comprueba "con la sangria exacta" "1" \
    "$(grep -cxF "      - $MONTAJE" "$TMP/c1.yml")"
comprueba "y no hay ningun guion duplicado" "0" \
    "$(grep -cE '^[[:space:]]*-[[:space:]]+-[[:space:]]' "$TMP/c1.yml")"
# Dentro del bloque de dionaea, no en el de cowrie: se comprueba que va
# despues de la linea de dionaea que ya habia.
comprueba "dentro del bloque de dionaea" "si" \
    "$( [ "$(grep -n 'dionaea/tds.py:' "$TMP/c1.yml" | cut -d: -f1)" -lt \
          "$(grep -n 'dionaea/mssql.py:' "$TMP/c1.yml" | cut -d: -f1)" ] \
        && echo si || echo no )"
comprueba "deja copia de seguridad" "1" \
    "$(ls "$TMP"/c1.yml.bak-* 2>/dev/null | wc -l)"

echo
echo "Y se puede volver a lanzar"
# El README se copia y se pega, y tras una reinstalacion no se sabe si ya
# estaba puesto. Ejecutarlo dos veces no puede duplicar la linea.
antes=$(md5sum < "$TMP/c1.yml")
salida=$(correr "$TMP/c1.yml" "$TMP/bien" --apply); rc=$?
comprueba "la segunda vez no hace nada" "0" "$rc"
comprueba "y lo dice" "1" "$(printf '%s' "$salida" | grep -c 'No falta ninguno')"
comprueba "sin duplicar la linea" "1" "$(grep -cF "$MONTAJE" "$TMP/c1.yml")"
comprueba "ni tocar el fichero" "$antes" "$(md5sum < "$TMP/c1.yml")"

echo
echo "Si el compose resultante no vale, se deshace"
preparar "$TMP/c2.yml" sin-mssql
antes=$(md5sum < "$TMP/c2.yml")
salida=$(correr "$TMP/c2.yml" "$TMP/mal" --apply); rc=$?
comprueba "sale con error" "1" "$rc"
comprueba "lo dice en vez de callarse" "1" \
    "$(printf '%s' "$salida" | grep -c 'NO es valido')"
# Lo importante: el fichero queda EXACTAMENTE como estaba. Un compose a medias
# es peor que uno sin actualizar.
comprueba "y el fichero queda como estaba" "$antes" "$(md5sum < "$TMP/c2.yml")"

echo
echo "Lo que pide sale del repositorio, no de una lista de aqui"
# Si estuviera escrito en el guion, se anadiria un montaje al compose del
# repositorio y este seguiria diciendo que todo esta bien.
cp "$MODELO_REAL" "$TMP/modelo-mas.yml"
sed -i 's#\(.*\)- /opt/dirtyland/dionaea/tds.py:#\1- /opt/dirtyland/dionaea/inventado.py:/opt/dionaea/inventado.py:ro\n\1- /opt/dirtyland/dionaea/tds.py:#' \
    "$TMP/modelo-mas.yml"
preparar "$TMP/c3.yml"
salida=$( PATH="$TMP/bien:$PATH"; COMPOSE="$TMP/c3.yml"; MODELO="$TMP/modelo-mas.yml"
          export COMPOSE MODELO; bash "$GUION" 2>&1 )
comprueba "un montaje nuevo en el repositorio se pide solo" "1" \
    "$(printf '%s' "$salida" | grep -c 'FALTA.*inventado.py')"

echo
echo "Instalado en /opt/dirtyland no tiene el PART 1 al lado"
# ESTE ERA EL FALLO. La primera version buscaba el compose modelo solo junto a
# si misma, asi que funcionaba desde el arbol del repositorio ---que es donde
# se probo--- y al instalarla en /opt/dirtyland fallaba con
# "No existe el compose del repositorio: /opt/dirtyland/PART 1/...".
mkdir -p "$TMP/opt"
cp "$GUION" "$TMP/opt/montajes-dionaea.sh"
mkdir -p "$TMP/copia-repo/DOCKER-COMPOSE/PART 1"
cp "$MODELO_REAL" "$TMP/copia-repo/DOCKER-COMPOSE/PART 1/docker-compose.yml"
preparar "$TMP/c5.yml" sin-mssql

salida=$( PATH="$TMP/bien:$PATH"; COMPOSE="$TMP/c5.yml"; REPO_COPIA="$TMP/copia-repo"
          export COMPOSE REPO_COPIA; bash "$TMP/opt/montajes-dionaea.sh" 2>&1 )
comprueba "encuentra el modelo en la copia del repositorio" "1" \
    "$(printf '%s' "$salida" | grep -c 'FALTA.*mssql.py')"

# Y si no esta en ninguno de los dos sitios, lo dice con las dos rutas y como
# arreglarlo, en vez de con un "no existe" a secas.
salida=$( PATH="$TMP/bien:$PATH"; COMPOSE="$TMP/c5.yml"; REPO_COPIA="$TMP/no-hay-nada"
          export COMPOSE REPO_COPIA; bash "$TMP/opt/montajes-dionaea.sh" 2>&1 )
comprueba "si no lo encuentra, nombra los dos sitios" "2" \
    "$(printf '%s' "$salida" | grep -c 'PART 1/docker-compose.yml')"
# Y ofrece la salida de emergencia, que es la tercera mencion.
comprueba "y ofrece pasar la ruta a mano" "1" \
    "$(printf '%s' "$salida" | grep -c 'MODELO=')"
comprueba "y dice como arreglarlo" "1" \
    "$(printf '%s' "$salida" | grep -c 'Sube el repositorio')"

echo
echo "Lo que se niega a hacer"
# Sin ningun montaje de dionaea no hay de que colgarse, y adivinar donde va
# una linea en un YAML ajeno es como se rompe un compose.
grep -v '/opt/dirtyland/dionaea/' "$TMP/c3.yml" > "$TMP/c4.yml"
antes=$(md5sum < "$TMP/c4.yml")
salida=$(correr "$TMP/c4.yml" "$TMP/bien" --apply); rc=$?
comprueba "sin nada de donde colgarse, se para" "1" "$rc"
comprueba "y manda pegar el compose entero" "1" \
    "$(printf '%s' "$salida" | grep -c 'PART 1')"
comprueba "sin tocar el fichero" "$antes" "$(md5sum < "$TMP/c4.yml")"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
