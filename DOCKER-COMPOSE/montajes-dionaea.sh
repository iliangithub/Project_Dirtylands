#!/bin/bash
# ---------------------------------------------------------------------------
# Comprueba ---y pone--- los montajes del servicio dionaea del docker-compose.
#
#   ./montajes-dionaea.sh              dice cuales faltan, no toca nada
#   ./montajes-dionaea.sh --apply      anade los que falten
#
# EXISTE POR UN FALLO CONCRETO. El 2026-08-29, actualizando una instalacion
# que ya estaba en marcha, hubo que anadir a mano la linea del mssql.py
# parcheado. A la primera salio asi:
#
#     -       - /opt/dirtyland/dionaea/mssql.py:...:ro
#
# ...con el guion duplicado. Se vio porque alguien miro el fichero. Es la
# unica parte del despliegue que no es copiar y pegar, y por eso es la que se
# tuerce: pegar una linea con la sangria exacta dentro del bloque correcto de
# un YAML es justo lo que un editor de texto hace mal.
#
# Y lo que se pierde si se tuerce no es poco: sin el montaje del mssql.py,
# Dionaea vuelve a colgarse con el primer paquete MSSQL malformado que reciba,
# y el compose sigue siendo YAML valido, asi que nada lo dice.
#
# EN UNA INSTALACION DESDE CERO ESTO NO HACE FALTA: el compose se pega entero
# desde DOCKER-COMPOSE/PART 1 y ya lleva sus montajes. Esto es para las
# ACTUALIZACIONES, que es cuando hay que meter una linea en un fichero que ya
# existe y que ademas lleva las IPs de la maquina sustituidas ---por eso no se
# puede copiar el del repositorio encima y hay que insertar---.
#
# LA LISTA DE LO QUE HACE FALTA SALE DEL COMPOSE DEL REPOSITORIO, no de aqui.
# Escribirla en este script seria tenerla en dos sitios, y dos sitios acaban
# diciendo cosas distintas: se anadiria un montaje al compose y este script
# seguiria diciendo que todo esta bien.
#
# Con --apply hace copia de seguridad, inserta, y valida con `docker compose
# config`. Si el resultado no fuera valido deja el fichero como estaba: mas
# vale no cambiar nada que dejar un compose roto.
# ---------------------------------------------------------------------------
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COMPOSE=${COMPOSE:-/opt/dirtyland/docker-compose.yml}

# DONDE BUSCAR EL COMPOSE MODELO. Se prueban dos sitios porque este guion se
# ejecuta desde dos: recien sacado del repositorio ---y entonces tiene el
# "PART 1/" al lado--- o ya instalado en /opt/dirtyland, donde no lo tiene.
#
# La primera version solo miraba al lado de si mismo, y al instalarlo fallaba
# con "No existe el compose del repositorio: /opt/dirtyland/PART 1/...". Se
# probo unicamente desde el arbol del repositorio, que es donde funcionaba.
#
# El segundo sitio es la copia que deja el paso de transferencia, que es el
# mismo /tmp/dirtyland-repo que usan todos los demas pasos de actualizacion:
# si estas actualizando, esta ahi por definicion.
REPO_COPIA=${REPO_COPIA:-/tmp/dirtyland-repo}
if [ -z "${MODELO:-}" ]; then
    for _cand in "$AQUI/PART 1/docker-compose.yml" \
                 "$REPO_COPIA/DOCKER-COMPOSE/PART 1/docker-compose.yml"; do
        [ -f "$_cand" ] && MODELO="$_cand" && break
    done
fi
MODELO=${MODELO:-$AQUI/PART 1/docker-compose.yml}

# Solo los montajes cuyo origen es /opt/dirtyland/dionaea. Se deja fuera el
# volumen con nombre (dionaea-var) porque no es una ruta del anfitrion, y con
# esa forma tan concreta no hay manera de confundir el bloque del servicio:
# ningun otro lo usa.
PATRON='^[[:space:]]*-[[:space:]]*/opt/dirtyland/dionaea/'

if [ ! -f "$MODELO" ]; then
    echo "No encuentro el compose del repositorio, que es de donde sale la" >&2
    echo "lista de montajes. Se ha buscado en:" >&2
    echo "  $AQUI/PART 1/docker-compose.yml" >&2
    echo "  $REPO_COPIA/DOCKER-COMPOSE/PART 1/docker-compose.yml" >&2
    echo >&2
    echo "Sube el repositorio a $REPO_COPIA (apartado 3.2 del README)" >&2
    echo "o pasa la ruta a mano:  MODELO=/ruta/docker-compose.yml $0" >&2
    exit 1
fi
if [ ! -f "$COMPOSE" ]; then
    echo "No existe $COMPOSE" >&2
    exit 1
fi

# El contenido de cada montaje, sin la sangria ni el guion: es lo que se
# compara, para que una diferencia de espacios no cuente como que falta.
contenido() {
    grep -E "$PATRON" "$1" | sed -E 's/^[[:space:]]*-[[:space:]]*//'
}

mapfile -t QUIERE < <(contenido "$MODELO")
if [ "${#QUIERE[@]}" -eq 0 ]; then
    echo "El compose del repositorio no declara ningun montaje de dionaea." >&2
    echo "Eso no puede ser: revisa $MODELO" >&2
    exit 1
fi

FALTAN=()
for m in "${QUIERE[@]}"; do
    if ! contenido "$COMPOSE" | grep -qxF "$m"; then
        FALTAN+=("$m")
    fi
done

echo "Montajes de dionaea que pide el repositorio: ${#QUIERE[@]}"
for m in "${QUIERE[@]}"; do
    if printf '%s\n' "${FALTAN[@]:-}" | grep -qxF "$m"; then
        echo "  FALTA  $m"
    else
        echo "  ok     $m"
    fi
done

if [ "${#FALTAN[@]}" -eq 0 ]; then
    echo
    echo "No falta ninguno; no hay nada que hacer."
    exit 0
fi

if [ "${1:-}" != "--apply" ]; then
    echo
    echo "Faltan ${#FALTAN[@]}. Para ponerlos:  $0 --apply"
    exit 1
fi

# --- Insertar -------------------------------------------------------------
#
# El ancla es la ULTIMA linea de montaje de dionaea que ya haya: garantiza que
# se escribe dentro del bloque correcto ---ningun otro servicio usa esa ruta---
# y de ella se copia la sangria, que es exactamente lo que se hace mal a mano.
ANCLA=$(grep -nE "$PATRON" "$COMPOSE" | tail -1 | cut -d: -f1)
if [ -z "$ANCLA" ]; then
    echo "En $COMPOSE no hay ningun montaje de dionaea del que colgarse." >&2
    echo "Eso no es una actualizacion: pega el compose entero desde" >&2
    echo "DOCKER-COMPOSE/PART 1 siguiendo el apartado 3.4 del README." >&2
    exit 1
fi
SANGRIA=$(sed -n "${ANCLA}p" "$COMPOSE" | sed -E 's/^([[:space:]]*)-.*/\1/')

BACKUP="${COMPOSE}.bak-$(date +%Y-%m-%d_%H%M%S)"
cp -a "$COMPOSE" "$BACKUP" || exit 1

SALIDA=$(mktemp)
{
    head -n "$ANCLA" "$COMPOSE"
    for m in "${FALTAN[@]}"; do
        printf '%s- %s\n' "$SANGRIA" "$m"
    done
    tail -n +"$((ANCLA + 1))" "$COMPOSE"
} > "$SALIDA"

if [ ! -s "$SALIDA" ]; then
    echo "El resultado salio vacio; no se toca nada." >&2
    rm -f "$SALIDA"
    exit 1
fi

cp -a "$SALIDA" "$COMPOSE"
rm -f "$SALIDA"

if docker compose -f "$COMPOSE" config >/dev/null 2>&1; then
    echo
    echo "Anadidos ${#FALTAN[@]}, y el compose sigue siendo valido."
    echo "Copia de seguridad en $BACKUP"
    # El comando para aplicarlo esta en el README y no aqui, por lo mismo que
    # en generar-volumes-cowrie.sh: un comando en dos sitios acaba divergiendo.
    echo "Para que surta efecto, recrea el contenedor como dice el 3.4."
    exit 0
fi

echo "El compose resultante NO es valido. Se restaura la copia de seguridad." >&2
cp -a "$BACKUP" "$COMPOSE"
exit 1
