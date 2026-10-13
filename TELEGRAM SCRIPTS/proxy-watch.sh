#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# proxy-watch.sh --- vigila que los proxys SOCKS de acceso a la VPS sigan vivos.
#
# Pensado para cron cada media hora. Corre EN LA VPS y avisa por el bot del
# host (el mismo de ssh-watch.sh: /opt/dirtyland/monitor/send-alert.sh, con su
# silenciador y su carrete).
#
# QUE VIGILA. El SSH de administracion entra por uno de tres relays SOCKS5 de
# Mullvad, y el cortafuegos solo admite la IP de salida de esos tres (lineas
# «ip saddr … tcp dport 56769» de CORTAFUEGOS/). Mullvad los da de baja sin
# avisar: el 2026-09-08 cayo el de Zurich y hubo que entrar por los de Suecia
# y Paises Bajos; dos dias despues volvio Zurich y cayo el de Amsterdam. Si
# caen los tres a la vez se pierde el acceso y solo queda la consola web del
# proveedor.
#
# QUE PUEDE VER Y QUE NO. La VPS NO puede probar los proxys de verdad: viven
# en 10.124.0.x, dentro del tunel de Mullvad, y la VPS no es --- ni debe ser
# --- cliente de Mullvad. Lo unico que puede hacer desde aqui es preguntarle a
# la API publica de Mullvad si cada relay sigue `active`. Ese flag es
# justamente lo que se puso en `false` las dos veces. Lo que NO detecta: un
# relay que cambie de IP de salida sin darse de baja (raro; el sintoma es «no
# entro» y se ve a mano con  curl -x socks5h://PROXY:1080 https://am.i.mullvad.net/ip
# desde el equipo).
#
# DE DONDE SACA LA LISTA. De /opt/dirtyland/monitor/proxys.conf, un nombre de
# relay por linea. Tienen que ser los mismos tres del ~/.ssh/config del equipo
# y los de la whitelist del cortafuegos.
#
# LA BANDERA. Sale del `country_code` que la propia API da para cada relay, asi
# que sirve para CUALQUIER pais: si manana se cambia Paises Bajos por Japon, el
# aviso llevara la bandera de Japon sin tocar nada aqui.
#
# CUANDO AVISA. Solo en los cambios de estado, comparando con el fichero de
# estado. activo->inactivo, activo->ausente (renombrado o retirado),
# vuelta a activo. Y si tras la pasada quedan 0 o 1 relays activos y eso ha
# empeorado, un aviso de gravedad aparte.
#
# NO TOCA NADA: ni el cortafuegos, ni el ssh, ni los contenedores. Solo mira y
# avisa.
#
#   proxy-watch.sh            comprueba y avisa si algo ha cambiado
#   proxy-watch.sh --test     imprime el estado y NO toca el estado ni avisa
# ---------------------------------------------------------------------------
set -uo pipefail

ALERT="${PROXY_WATCH_ALERT:-/opt/dirtyland/monitor/send-alert.sh}"
CONF="${PROXY_WATCH_CONF:-/opt/dirtyland/monitor/proxys.conf}"
STATE_DIR="${PROXY_WATCH_STATE_DIR:-/var/lib/dirtyland-reporter}"
STATE="$STATE_DIR/proxy-watch.state"
API="${PROXY_WATCH_API:-https://api.mullvad.net/www/relays/all/}"
TIMEOUT="${PROXY_WATCH_TIMEOUT:-20}"
# La tabla CC -> nombre en espanol, la misma que usan las demas alertas del
# host (la instala el 3.4.4 junto al resto de geoip). Si falta, se usa el
# nombre en ingles que da la propia API.
NOMBRES="${PROXY_WATCH_NOMBRES:-/opt/dirtyland/geoip/nombres.txt}"

TEST=0
[ "${1:-}" = "--test" ] && TEST=1

# bandera CC -> emoji de la bandera de ese pais (indicadores regionales).
# Un codigo que no sean dos letras -> 🏴, para que el aviso salga igual.
# LOS BYTES DE UTF-8 A PELO, y no un "\U0001F1F3" que seria mas legible. El
# "\U" de printf necesita que el LOCALE sepa representar ese caracter: si no
# puede, bash escribe la secuencia TAL CUAL y al chat llega
# "\U0001F1F3\U0001F1F1" en lugar de la bandera.
#
# Y eso no era un problema de mi portatil: ESTO LO LANZA CRON, que arranca sin
# LANG ni LC_ALL ---o sea en locale C--- cada media hora. El aviso solo sale en
# las transiciones, que son rarisimas, asi que el dia que Mullvad tirara un
# relay habria llegado un mensaje con el escape en crudo y nadie habria sabido
# por que. La suite lo cazaba desde el principio; lo que faltaba era poder
# ejecutarla.
#
# Los \x de printf, en cambio, son bytes: no pasan por el locale. Es lo que ya
# hace la bandera negra de abajo y el emoji de baneadas-diario.sh. Un indicador
# regional es U+1F1E6 + la letra, y en UTF-8 los tres primeros bytes son
# siempre f0 9f 87: solo cambia el cuarto, de a6 (A) a bf (Z).
bandera() {
    local cc p1 p2 h1 h2
    cc=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')
    case "$cc" in [a-z][a-z]) : ;; *) printf '\xf0\x9f\x8f\xb4'; return ;; esac
    printf -v p1 '%d' "'${cc:0:1}"
    printf -v p2 '%d' "'${cc:1:1}"
    printf -v h1 '%x' $((0xa6 + p1 - 97))
    printf -v h2 '%x' $((0xa6 + p2 - 97))
    printf "\\xf0\\x9f\\x87\\x$h1\\xf0\\x9f\\x87\\x$h2"
}

# nombre_pais CC FALLBACK -> nombre en espanol de la tabla, o el fallback.
nombre_pais() {
    local cc n=""
    cc=$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')
    [ -n "$cc" ] && [ -r "$NOMBRES" ] && \
        n=$(grep -m1 "^$cc " "$NOMBRES" 2>/dev/null | cut -d' ' -f2-)
    printf '%s' "${n:-${2:-}}"
}

avisa() {   # avisa "TITULO" "CUERPO"
    if [ "$TEST" -eq 1 ] || [ "${PROXY_WATCH_DRY:-0}" = "1" ]; then
        printf '===AVISO===\n%s\n%s\n' "$1" "$2"
        return 0
    fi
    if [ -x "$ALERT" ]; then
        "$ALERT" "<strong>[Proxy] $1</strong>
$2"
    else
        echo "proxy-watch: no puedo avisar, falta $ALERT" >&2
    fi
}

[ -r "$CONF" ] || { echo "proxy-watch: no existe $CONF" >&2; exit 1; }

# Lista de relays a vigilar: una por linea, ignorando comentarios y vacias.
mapfile -t PROXYS < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$CONF" | grep .)
[ "${#PROXYS[@]}" -gt 0 ] || { echo "proxy-watch: $CONF no lista ningun relay" >&2; exit 1; }

# --- Descarga de la lista de relays -----------------------------------------
JSON=$(mktemp) || exit 1
trap 'rm -f "$JSON"' EXIT
if ! curl -s --max-time "$TIMEOUT" "$API" -o "$JSON" || [ ! -s "$JSON" ]; then
    # Un fallo de red no es una caida de proxy. No se avisa y no se toca el
    # estado: en la proxima pasada se reintenta.
    echo "proxy-watch: no pude hablar con la API de Mullvad; se reintenta luego" >&2
    exit 0
fi

# datos_api RELAY -> "estado|cc|nombrepais"
#   estado: activo | inactivo | ausente
#   cc / nombrepais: vacios si el relay no esta en la lista
datos_api() {
    local r="$1" out
    if command -v jq >/dev/null 2>&1; then
        out=$(jq -r --arg h "$r" '
            ([.[] | select((.socks_name // "") == $h
                            or ((.socks_name // "") | startswith($h + ".")))][0]) as $o
            | if $o == null then "ausente||"
              else ((if $o.active then "activo" else "inactivo" end)
                    + "|" + ($o.country_code // "") + "|" + ($o.country_name // ""))
              end' "$JSON" 2>/dev/null)
        [ -n "$out" ] && { printf '%s' "$out"; return; }
    fi
    # Plan B sin jq: se recorta el OBJETO {...} que contiene ese socks_name y
    # se lee dentro. OJO: en el JSON de Mullvad "active" y "country_code" van
    # ANTES de "socks_name", asi que hay que quedarse con el objeto entero;
    # mirar solo hacia adelante daba los tres por inactivos (2026-09-10). Los
    # objetos de relay no tienen llaves anidadas, asi que [^{}]* basta.
    #
    # NI UN ESPACIO NI UN SALTO DE LINEA PUEDEN DECIDIR ESTO. El case de
    # abajo comparaba contra '"active":true', sin espacio, y un JSON con
    # formato ---'"active": true', que es JSON igual de valido--- no casaba
    # ninguna rama: TODOS los relays salian "ausente". Eso son tres avisos
    # de "fuera de la lista" y un SIN ACCESO, los cuatro falsos. Y peor que
    # falsos: con todo "ausente" pase lo que pase, una caida de verdad se
    # ve exactamente igual que la anterior y no avisa de nada nuevo.
    #
    # Se quita el formato antes de mirar: el JSON se lee de un tiron (un
    # objeto con formato ocupa varias lineas y grep va por lineas) y del
    # fragmento se borran los blancos antes del case. El pais se saca del
    # fragmento SIN aplanar, que ahi los espacios cuentan ("New Zealand").
    local frag est cc nom plano
    frag=$(tr -d '
' < "$JSON" 2>/dev/null            | grep -o "{[^{}]*\"socks_name\"[[:space:]]*:[[:space:]]*\"$r[.\"][^{}]*}"            | head -1)
    [ -z "$frag" ] && { printf 'ausente||'; return; }
    plano=${frag//[[:space:]]/}
    case "$plano" in
        *'"active":true'*)  est=activo ;;
        *'"active":false'*) est=inactivo ;;
        *)                  est=ausente ;;
    esac
    cc=$(printf '%s' "$frag"  | grep -o '"country_code": *"[^"]*"' | head -1 | sed 's/.*"\(.*\)"/\1/')
    nom=$(printf '%s' "$frag" | grep -o '"country_name": *"[^"]*"' | head -1 | sed 's/.*"\(.*\)"/\1/')
    printf '%s|%s|%s' "$est" "$cc" "$nom"
}

lee_campo() {   # lee_campo RELAY N  -> campo N de la linea de estado (1=estado, 2=cc)
    [ -r "$STATE" ] || return 0
    grep -m1 "^estado|$1|" "$STATE" 2>/dev/null | cut -d'|' -f$(( $2 + 2 ))
}
lee_activos_prev() {
    [ -r "$STATE" ] || return 0
    grep -m1 '^activos|' "$STATE" 2>/dev/null | cut -d'|' -f2
}

# nombre corto del relay: nl-ams-wg-socks5-001
corto_de() { printf '%s' "${1%%.relays.mullvad.net}"; }

mkdir -p "$STATE_DIR" 2>/dev/null || true
NUEVO=$(mktemp) || exit 1
primera_vez=0
[ -r "$STATE" ] || primera_vez=1

n_activos=0
activos_flag=""      # "🇨🇭 ch-zrh… · 🇸🇪 se-got…"
todos_detalle=""     # una linea por relay, para el aviso de SIN ACCESO

for r in "${PROXYS[@]}"; do
    IFS='|' read -r est cc nom <<<"$(datos_api "$r")"
    prev=$(lee_campo "$r" 1)
    prev_cc=$(lee_campo "$r" 2)

    corto=$(corto_de "$r")
    [ -n "$cc" ] || cc="$prev_cc"        # ausente: se usa la ultima bandera conocida
    fb=$(bandera "$cc")
    nombre=$(nombre_pais "$cc" "$nom")
    pais="${nombre:+ ($nombre)}"

    todos_detalle+="${fb} <code>${corto}</code> — ${est}"$'\n'
    if [ "$est" = activo ]; then
        n_activos=$((n_activos+1))
        activos_flag+="${activos_flag:+ · }${fb} ${corto}"
    fi

    if [ "$est" != "$prev" ]; then
        if [ "$primera_vez" -eq 1 ]; then
            # Primera pasada: no se avisa de lo que YA esta bien; de lo que ya
            # esta mal, si --- puede montarse esto con un relay caido.
            case "$est" in
                inactivo) avisa "🟠 «${corto}» inactivo (estado inicial)" \
"Al arrancar la vigilancia, ${fb} <code>${r}</code>${pais} ya estaba <b>inactivo</b> en Mullvad.
Entra por otro relay." ;;
                ausente)  avisa "🟠 «${corto}» fuera de la lista (estado inicial)" \
"Al arrancar la vigilancia, <code>${r}</code> no figura entre los relays de Mullvad. ¿Se renombró?" ;;
            esac
        else
            case "$est" in
                inactivo)
                    avisa "🔴 «${corto}» caído" \
"${fb} <code>${r}</code>
Mullvad${pais} lo ha marcado <b>inactivo</b>. El SSH por ese relay ya no entra.

Relays en pie: ${activos_flag:-—}" ;;
                ausente)
                    avisa "🔴 «${corto}» fuera de la lista" \
"${fb} <code>${r}</code> ya no figura entre los relays de Mullvad (retirado o renombrado).
Elige otro y actualízalo en los <b>tres</b> sitios:
• <code>${CONF}</code>
• el <code>~/.ssh/config</code> del equipo
• las líneas «ip saddr … tcp dport 56769» de las 4 partes de <code>CORTAFUEGOS/</code>" ;;
                activo)
                    avisa "🟢 «${corto}» recuperado" \
"${fb} <code>${r}</code>${pais} vuelve a estar <b>activo</b> en Mullvad.

Relays en pie: ${activos_flag}" ;;
            esac
        fi
    fi

    echo "estado|$r|$est|$cc" >> "$NUEVO"
done

# --- Resumen de gravedad: solo si ha empeorado ----------------------------
prev_activos=$(lee_activos_prev)
echo "activos|$n_activos" >> "$NUEVO"
echo "revisado|$(date -u +%s)" >> "$NUEVO"

if [ "$primera_vez" -eq 0 ] && [ -n "$prev_activos" ] && [ "$n_activos" -lt "$prev_activos" ]; then
    if [ "$n_activos" -eq 0 ]; then
        avisa "🚨 SIN ACCESO — los ${#PROXYS[@]} relays caídos" \
"Ningún relay de acceso responde en Mullvad:
${todos_detalle}
No se puede entrar por SSH. Vía de emergencia: consola web del proveedor."
    elif [ "$n_activos" -eq 1 ]; then
        avisa "🟠 Acceso sin respaldo — queda ${activos_flag}" \
"De los ${#PROXYS[@]} relays solo sigue activo ${activos_flag}.
Si se cae, se pierde el acceso. Conviene sustituir los caídos cuanto antes."
    fi
fi

if [ "$TEST" -eq 1 ]; then
    echo "-- estado actual (no guardado) --"
    cat "$NUEVO"
    rm -f "$NUEVO"
    exit 0
fi

mv "$NUEVO" "$STATE" 2>/dev/null || rm -f "$NUEVO"
[ "$primera_vez" -eq 1 ] && echo "proxy-watch: línea base fijada ($n_activos/${#PROXYS[@]} activos)."
exit 0
