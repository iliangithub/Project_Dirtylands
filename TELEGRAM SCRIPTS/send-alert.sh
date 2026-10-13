#!/usr/bin/env bash
# send-alert.sh
# Envia un mensaje a Telegram. Uso: send-alert.sh "texto en HTML"
set -euo pipefail

# Las rutas se pueden sobreescribir por entorno, igual que CFG_REPORTER en
# el resumen diario. No es un adorno: sin esto la prueba tendria que copiar
# la logica del silenciador en vez de ejercitar ESTE fichero, y lo que se
# probaria seria la copia.
ENV_FILE="${ENV_FILE:-/opt/dirtyland/monitor/telegram.env}"
[ -f "$ENV_FILE" ] || { echo "ERROR: falta $ENV_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$ENV_FILE"

# Los limites de Telegram, definidos en un solo sitio. Ver la cabecera de ese
# fichero: son dos, y el que de verdad muerde es el de 100 entities, que no da
# ningun error y se limita a dejar sin formato el final del mensaje.
#
# Con red, igual que lib-ips.sh: si faltara, se manda de una pieza. Un aviso
# con el final estropeado sigue siendo mejor que ningun aviso.
LIB_TELEGRAM="${LIB_TELEGRAM:-/opt/dirtyland/monitor/lib-telegram.sh}"
if [ -r "$LIB_TELEGRAM" ]; then
    # shellcheck source=/dev/null
    . "$LIB_TELEGRAM"
else
    echo "aviso: falta $LIB_TELEGRAM; se enviara sin trocear" >&2
    tg_enviar_troceado() { "$1" "${2}
${3}"; }
fi

# --- El silenciador ---------------------------------------------------
#
# Cuando el operador esta FISICAMENTE en la maquina, todo lo que toca genera
# avisos: entra por SSH, teclea ordenes, reinicia contenedores. Sin esto, el
# movil se colapsa justo cuando menos falta hace, porque quien lee el aviso es
# quien lo esta provocando. Se apaga a mano con ~/estoy_dentro.py y se vuelve
# a encender al salir.
#
# Los avisos silenciados NO se tiran: se anotan en un carrete que el resumen
# diario cuenta y ensena. Un aviso perdido en silencio es una intrusion que
# nadie mirara jamas, y ese es exactamente el fallo que este proyecto ya
# cometio una vez con el cron del reporter en simulacion.
#
# El resumen diario y cualquier cosa que DEBA llegar pase lo que pase se
# manda con "--siempre". Si el propio resumen se silenciara, no quedaria nada
# que avisara de que la vigilancia esta apagada.
SILENCIO="${SILENCIO:-/opt/dirtyland/monitor/silencio}"
CARRETE="${CARRETE:-/opt/dirtyland/monitor/silenciadas.log}"

# silenciado -> 0 si hay que callarse. Un plazo vencido NO silencia: el
# fichero puede quedarse ahi para siempre y la vigilancia tiene que volver
# sola. Es la red de seguridad para el dia que alguien lo apague y se olvide.
silenciado() {
    [ -f "$SILENCIO" ] || return 1
    local hasta
    hasta=$(sed -n 's/^hasta=\([0-9]*\)$/\1/p' "$SILENCIO" | head -1)
    [ -z "$hasta" ] && return 1          # sin plazo legible: no se silencia
    [ "$hasta" = "0" ] && return 0       # 0 = hasta que se encienda a mano
    [ "$(date +%s)" -lt "$hasta" ]
}

SIEMPRE=0
if [ "${1:-}" = "--siempre" ]; then
    SIEMPRE=1
    shift
fi

MSG="$1"

if [ "$SIEMPRE" -eq 0 ] && silenciado; then
    # Solo la primera linea, y sin etiquetas: el carrete es para contar y
    # reconocer, no para releer el aviso entero.
    primera="${MSG%%$'\n'*}"
    primera=$(printf '%s' "$primera" | sed -e 's/<[^>]*>//g')
    printf '%s|%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$primera" >> "$CARRETE" 2>/dev/null || true
    exit 0
fi

# La respuesta NO se tira. "curl -s" devuelve 0 aunque Telegram conteste 400
# o 429, asi que descartarla convierte un aviso perdido en un exito aparente.
# Es exactamente como se perdio el resumen diario el dia que supero los 4096
# caracteres: nada fallo, simplemente dejo de llegar.
envia_uno() {
    local texto="$1" respuesta
    # EL TOKEN NO PUEDE IR EN LA LINEA DE ORDENES. Los argumentos de cada
    # programa los ve cualquiera que mire "ps", quedan en /proc, y ---lo que
    # lo destapo--- auditd los registra: el 2026-08-29 el token del bot
    # aparecio en el log de auditoria y salio publicado en el propio aviso de
    # Telegram, con lo que hubo que revocarlo.
    #
    # Se le pasa a curl por la ENTRADA ESTANDAR con --config, que lee de ahi
    # las mismas opciones. Lo que no es secreto puede seguir en los
    # argumentos; el token, no.
    respuesta=$(printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' \
        "$BOT_TOKEN" | curl -s --config - -X POST \
        --data-urlencode "chat_id=${CHAT_ID}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "disable_web_page_preview=true" \
        --data-urlencode "text=${texto}") || {
        echo "send-alert: curl fallo al hablar con Telegram" >&2
        return 0
    }
    case "$respuesta" in
        *'"ok":true'*) : ;;
        *) echo "send-alert: Telegram rechazo el mensaje: ${respuesta:0:300}" >&2 ;;
    esac
    return 0
}

# Se trocea en vez de recortar. Antes esto cortaba por las bravas a 3960 y
# anadia "(mensaje truncado)", y tenia dos problemas de distinto calibre:
#
#   - Tiraba informacion. Un resumen diario recortado es justo el dia en que
#     hay tanto que contar que conviene leerlo entero.
#   - Y medía la cosa equivocada: contaba los caracteres del HTML, cuando el
#     limite de Telegram es sobre el texto renderizado. La alerta de Dionaea
#     del 2026-08-20 tenia 6201 de HTML y 3179 de texto: cabia de sobra, y ese
#     recorte se habria comido la mitad del parte sin motivo.
#
# La CABECERA es la primera linea --- en todos nuestros avisos es el
# "<strong>[Dirtyland] ...</strong>" --- y se repite en cada trozo, para que
# el segundo mensaje se entienda sin haber leido el primero.
CABECERA="${MSG%%$'\n'*}"
if [ "$CABECERA" = "$MSG" ]; then
    CUERPO=""
else
    CUERPO="${MSG#*$'\n'}"
fi

tg_enviar_troceado envia_uno "$CABECERA" "$CUERPO"
