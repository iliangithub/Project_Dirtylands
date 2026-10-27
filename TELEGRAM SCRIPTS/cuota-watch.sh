#!/usr/bin/env bash
# cuota-watch.sh
# Avisa cuando una plataforma agota su cuota diaria de llamadas, y avisa
# tambien cuando vuelve. Pensado para cron cada pocos minutos.
#
#   --test   Manda un aviso de ejemplo y sale, sin tocar el estado.
#
# POR QUE EXISTE:
#
# El 2026-09-11 AbuseIPDB agoto su cupo a las 15:01 y el senuelo estuvo cinco
# horas y media sin denunciar nada. No salto ninguna alarma, y con razon: el
# sistema estaba haciendo lo correcto --- QuotaExceeded no es un error, es el
# limitador funcionando --- y por eso justamente no se entera nadie.
#
# Pero hay que saberlo EL MISMO DIA. Con lookback_hours = 24, lo que no sale
# hoy se cae de la ventana y no se denuncia jamas: no es un retraso, es una
# perdida. Y la senal de que el plan gratuito se ha quedado corto es
# exactamente esta, repetida dia tras dia.
#
# POR QUE VA AL BOT DEL ANFITRION Y NO AL DEL SEÑUELO:
#
# Se envia con send-alert.sh, o sea el canal del resumen diario, por lo mismo
# que breaker-watch.sh: el otro canal es el del honeypot, donde entran decenas
# de avisos de ataques al dia. Esto no es un ataque --- es una limitacion
# NUESTRA que pide una decision NUESTRA (pedir mas cupo, o asumirlo).
#
# AVISARA CASI TODOS LOS DIAS, y eso es informacion, no ruido: mientras
# AbuseIPDB siga en el plan gratuito el cupo se agota a diario, y el mensaje
# dice A QUE HORA se agoto. La hora es el dato: si un dia salta a las 09:00 en
# vez de a las 15:00, el ritmo de ataque se ha doblado. El dia que deje de
# llegar es que el cupo por fin sobra.
#
# Solo se avisa en las TRANSICIONES. Con cron cada pocos minutos, repetirlo
# mientras siga agotado serian cientos de mensajes iguales al dia, y a la
# tercera vez ya no los lee nadie --- que es lo mismo que no avisar, pero
# molestando.
set -euo pipefail

# Rutas sobreescribibles por entorno, igual que en breaker-watch.sh: es lo que
# permite ensayar el vigilante contra una base de mentira sin tocar la de
# verdad ni mandar nada a Telegram.
ALERT="${ALERT:-/opt/dirtyland/monitor/send-alert.sh}"
STATE_DB="${STATE_DB:-/var/lib/dirtyland-reporter/state.sqlite3}"
STATE_DIR="${STATE_DIR:-/var/lib/dirtyland-reporter}"
STATE="${STATE:-$STATE_DIR/cuota-telegram.state}"
PR="${PR:-/opt/dirtyland/platform-reporter}"

TEST=0
[ "${1:-}" = "--test" ] && TEST=1

[ -x "$ALERT" ] || { echo "cuota-watch: falta $ALERT" >&2; exit 1; }

# --------------------------------------------------------------- el reloj
#
# EL DIA ES UTC, y no es un detalle. El contador de la base se indexa con
# datetime.now(timezone.utc).strftime("%Y-%m-%d") (ver state.py), y las dos
# plataformas con cupo lo reinician a medianoche UTC. Calcular esto en hora
# local diria una hora equivocada en cuanto el equipo no este en UTC --- y el
# nuestro esta en Europe/Madrid.
HOY="${HOY:-$(date -u +%F)}"

cuanto_falta() {
    local ahora manana faltan h m
    ahora=$(date -u +%s)
    manana=$(TZ=UTC date -d 'tomorrow 00:00' +%s)
    faltan=$(( manana - ahora ))
    [ "$faltan" -lt 0 ] && faltan=0
    h=$(( faltan / 3600 ))
    m=$(( (faltan % 3600) / 60 ))
    if [ "$h" -gt 0 ]; then
        printf '%d h %d min' "$h" "$m"
    else
        printf '%d min' "$m"
    fi
}

# Nombre presentable. Un aviso que dice "abuseipdb" obliga a traducir mentalmente
# a quien lo lee en el movil a las tres de la manana.
bonito() {
    case "$1" in
        abuseipdb)     printf 'AbuseIPDB' ;;
        virustotal)    printf 'VirusTotal' ;;
        malwarebazaar) printf 'MalwareBazaar' ;;
        threatfox)     printf 'ThreatFox' ;;
        urlhaus)       printf 'URLhaus' ;;
        *)             printf '%s' "$1" ;;
    esac
}

if [ "$TEST" -eq 1 ]; then
    "$ALERT" "<strong>[cuota-watch] 🚨 Cuota superada 🚨</strong>
Prueba manual, no se ha agotado nada.
La plataforma <u>AbuseIPDB</u> ha superado su cuota de <code>1000 llamadas/dia</code>.
Van <code>1000/1000</code> hoy (<code>${HOY}</code> UTC), asi que no publica nada mas.
Vuelve dentro de <code>$(cuanto_falta)</code>, a las 00:00 UTC."
    echo "cuota-watch: aviso de prueba enviado."
    exit 0
fi

# Sin base todavia no hay nada que vigilar. No es un error: el reporter puede
# no haber corrido nunca.
[ -f "$STATE_DB" ] || { echo "cuota-watch: aun no existe $STATE_DB"; exit 0; }
command -v sqlite3 >/dev/null || { echo "cuota-watch: falta sqlite3" >&2; exit 1; }
mkdir -p "$STATE_DIR"

# ------------------------------------------------------------ los limites
#
# SE LEEN DE ratelimit.py, no se copian aqui. Es la unica fuente: si alguien
# sube el cupo de AbuseIPDB al contratar un plan, este vigilante lo sigue solo.
# Una copia en este fichero acabaria avisando de un limite que ya no existe, y
# ese es el peor fallo posible en algo cuyo trabajo es avisar.
#
# Las plataformas con cupo None (las tres de abuse.ch) no aparecen: no tienen
# limite publicado, asi que no hay nada que superar. De esas se ocupa
# breaker-watch.sh, que vigila otra cosa.
LIMITES="${LIMITES:-}"
if [ -z "$LIMITES" ]; then
    LIMITES=$(python3 - "$PR" <<'PY' 2>/dev/null || true
import sys
sys.path.insert(0, sys.argv[1])
from common.ratelimit import LIMITS
for nombre, (_por_min, por_dia) in LIMITS.items():
    if por_dia:
        print(nombre, por_dia)
PY
)
fi
if [ -z "$LIMITES" ]; then
    echo "cuota-watch: no pude leer los limites de $PR/common/ratelimit.py" >&2
    exit 1
fi

# ------------------------------------------------------------- el estado
#
# Lectura en SOLO LECTURA: el reporter puede estar escribiendo en esta misma
# base ahora mismo, y un vigilante nunca debe poder corromper lo que vigila.
#
# Se mira api_calls y NO quota, que es el tropiezo facil: quota cuenta lo
# PUBLICADO y api_calls cuenta las LLAMADAS, que es contra lo que compara el
# limitador. En VirusTotal la diferencia es enorme --- la mayoria de sus
# llamadas son consultas de hash que no publican nada --- y mirando quota el
# aviso no llegaria nunca.
usos=$(sqlite3 -separator '|' "file:${STATE_DB}?mode=ro" \
       "SELECT platform, calls FROM api_calls WHERE day='${HOY}';" \
       2>/dev/null || true)

declare -A usado=()
while IFS='|' read -r plat n; do
    [ -n "$plat" ] && usado["$plat"]="$n"
done <<< "$usos"

# Los limites, en una tabla y de una vez. La primera version los buscaba con un
# bucle dentro del bucle de recuperacion, y ahi habia un fallo de los que no se
# ven leyendo: la ultima orden era `[ "$p" = "$plat" ] && echo "$l"`, que en la
# linea que NO casa devuelve 1. Ese 1 se convertia en el codigo de salida del
# bucle, y con `set -e` la asignacion entera mataba el guion en silencio ---
# justo antes de mandar el aviso de que la cuota habia vuelto.
declare -A limite_de=()
while read -r plat lim; do
    [ -n "$plat" ] && limite_de["$plat"]="$lim"
done <<< "$LIMITES"

anterior=""
[ -f "$STATE" ] && anterior=$(cat "$STATE" 2>/dev/null || true)

nuevas=""
avisados=0

while read -r plat limite; do
    [ -n "$plat" ] || continue
    n="${usado[$plat]:-0}"
    [ "$n" -ge "$limite" ] || continue

    # La huella lleva el DIA: cuando cambie la fecha, la misma plataforma
    # agotada vuelve a ser una transicion y se avisa otra vez. Sin la fecha, el
    # aviso solo llegaria el primer dia y nunca mas.
    huella="${plat}|${HOY}"
    nuevas+="${huella}"$'\n'

    case "$anterior" in
        *"$huella"*) continue ;;          # ya avisado hoy
    esac

    "$ALERT" "<strong>[cuota-watch] 🚨 Cuota superada 🚨</strong>
La plataforma <u>$(bonito "$plat")</u> ha superado su cuota de <code>${limite} llamadas/dia</code>.
Van <code>${n}/${limite}</code> hoy (<code>${HOY}</code> UTC), asi que no publica nada mas.
Vuelve dentro de <code>$(cuanto_falta)</code>, a las 00:00 UTC."
    avisados=$((avisados + 1))
    echo "cuota-watch: aviso de cuota agotada en ${plat} (${n}/${limite})."
done <<< "$LIMITES"

# Lo que estaba agotado y ya no lo esta. Pasa al cambiar el dia, que es el caso
# normal, y tambien si alguien amplia el cupo. Se cierra el aviso anterior para
# no dejar a quien lo leyo pensando que sigue parado.
while read -r huella; do
    [ -n "$huella" ] || continue
    case "$nuevas" in
        *"$huella"*) continue ;;
    esac
    plat=${huella%%|*}
    limite="${limite_de[$plat]:-?}"
    n="${usado[$plat]:-0}"
    "$ALERT" "<strong>[cuota-watch] ✅ Cuota restablecida</strong>
<u>$(bonito "$plat")</u> vuelve a publicar: <code>${n}/${limite}</code> llamadas hoy."
    avisados=$((avisados + 1))
    echo "cuota-watch: aviso de cuota restablecida en ${plat}."
done <<< "$anterior"

printf '%s' "$nuevas" > "$STATE"

[ "$avisados" -gt 0 ] || echo "cuota-watch: sin novedad."
