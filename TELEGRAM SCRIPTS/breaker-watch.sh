#!/usr/bin/env bash
# breaker-watch.sh
# Avisa en cuanto salta el cortacircuitos de la cuenta de abuse.ch, y avisa
# tambien cuando se rearma. Pensado para cron cada pocos minutos.
#
#   --test   Manda un aviso de ejemplo y sale, sin tocar el estado.
#
# POR QUE EXISTE, teniendo ya el resumen diario:
#
# Cuando el cortacircuitos salta, las TRES plataformas de abuse.ch dejan de
# publicar --- MalwareBazaar, ThreatFox y URLhaus comparten una sola cuenta ---
# y se quedan asi hasta que una persona las rearma a mano. Enterarse a la
# manana siguiente son hasta veinticuatro horas de capturas que no se envian a
# ninguna parte, y ademas veinticuatro horas sin saber que abuse.ch nos esta
# rechazando algo, que es justo el aviso que hay que atender el mismo dia.
#
# POR QUE VA AL BOT DEL ANFITRION Y NO AL DEL SEÑUELO:
#
# Se envia con send-alert.sh, o sea el canal del resumen diario y los accesos
# a la VPS. Es una decision, no una casualidad: el otro canal es el del
# honeypot, donde entran decenas de avisos de ataques al dia y donde esto se
# perderia entre el ruido. Esto no es un ataque --- es una averia NUESTRA que
# pide una accion NUESTRA, y va donde van las cosas que tenemos que arreglar.
set -euo pipefail

# Las rutas admiten sobreescritura por entorno, como en lib-ips.sh. No es un
# adorno: es lo que permite probar el vigilante contra una base de mentira sin
# tocar la de verdad ni mandar nada a Telegram. Un vigilante que no se puede
# ensayar solo se estrena el dia que hace falta.
ALERT="${ALERT:-/opt/dirtyland/monitor/send-alert.sh}"
STATE_DB="${STATE_DB:-/var/lib/dirtyland-reporter/state.sqlite3}"
STATE_DIR="${STATE_DIR:-/var/lib/dirtyland-reporter}"
STATE="${STATE:-$STATE_DIR/breaker-telegram.state}"
CUENTA="${CUENTA:-abuse.ch}"
REPORTER="${REPORTER:-/opt/dirtyland/platform-reporter/orchestrator.py}"
CFG="${CFG:-/opt/dirtyland/platform-reporter/config.ini}"

TEST=0
[ "${1:-}" = "--test" ] && TEST=1

[ -x "$ALERT" ] || { echo "breaker-watch: falta $ALERT" >&2; exit 1; }

# El comando de rearme, en una sola variable: aparece en el aviso y quien lo
# lee lo necesita entero para poder copiarlo desde el movil.
REARME="sudo python3 ${REPORTER} -c ${CFG} --reset-breaker"

if [ "$TEST" -eq 1 ]; then
    "$ALERT" "<strong>[Dirtyland] 🚨 Cortacircuitos SALTADO</strong>
Prueba manual, no ha saltado nada.
<u>abuse.ch</u> (MalwareBazaar + ThreatFox + URLhaus) dejaria de publicar.
Cuando: <code>2026-01-01 00:00:00</code>
Motivo: <code>ejemplo</code>
Rearmar: <code>${REARME}</code>"
    echo "breaker-watch: aviso de prueba enviado."
    exit 0
fi

# Sin base todavia no hay nada que vigilar. No es un error: el reporter puede
# no haber corrido nunca.
[ -f "$STATE_DB" ] || { echo "breaker-watch: aun no existe $STATE_DB"; exit 0; }
command -v sqlite3 >/dev/null || { echo "breaker-watch: falta sqlite3" >&2; exit 1; }
mkdir -p "$STATE_DIR"

# Lectura en SOLO LECTURA: el reporter puede estar escribiendo en esta misma
# base ahora mismo, y un vigilante nunca debe poder corromper lo que vigila.
#
# Se pide una linea con separador, en vez de tres consultas: asi no puede
# darse el caso de leer un "ha saltado" y un motivo de dos instantes
# distintos. La salida es vacia si no hay nada, que es el caso normal.
fila=$(sqlite3 -separator '|' "file:${STATE_DB}?mode=ro" \
       "SELECT tripped_at, replace(replace(reason, char(10), ' '), '|', '/')
        FROM breaker WHERE account='${CUENTA}' LIMIT 1;" 2>/dev/null || true)

anterior=""
[ -f "$STATE" ] && anterior=$(cat "$STATE" 2>/dev/null || true)

# Solo se avisa en los CAMBIOS de estado. Con cron cada pocos minutos, avisar
# mientras siga saltado serian trescientos mensajes iguales al dia, y a la
# tercera vez nadie los lee --- que es lo mismo que no avisar, pero molestando.
if [ -n "$fila" ]; then
    cuando=${fila%%|*}
    motivo=${fila#*|}
    huella="SALTADO ${cuando}"
    if [ "$huella" = "$anterior" ]; then
        echo "breaker-watch: sigue saltado desde ${cuando}, ya avisado."
        exit 0
    fi
    # El motivo lo compone el reporter, no el atacante, pero se escapa igual:
    # arrastra el texto del rechazo de abuse.ch, y eso viene de fuera. Un "<"
    # ahi dentro dejaria el aviso en un 400 --- justo el aviso que menos nos
    # podemos permitir perder.
    motivo=${motivo//&/\&amp;}; motivo=${motivo//</\&lt;}; motivo=${motivo//>/\&gt;}
    "$ALERT" "<strong>[Dirtyland] 🚨 Cortacircuitos SALTADO</strong>
<u>abuse.ch</u> ha dejado de publicar: MalwareBazaar, ThreatFox y URLhaus, las tres.
Cuando: <code>${cuando}</code>
Motivo: <code>${motivo}</code>
Se queda asi hasta rearmarlo a mano:
<code>${REARME}</code>
Hazlo solo despues de entender por que salto."
    printf '%s' "$huella" > "$STATE"
    echo "breaker-watch: aviso de salto enviado (${cuando})."
    exit 0
fi

# No hay salto. Si antes lo habia, alguien lo ha rearmado y eso tambien se
# cuenta: cierra el aviso anterior, y deja constancia de cuando volvimos a
# publicar sin tener que ir a mirar el log.
if [ -n "$anterior" ]; then
    "$ALERT" "<strong>[Dirtyland] ✅ Cortacircuitos rearmado</strong>
<u>abuse.ch</u> vuelve a publicar: MalwareBazaar, ThreatFox y URLhaus."
    rm -f "$STATE"
    echo "breaker-watch: rearme avisado."
    exit 0
fi

echo "breaker-watch: sin novedad."
