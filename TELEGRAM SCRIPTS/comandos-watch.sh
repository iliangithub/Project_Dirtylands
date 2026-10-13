#!/usr/bin/env bash
#
# comandos-watch.sh
# Sigue el journal y avisa por Telegram de las ordenes que se teclean en el
# ANFITRION. Las anota registro-comandos.sh, que se instala en
# /etc/profile.d/. Corre como servicio systemd.
#
# La maquina principal no se toca nunca, asi que lo normal es que este canal
# no diga nada en semanas. Esa es la idea: el silencio es la prueba de que no
# hay nadie dentro, y una sola linea es motivo para mirar.
#
# POR QUE SE AGRUPA. Un aviso por orden es inservible: en cuanto alguien entra
# y trabaja diez minutos, el movil se colapsa y se deja de leer, que es como
# no tener aviso ninguno. Se junta lo que llega y se manda de una pieza en
# cuanto hay una pausa, o antes si se acumulan demasiadas.
#
set -euo pipefail

# El servicio que avisa y la maquina de la que habla. Ver el comentario de
# mas abajo, donde se compone el mensaje.
SERVICIO="${SERVICIO:-dirtyland-cmdwatch}"
MAQUINA="${MAQUINA:-Maquina VPS principal}"
# El emoji se construye con printf y NO se escribe como "\xf0\x9f\x9a\xa8"
# dentro de unas comillas dobles: bash no interpreta esos escapes ahi y la
# secuencia sale literal en el mensaje. Paso, y se vio en el movil. Es la
# misma forma octal que usa daily-digest.sh para sus puntos de color.
ALARMA=$(printf '\360\237\232\250')
ALERT="${ALERT:-/opt/dirtyland/monitor/send-alert.sh}"

# Segundos de silencio que cierran un grupo, y tope de ordenes por mensaje.
# 20 s es suficiente para que una tanda de ordenes seguidas viaje junta y lo
# bastante corto para enterarse mientras aun esta pasando.
ESPERA="${COMANDOS_ESPERA:-20}"
# Donde se apunta por donde iba, para no perder nada al reiniciar. Ver el
# comentario del journalctl, al final.
CURSOR="${COMANDOS_CURSOR:-/opt/dirtyland/monitor/cmdwatch.cursor}"
MAXIMO="${COMANDOS_MAXIMO:-25}"

LIB_TELEGRAM=/opt/dirtyland/monitor/lib-telegram.sh
if [ -r "$LIB_TELEGRAM" ]; then
    # shellcheck source=/dev/null
    . "$LIB_TELEGRAM"
else
    echo "aviso: falta $LIB_TELEGRAM" >&2
    tg_escapar() {
        local t="${1:-}"; t="${t//&/\&amp;}"; t="${t//</\&lt;}"; t="${t//>/\&gt;}"
        printf '%s' "$t"
    }
fi

LIB_IPS=/opt/dirtyland/monitor/lib-ips.sh
if [ -r "$LIB_IPS" ]; then
    # shellcheck source=/dev/null
    . "$LIB_IPS"
else
    marca_propia() { return 0; }
fi

NL=$'\n'

# campo NOMBRE LINEA -> el valor de "nombre=" en una linea del registro.
#
# Se lee de IZQUIERDA a DERECHA y "cmd" se trata aparte, porque la orden es lo
# ULTIMO de la linea y puede contener cualquier cosa, "pwd=" y "rc=" incluidos.
# Si se buscara "pwd=" a lo bruto, bastaria con que alguien tecleara
#   echo pwd=/falso
# para que el aviso ensenara un directorio inventado. La orden nunca se usa
# para decidir nada: se recorta desde " cmd=" y todo lo demas queda intacto.
campo() {
    local nombre="$1" linea="$2" resto
    case "$nombre" in
        cmd) printf '%s' "${linea#* cmd=}" ;;
        *)
            resto="${linea#*${nombre}=}"
            printf '%s' "${resto%% *}"
            ;;
    esac
}

# Compone y manda el aviso de una tanda. Recibe el bloque acumulado por la
# entrada estandar para no depender de una variable global gigante.
enviar_tanda() {
    local clave="$1" cuantas="$2" cuerpo="$3"
    local usuario origen tty propia
    IFS='|' read -r usuario origen tty <<< "$clave"
    propia=$(marca_propia "$origen" 2>/dev/null || true)
    local ts; ts=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

    local titulo="orden"
    [ "$cuantas" -ne 1 ] && titulo="ordenes"

    # QUIEN AVISA Y DE QUE MAQUINA, en la primera linea. Por este mismo chat
    # llegan los avisos de los dos senuelos, y un aviso de ordenes ejecutadas
    # se lee MUY distinto segun de donde venga: dentro de Cowrie es lo normal
    # ---para eso esta---, y en el anfitrion es que hay alguien dentro de la
    # maquina de verdad. Confundirlos es confundir "todo va bien" con "esto
    # es grave".
    "$ALERT" "<b>[${SERVICIO}] ${MAQUINA}</b>
<b>${ALARMA} Esto NO son los senuelos ${ALARMA}</b>
<b>${cuantas} ${titulo}  ---  $(tg_escapar "$usuario") desde $(tg_escapar "$origen")${propia}  tty $(tg_escapar "$tty")</b>
<i>${ts}</i>

<pre>${cuerpo}</pre>"
}

# --- El bucle -------------------------------------------------------------
#
# Se guarda UNA tanda por sesion (usuario+origen+tty). Dos personas a la vez
# es raro, pero mezclar sus ordenes en un mismo mensaje seria justo el error
# que hace inutil el aviso.
declare -A ACUM CUENTA

vaciar_todo() {
    local k
    for k in "${!ACUM[@]}"; do
        [ -z "${ACUM[$k]}" ] && continue
        enviar_tanda "$k" "${CUENTA[$k]}" "${ACUM[$k]}" || true
        ACUM[$k]=""; CUENTA[$k]=0
    done
}

procesar() {
    local linea usuario origen tty pwd rc orden clave
    while true; do
        if IFS= read -r -t "$ESPERA" linea; then
            # Lineas que no son nuestras (o un journal con prefijo) se ignoran.
            case "$linea" in *" cmd="*) ;; *) continue ;; esac

            usuario=$(campo user "$linea")
            origen=$(campo from "$linea")
            tty=$(campo tty "$linea")
            pwd=$(campo pwd "$linea")
            rc=$(campo rc "$linea")
            orden=$(campo cmd "$linea")
            clave="${usuario}|${origen}|${tty}"

            # El directorio solo se ensena cuando cambia: repetirlo en cada
            # linea llena el mensaje de ruido y lo hace ilegible en el movil.
            local cabecera=""
            if [ "${ULTIMO_PWD[$clave]:-}" != "$pwd" ]; then
                cabecera="[${pwd}]${NL}"
                ULTIMO_PWD[$clave]="$pwd"
            fi
            # El codigo de salida solo si NO es 0: lo interesante es lo que
            # falla, y un "(0)" en cada linea no aporta nada.
            local sufijo=""
            [ "${rc:-0}" != "0" ] && sufijo="   <- rc=${rc}"

            ACUM[$clave]="${ACUM[$clave]:-}${cabecera}$(tg_escapar "$orden")${sufijo}${NL}"
            CUENTA[$clave]=$(( ${CUENTA[$clave]:-0} + 1 ))

            if [ "${CUENTA[$clave]}" -ge "$MAXIMO" ]; then
                enviar_tanda "$clave" "${CUENTA[$clave]}" "${ACUM[$clave]}" || true
                ACUM[$clave]=""; CUENTA[$clave]=0
                unset "ULTIMO_PWD[$clave]"
            fi
        else
            # read devuelve >128 cuando vence el plazo y <=128 al acabarse la
            # entrada. Distinguirlo importa: con el plazo hay que mandar lo
            # acumulado y seguir; con el fin de la entrada, mandarlo y salir.
            local salida=$?
            vaciar_todo
            [ "$salida" -le 128 ] && return 0
        fi
    done
}
declare -A ULTIMO_PWD

# Puerta para las pruebas, igual que en ssh-watch.sh: con esto se puede hacer
# "source" y quedarse con las funciones sin arrancar el seguimiento.
if [ "${COMANDOS_WATCH_SOLO_FUNCIONES:-0}" = "1" ]; then
    return 0
fi

# Con --stdin lee de la entrada estandar en vez del journal. Es lo que usa la
# prueba: asi se ejercita el MISMO bucle que corre en produccion en vez de una
# copia parecida.
if [ "${1:-}" = "--stdin" ]; then
    procesar
else
    # --cursor-file NO ES UN ADORNO: sin el, aqui iba "-n 0", que significa
    # "empieza desde ahora mismo", y TODO lo anotado mientras el servicio
    # estaba parado ---o durante el momento que tarda journalctl en
    # engancharse--- se perdia para siempre y sin dejar rastro.
    #
    # Paso el 2026-08-29: al reiniciar el servicio se comio las dos ordenes
    # siguientes. Estaban en el journal, se veian con journalctl a mano, y no
    # llegaron nunca al movil. Un vigilante que pierde lo que vigila JUSTO
    # cuando se le reinicia es peor que no tenerlo, porque uno cree que lo
    # tiene.
    #
    # Con el fichero de cursor, journalctl retoma exactamente donde lo dejo.
    # La primera vez, cuando ese fichero aun no existe, manda el "-n 0" y se
    # empieza desde el final: en una instalacion nueva no interesa el
    # historico entero.
    procesar < <(journalctl -t dirtyland-cmd -f -n 0 \
        --cursor-file="$CURSOR" -o cat --no-pager)
fi
