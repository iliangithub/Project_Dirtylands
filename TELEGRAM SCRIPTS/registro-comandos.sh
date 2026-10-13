# registro-comandos.sh
#
# Se instala como /etc/profile.d/dirtyland-registro.sh y hace que CADA orden
# que alguien teclee en el anfitrion quede anotada en el journal con la
# etiqueta "dirtyland-cmd". De ahi la recoge comandos-watch.sh y la manda a
# Telegram.
#
# Para que sirve. La maquina principal no se toca nunca: lo normal es que en
# 24 horas no se ejecute ni una sola orden. Con eso, el valor de esto no es
# tanto leer lo que se ejecuta como poder afirmar que NO se ejecuta nada.
# Un canal vacio es la prueba; una linea es una pregunta.
#
# NO es un fichero ejecutable: lo carga el shell con "source", asi que no
# lleva "#!" ni bit de ejecucion.
#
# SE CARGA DESDE DOS SITIOS, Y HACEN FALTA LOS DOS. Esto no es cinturon y
# tirantes: cada uno cubre unos shells que el otro no ve.
#
#   /etc/profile.d/dirtyland-registro.sh   lo leen los shells de LOGIN
#   /etc/bash.bashrc                       lo leen los interactivos NO login
#
# Con solo el primero quedaba fuera justo lo que mas importa: un shell de
# root abierto con "sudo su", "sudo -s" o "sudo bash" NO es un shell de
# login, asi que no pasa por /etc/profile.d y no se registraba NADA de lo
# que se tecleara dentro. Se veia "cmd=sudo su" y despues silencio absoluto,
# sin ningun error. Con "sudo -i" o "sudo su -" si funcionaba, que es lo que
# hacia el fallo dificil de ver: dependia de como te hicieras root.
#
# En Debian el /etc/profile carga tambien /etc/bash.bashrc, asi que un shell
# de login pasa por los dos. Por eso importa la guarda de DIRTYLAND_REGISTRO
# de mas abajo: sin ella, la misma orden se anotaria dos veces.
#
# QUE COGE Y QUE NO COGE. Conviene tenerlo claro, porque un registro que
# promete mas de lo que da es peor que no tenerlo:
#
#   SI  las ordenes tecleadas en un bash interactivo, TAL COMO SE ESCRIBEN.
#       Eso incluye lo que un auditor de llamadas al sistema NO ve: los
#       builtins ("cd", "export", "history -c") y la tuberia entera como una
#       sola linea en vez de un execve por cada tramo.
#
#   NO  lo que ejecuta un demonio, ni un proceso hijo suelto, ni una shell
#       que no sea bash ("sh", "zsh", "python -c"). Y quien ya tiene shell
#       puede desactivarlo con "unset PROMPT_COMMAND".
#
# O sea: esto cuenta lo que hace una PERSONA sentada delante. Que haya
# alguien dentro lo detecta ssh-watch.sh, que mira el log de sshd y no
# depende del shell. Las dos mitades se complementan; ninguna sustituye a la
# otra. Para cobertura a nivel de llamada al sistema haria falta auditd, que
# es otro demonio con su propio riesgo de llenar el disco, y no se instala
# aqui a la ligera.

# Solo shells interactivos. Un "scp" o un "ssh maquina comando" abre un bash
# no interactivo, no tiene historial y aqui no pinta nada.
case $- in *i*) ;; *) return 0 ;; esac

# Una sola vez por shell. Sin esto, cada "bash" anidado volveria a anadirse a
# PROMPT_COMMAND y la misma orden se anotaria tantas veces como shells haya.
[ -n "${DIRTYLAND_REGISTRO:-}" ] && return 0
DIRTYLAND_REGISTRO=1

# La orden se saca del HISTORIAL y no de una variable, porque el historial la
# guarda ya expandida y con sus comillas, que es lo que interesa leer.
_dirtyland_anotar() {
    # Lo PRIMERO: guardar el codigo de salida. Todo lo que venga despues lo
    # pisa, y el prompt del usuario suele ensenarlo. Si esta funcion lo
    # cambiara, cualquiera que mire su propio $? veria el nuestro.
    local codigo=$?
    local h numero texto primera=""

    # LA MARCA DE ARRANQUE SE PONE AQUI, ANTES DE MIRAR EL HISTORIAL. Ponerla
    # despues tenia un agujero: en una cuenta recien creada el historial esta
    # vacio, el primer disparo se iba por el "return" de mas abajo sin llegar a
    # marcar nada, y entonces la PRIMERA ORDEN DE VERDAD se tomaba por el
    # arranque y se perdia. Lo caza la prueba del historial vacio.
    if [ -z "${_DIRTYLAND_ARRANCADO:-}" ]; then
        _DIRTYLAND_ARRANCADO=1
        primera=1
    fi
    h=$(HISTTIMEFORMAT= history 1 2>/dev/null) || return $codigo

    # "  123  ls -la"  ->  numero=123  texto="ls -la"
    [[ $h =~ ^[[:space:]]*([0-9]+)[[:space:]]+(.*)$ ]] || return $codigo
    numero=${BASH_REMATCH[1]}
    texto=${BASH_REMATCH[2]}
    [ -z "$texto" ] && return $codigo

    # EL PRIMER DISPARO NO ANOTA: SOLO TOMA NOTA DE POR DONDE IBA.
    #
    # Al abrir un shell, bash carga ~/.bash_history, y ese primer disparo ---el
    # del prompt inicial, antes de que nadie haya tecleado nada--- encuentra en
    # "history 1" la ultima linea de una sesion ANTERIOR. Sin esto se anotaba
    # como recien ejecutada.
    #
    # Se vio el 2026-08-29: se abrieron tres shells de root y llegaron dos
    # avisos de "exit" que no correspondian a nada de lo que se acababa de
    # teclear; eran el final de sesiones viejas de root. Un registro que
    # inventa ordenes es peor que uno que se calla, porque manda a investigar
    # humo.
    #
    # No vale hacerlo al cargar el fichero: bash lee los ficheros de arranque
    # ANTES de cargar el historial, asi que ahi "history 1" todavia esta vacio
    # ---comprobado---. Tiene que ser en el primer disparo.
    if [ -n "$primera" ]; then
        _DIRTYLAND_ULTIMO=$numero
        return $codigo
    fi

    # Se compara el NUMERO de historial, no el texto. PROMPT_COMMAND se
    # dispara en cada prompt, tambien al dar solo a Enter, asi que sin esto la
    # ultima orden se anotaria una y otra vez. Y comparando el texto se
    # perderia la orden repetida a proposito, que es justo la que interesa
    # cuando alguien esta insistiendo en algo.
    [ "$numero" = "${_DIRTYLAND_ULTIMO:-}" ] && return $codigo
    _DIRTYLAND_ULTIMO=$numero

    logger -t dirtyland-cmd -p authpriv.notice -- \
        "user=${USER:-desconocido} tty=${_DIRTYLAND_TTY:-?} from=${_DIRTYLAND_ORIGEN:-local} pwd=${PWD} rc=${codigo} cmd=${texto}"

    return $codigo
}

# El terminal y el origen no cambian en toda la sesion: se calculan una vez y
# no en cada prompt. "tty" es un proceso, y lanzarlo antes de cada linea que
# se teclea se nota.
#
# El "if" no es un adorno sobre "$(tty || echo ?)": cuando no hay terminal,
# tty escribe "no es un `tty'" en la SALIDA ESTANDAR ---no en la de error---
# y ademas termina con error, asi que aquella forma metia ese texto Y el "?"
# en el campo, con un salto de linea en medio. Y un salto de linea aqui parte
# la linea del syslog en dos, con lo que comandos-watch.sh ve media orden.
if _DIRTYLAND_TTY=$(tty 2>/dev/null); then
    _DIRTYLAND_TTY=${_DIRTYLAND_TTY#/dev/}
else
    _DIRTYLAND_TTY="?"
fi
_DIRTYLAND_ORIGEN=${SSH_CONNECTION%% *}
[ -z "$_DIRTYLAND_ORIGEN" ] && _DIRTYLAND_ORIGEN=local

# Se anade DELANTE de lo que ya hubiera, no se sustituye: si alguien tiene su
# propio PROMPT_COMMAND, se respeta. Y va primero para que lea el $? de la
# orden del usuario y no el de lo que ese otro PROMPT_COMMAND deje.
PROMPT_COMMAND="_dirtyland_anotar${PROMPT_COMMAND:+; $PROMPT_COMMAND}"

# Y AL SALIR, otra vez. PROMPT_COMMAND se dispara ANTES de cada prompt, asi
# que la ultima orden de la sesion no llega a anotarse nunca: despues de
# "exit" ya no hay otro prompt. Justamente la ultima ---lo que alguien hace
# antes de irse--- es la que mas interesa leer.
#
# La guarda del numero de historial evita que esto duplique nada: si la ultima
# orden ya se anoto por el camino normal, aqui se reconoce y se calla.
#
# No devuelve el control a nadie ni cambia el codigo de salida del shell: una
# trampa de EXIT que no llama a "exit" deja el estado como estaba.
trap '_dirtyland_anotar' EXIT
