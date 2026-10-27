# shellcheck shell=bash
# lib-telegram.sh — que Telegram entregue el mensaje ENTERO. Se SOURCEA.
#
#   . /opt/dirtyland/monitor/lib-telegram.sh
#
# sendMessage tiene DOS limites y hay que respetar los dos, porque un mensaje
# puede ir sobradisimo en uno y pasarse en el otro sin enterarse:
#
#   1. 4096 caracteres de TEXTO YA RENDERIZADO. Las etiquetas HTML NO cuentan:
#      Telegram las convierte en "entities" (tramos con formato, guardados
#      aparte con su desplazamiento y su longitud) y lo que mide son los
#      caracteres que quedan despues de quitarlas. Medir el HTML en bruto es
#      medir otra cosa distinta --- la alerta de Dionaea del 2026-08-20 tenia
#      6201 caracteres de HTML y solo 3179 de texto. Un recorte a 4000 sobre
#      el HTML se habria comido la mitad del parte sin que fallara nada.
#
#   2. 100 entities. Este es el que nos mordio, y es el peor de los dos porque
#      NO da error: Telegram acepta el mensaje, contesta "ok":true, lo entrega
#      completo... y se limita a TIRAR las entities que sobran, de la ultima
#      hacia atras. El texto llega entero, asi que de un vistazo el mensaje
#      parece correcto. Lo unico que ha pasado es que los ultimos enlaces han
#      dejado de ser enlaces.
#
# Como se vio: aquella alerta tenia 106 entities y las seis ultimas eran los
# dos ultimos enlaces a AbuseIPDB, el subrayado de "Malware capturado", el
# <code> del MD5, el <code> de la IP de origen y el enlace "Ver hash en
# VirusTotal". Los sintomas encajaron uno a uno: el enlace de VirusTotal se
# quedo en texto plano y la IP de origen, al perder su <code>, quedo suelta.
#
# Y a una IP suelta el cliente de Telegram le pone enlace automatico. O sea
# que la alerta acabo ofreciendo un enlace pulsable HACIA LA MAQUINA DEL
# ATACANTE, y quitando el unico que servia para algo. Justo al reves.
#
# De ahi una regla que conviene no olvidar al escribir estos mensajes: toda IP
# hostil va dentro de un <code>. No es cosmetica ni es para que quede mono ---
# es lo que impide que Telegram la convierta en un http:// que se puede pulsar
# sin querer desde el movil.

# Margenes deliberados por debajo de los limites reales (4096 y 100).
#
# El de entities es el que importa: como no hay error que avise, el margen es
# lo unico que separa "sale bien" de "sale mal en silencio". El de texto va
# holgado porque medimos en bytes (ver tg_longitud) y eso ya se pasa de
# prudente por su cuenta.
TG_MAX_ENTITIES="${TG_MAX_ENTITIES:-85}"
TG_MAX_TEXTO="${TG_MAX_TEXTO:-3500}"

# Cuantos mensajes como mucho por aviso. Con el formato actual entran unas 40
# IPs en cada uno, o sea que cuatro son ~160 IPs.
#
# Este tope NO es por estetica. Telegram admite del orden de 20 mensajes por
# minuto al mismo chat, y a partir de ahi contesta 429. Un trozo rechazado no
# se reintenta jamas: cuando nos enteramos, el estado del vigilante ya ha
# avanzado y ese evento no vuelve. O sea que sin tope, una ráfaga lo bastante
# grande no es que llene el chat --- es que PIERDE avisos, que es justo lo que
# veniamos a arreglar. Un barrido a un /24 son 254 IPs y siete mensajes; uno
# de mil IPs serian veinticinco, y los ultimos no llegarian.
#
# Lo que se recorta no se pierde de verdad: las conexiones siguen en la base
# de Dionaea y las IPs siguen yendo a AbuseIPDB por su camino. El aviso de
# Telegram sirve para enterarse de que esta pasando algo, y para eso 160
# lineas ya sobran; nadie lee mas en un movil.
TG_MAX_TROZOS="${TG_MAX_TROZOS:-4}"

# Texto del aviso de recorte. El emisor puede poner el suyo --- "%d" se
# sustituye por el numero de lineas omitidas --- para anadir donde mirar.
TG_NOTA_RECORTE="${TG_NOTA_RECORTE:-}"

TG_NL=$'\n'

# Salidas de tg_trocear. Se declaran aqui para que existan aunque nadie haya
# llamado todavia, y no revienten un "set -u".
TG_TROZOS=()
TG_OMITIDAS=0

# tg_entidades HTML -> cuantas entities generara ese fragmento.
#
# Se cuentan las etiquetas de CIERRE: en HTML bien formado hay exactamente una
# por entity, y contar las de apertura obligaria a distinguir <code> de
# <a href="...">, que es donde se cometen los errores.
#
# En bash puro, sin subshells: esto se llama una vez por linea y un mensaje de
# 300 IPs son 600 forks que no hacen falta.
# Las dos versiones internas dejan el resultado en TG_N / TG_L y NO imprimen.
#
# Son las que usa el bucle de troceo, y la razon es medible: "$(funcion ...)"
# arranca un subshell cada vez, o sea dos forks por linea. Midiendo un aviso
# de 254 lineas, esos forks eran 14 de los 14 segundos que tardaba --- el
# recuento en si no se notaba. Sin ellos baja a menos de un segundo.
TG_N=0
TG_L=0

_tg_entidades() {
    local resto="${1:-}"
    TG_N=0
    while [ "$resto" != "${resto#*</}" ]; do
        resto="${resto#*</}"
        TG_N=$((TG_N + 1))
    done
}

tg_entidades() {
    _tg_entidades "${1:-}"
    printf '%s' "$TG_N"
}

# tg_longitud HTML -> longitud del texto que contara Telegram.
#
# Se quitan las etiquetas y se mide en BYTES, aunque Telegram cuente en
# unidades UTF-16. Es a proposito: los bytes de UTF-8 son siempre >= esas
# unidades (un emoji son 4 bytes y 2 unidades; una vocal acentuada, 2 bytes y
# 1 unidad), asi que medir en bytes se pasa de prudente y nunca de optimista.
#
# Los bytes se consiguen con LC_ALL=C local a la funcion: ${#var} cuenta
# caracteres segun el locale, y contando caracteres un emoji valdria 1 cuando
# para Telegram vale 2. Al ser "local", el locale vuelve a lo que estaba al
# salir de la funcion.
#
# Las entidades HTML (&amp;, &lt;) tambien se cuentan enteras aunque rendericen
# a un solo caracter. Mismo criterio: pasarse contando no rompe nada.
_tg_longitud() {
    local LC_ALL=C
    local resto="${1:-}" texto=""
    while [ "$resto" != "${resto#*<}" ]; do
        texto+="${resto%%<*}"
        resto="${resto#*<}"
        resto="${resto#*>}"
    done
    texto+="$resto"
    TG_L=${#texto}
}

tg_longitud() {
    _tg_longitud "${1:-}"
    printf '%s' "$TG_L"
}

# tg_escapar TEXTO -> el mismo texto, ya seguro dentro del HTML de Telegram.
#
# OBLIGATORIO para todo lo que escriba el atacante. El caso claro es la URL de
# descarga que registra Dionaea: la elige el, y le basta con meter un "<" para
# que Telegram conteste 400 "can't parse entities". Y entonces no se pierde el
# formato --- se pierde el aviso ENTERO, porque el vigilante marca el evento
# como visto igualmente y no vuelve a mirarlo.
#
# O sea que sin escapar, cualquiera que sospeche que hay un Dionaea al otro
# lado puede apagarnos las alertas escribiendo un "<" en una URL. Ese es
# exactamente el tipo de fallo que no se descubre solo: deja de llegar el
# aviso justo cuando hay algo que avisar.
#
# Dos trampas, las dos con el mismo caracter:
#
#   1. El "&" se sustituye PRIMERO. Al reves, los "&" que introducen "&lt;" y
#      "&gt;" se volverian a escapar y saldria "&amp;lt;".
#
#   2. Los "&" del reemplazo van con barra invertida. Desde bash 5.2 un "&"
#      suelto en el lado derecho de ${var//patron/reemplazo} significa "el
#      texto que se acaba de encontrar" (la opcion patsub_replacement, activa
#      por defecto). O sea que "${t//</&lt;}" no escribia "&lt;" sino "<lt;":
#      cambiaba un "<" por otro "<" y el escapado no servia absolutamente de
#      nada. Se veia casi bien, que es lo peor que puede pasar.
tg_escapar() {
    local t="${1:-}"
    t="${t//&/\&amp;}"
    t="${t//</\&lt;}"
    t="${t//>/\&gt;}"
    printf '%s' "$t"
}

# tg_recortar TEXTO [MAX] -> recorta a MAX caracteres, con "…" si se recorto.
#
# Tambien para lo que escribe el atacante. Una URL de varios miles de
# caracteres es una sola linea que no cabe en ningun trozo, y el troceo la
# deja pasar a proposito antes que descartar el evento --- con lo que acaba
# siendo Telegram quien rechaza el mensaje. Mejor cortarla aqui.
#
# Se recorta ANTES de escapar. Al reves se podria partir un "&amp;" por la
# mitad y dejar un "&am" suelto, que es justo lo que rompe el parseo.
tg_recortar() {
    local t="${1:-}" max="${2:-200}"
    if [ "${#t}" -gt "$max" ]; then
        printf '%s…' "${t:0:$max}"
    else
        printf '%s' "$t"
    fi
}

# tg_trocear CABECERA CUERPO
#
# Reparte las lineas del CUERPO en los menos trozos posibles que quepan, y los
# deja en TG_TROZOS. La CABECERA no se reparte: se repite en todos, y por eso
# su coste se descuenta del presupuesto de cada trozo.
#
# Se corta SIEMPRE por salto de linea. Estos mensajes son de una cosa por
# linea, asi que cada trozo queda con el HTML cerrado; cortar por donde caiga
# dejaria un <a href= abierto y Telegram devolveria 400 --- y entonces se
# pierde el aviso entero, que es peor que cualquier cosa que estemos
# intentando arreglar aqui.
tg_trocear() {
    local cabecera="${1:-}" cuerpo="${2:-}"
    TG_TROZOS=()
    TG_OMITIDAS=0

    local ent_cab len_cab ent len acumulado linea e l lleno=0 nota
    _tg_entidades "$cabecera"; ent_cab=$TG_N
    _tg_longitud "$cabecera";  len_cab=$TG_L

    acumulado=""
    ent=$ent_cab
    len=$len_cab

    while IFS= read -r linea; do
        # Alcanzado el tope de mensajes ya solo se CUENTAN las lineas que
        # faltan. Contar es una suma; medirlas y pegarlas a una cadena que ya
        # es enorme no lo es --- en bash concatenar es copiar, asi que el coste
        # crece con el cuadrado. Con 3000 lineas el troceo tardaba mas de dos
        # minutos, y el vigilante corre en un cron cada pocos minutos.
        if [ "$lleno" -eq 1 ]; then
            TG_OMITIDAS=$((TG_OMITIDAS + 1))
            continue
        fi

        _tg_entidades "$linea"; e=$TG_N
        _tg_longitud "$linea";  l=$TG_L

        # El trozo solo se cierra si YA lleva algo dentro. Una linea que por si
        # sola no cabe sale igualmente, en su propio trozo y aunque se pase:
        # preferimos un mensaje demasiado largo (que como mucho Telegram
        # rechaza, y eso se ve en el journal) a un evento que no se reporta.
        if [ -n "$acumulado" ] \
           && { [ $((ent + e)) -gt "$TG_MAX_ENTITIES" ] \
                || [ $((len + l + 1)) -gt "$TG_MAX_TEXTO" ]; }; then
            TG_TROZOS+=("$acumulado")
            acumulado=""
            ent=$ent_cab
            len=$len_cab

            if [ "${#TG_TROZOS[@]}" -ge "$TG_MAX_TROZOS" ]; then
                lleno=1
                TG_OMITIDAS=$((TG_OMITIDAS + 1))
                continue
            fi
        fi

        acumulado+="${acumulado:+$TG_NL}$linea"
        ent=$((ent + e))
        len=$((len + l + 1))
    done <<< "$cuerpo"

    if [ -n "$acumulado" ]; then
        TG_TROZOS+=("$acumulado")
    fi

    # El aviso de recorte va al final del ultimo trozo. Sin etiquetas: una
    # entity mas por decir "he recortado" seria un mal negocio, y aqui vamos
    # justos por definicion.
    if [ "$TG_OMITIDAS" -gt 0 ] && [ "${#TG_TROZOS[@]}" -gt 0 ]; then
        if [ -n "$TG_NOTA_RECORTE" ]; then
            nota="${TG_NOTA_RECORTE//%d/$TG_OMITIDAS}"
        else
            nota="… y ${TG_OMITIDAS} lineas mas, no mostradas."
        fi
        TG_TROZOS[$(( ${#TG_TROZOS[@]} - 1 ))]+="${TG_NL}${nota}"
    fi
    return 0
}

# tg_enviar_troceado FUNCION_ENVIO CABECERA CUERPO
#
# FUNCION_ENVIO recibe cada mensaje ya montado y se encarga del curl. Va como
# parametro y no fija aqui porque los bots son DOS y distintos: el del
# anfitrion (telegram.env del monitor) y el de Cowrie/Dionaea (telegram.cfg).
# Cada script sabe cual es el suyo; esta libreria no tiene por que saberlo.
tg_enviar_troceado() {
    local envio="${1:?falta la funcion de envio}"
    local cabecera="${2:-}" cuerpo="${3:-}"

    tg_trocear "$cabecera" "$cuerpo"

    local total=${#TG_TROZOS[@]} i=0 marca trozo

    # Un aviso SIN cuerpo es un aviso valido, y hasta ahora se perdia entero.
    # tg_trocear no produce ningun trozo cuando el cuerpo esta vacio, asi que
    # el bucle de abajo no daba ni una vuelta y no se enviaba nada ---sin
    # error, sin rastro y sin que nadie se enterara---. Es justo el fallo que
    # este proyecto ya sufrio con el resumen diario que dejo de llegar.
    if [ "$total" -eq 0 ]; then
        "$envio" "$cabecera"
        return 0
    fi

    for trozo in "${TG_TROZOS[@]}"; do
        i=$((i + 1))

        # El "(1/3)" va en texto plano y no en <i>: seria una entity mas, y es
        # exactamente la clase de adorno por el que no merece la pena
        # arriesgar el ultimo enlace del mensaje.
        marca=""
        if [ "$total" -gt 1 ]; then
            marca="  ($i/$total)"
        fi

        "$envio" "${cabecera}${marca}${TG_NL}${trozo}"

        # Telegram admite del orden de un mensaje por segundo al mismo chat.
        # Pasarse devuelve 429, y un trozo rechazado no se reintenta nunca:
        # el estado ya habra avanzado cuando nos enteremos.
        if [ "$i" -lt "$total" ]; then
            sleep 1
        fi
    done
    return 0
}
