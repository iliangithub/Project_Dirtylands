#!/usr/bin/env bash
# dionaea-watch.sh
# Reporta a Telegram la actividad NUEVA de Dionaea (conexiones de ataque y
# descargas de malware capturadas) desde la ultima ejecucion. Pensado para
# cron cada pocos minutos. Paralelo al plugin output_telegram de Cowrie.
#
#   --test [N]   Reporta los ultimos eventos SIN actualizar el estado. N son
#                las conexiones que mira hacia atras (40 por defecto); subirlo
#                sirve para ensayar una rafaga grande y ver como se trocea.
set -euo pipefail

# Enviamos por la MISMA via que Cowrie: su bot_token + chat_id, que NO estan en
# cowrie.cfg sino en el telegram.cfg externo. Ahi es donde los busca tambien el
# plugin (su constante TELEGRAM_CFG_PATH), y el unico sitio donde existen: en
# cowrie.cfg la seccion [output_telegram] solo lleva "enabled".
#
# No es el telegram.env del monitor del anfitrion, que es otro bot y otra
# conversacion.
TELEGRAM_CFG="${DIONAEA_TELEGRAM_CFG:-/opt/dirtyland/Telegram Reports/telegram.cfg}"
DB="${DIONAEA_DB:-/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite}"

send_telegram() {
    local msg="$1"
    # En seco: se escribe lo que se habria mandado. Existe para poder
    # comprobar el CONTENIDO de los avisos en una prueba, que es lo unico que
    # no se puede mirar de otra forma sin mandarselos a alguien.
    if [ "${DIONAEA_DRY_RUN:-0}" = "1" ]; then
        printf '===MENSAJE===\n%s\n' "$msg"
        return 0
    fi
    local tok cid
    tok=$(sed -n 's/^bot_token[[:space:]]*=[[:space:]]*//p' "$TELEGRAM_CFG" | head -1)
    cid=$(sed -n 's/^chat_id[[:space:]]*=[[:space:]]*//p' "$TELEGRAM_CFG" | head -1)
    if [ -z "$tok" ] || [ -z "$cid" ]; then
        echo "dionaea-watch: no pude leer bot_token/chat_id de $TELEGRAM_CFG" >&2
        return 1
    fi
    # La respuesta NO se tira a /dev/null. "curl -s" devuelve 0 aunque Telegram
    # conteste 400 (HTML mal formado) o 429 (demasiados mensajes), asi que
    # descartarla convierte una alerta perdida en un exito aparente: el script
    # termina bien, el estado avanza, y ese evento ya no se reintenta nunca.
    local respuesta
    # Por lo mismo que en send-alert.sh: los argumentos de un programa los
    # registra auditd, y el token aparecio asi en el log el 2026-08-29. Va por
    # la entrada estandar con --config.
    respuesta=$(printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' \
        "$tok" | curl -s --config - -X POST \
        --data-urlencode "chat_id=${cid}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "disable_web_page_preview=true" \
        --data-urlencode "text=${msg}") || {
        echo "dionaea-watch: curl fallo al hablar con Telegram" >&2
        return 0
    }
    # A stderr, que es lo que recoge el journal de cron. Y SIN devolver error:
    # con "set -e" un return distinto de 0 abortaria el recorrido entero y se
    # perderian tambien los eventos que aun no se han mirado.
    case "$respuesta" in
        *'"ok":true'*) : ;;
        *) echo "dionaea-watch: Telegram rechazo el mensaje: ${respuesta:0:300}" >&2 ;;
    esac
    return 0
}
STATE_DIR="${DIONAEA_STATE_DIR:-/var/lib/dirtyland-reporter}"
STATE="$STATE_DIR/dionaea-telegram.state"
# La cabecera de los avisos es solo "[Dionaea]" con una linea en blanco
# debajo. El nombre del sensor no aporta nada a quien recibe el aviso.

# IPs que NUNCA se avisan: las nuestras. Ademas se filtran todas las IPs
# no globales (privadas/CGNAT/loopback) mas abajo.
# Quien somos nosotros: definicion unica, compartida por los tres
# vigilantes. Ver el comentario de cabecera de ese fichero.
#
# Se carga con red: si faltara, no se marca nada y ya, pero el aviso
# sale igual. Quedarse sin vigilancia por una anotacion cosmetica
# seria cambiar un problema pequeno por uno grande.
LIB_IPS=/opt/dirtyland/monitor/lib-ips.sh
if [ -r "$LIB_IPS" ]; then
    # shellcheck source=/dev/null
    . "$LIB_IPS"
else
    echo "aviso: falta $LIB_IPS; no se marcaran las IP propias" >&2
    es_propia() { return 1; }
    marca_propia() { return 0; }
fi

LIB_PAISES=/opt/dirtyland/monitor/lib-paises.sh
if [ -r "$LIB_PAISES" ]; then
    # shellcheck source=/dev/null
    . "$LIB_PAISES"
else
    pais_de() { return 0; }
fi

# Los limites de Telegram, en un solo sitio. Ver la cabecera de ese fichero:
# el que importa no es el de 4096 caracteres sino el de 100 entities, que no
# da error y se limita a dejar sin enlace el final del mensaje.
#
# Con red, igual que lib-ips.sh: si faltara, se manda de una pieza como antes.
# Un aviso con el final estropeado sigue siendo mejor que ningun aviso.
LIB_TELEGRAM=/opt/dirtyland/monitor/lib-telegram.sh
if [ -r "$LIB_TELEGRAM" ]; then
    # shellcheck source=/dev/null
    . "$LIB_TELEGRAM"
else
    echo "aviso: falta $LIB_TELEGRAM; se enviara sin trocear" >&2
    tg_enviar_troceado() { "$1" "${2}
${3}"; }
    # Estas dos NO son un adorno del que se pueda prescindir: sin escapar, un
    # "<" en una URL de descarga tumba el aviso entero. Si la libreria falta,
    # se define aqui lo minimo indispensable.
    # Los "\&" son obligatorios: desde bash 5.2 un "&" suelto en el reemplazo
    # significa "lo que se acaba de encontrar", y el escapado no haria nada.
    tg_escapar() {
        local t="${1:-}"; t="${t//&/\&amp;}"; t="${t//</\&lt;}"; t="${t//>/\&gt;}"
        printf '%s' "$t"
    }
    tg_recortar() {
        local t="${1:-}" max="${2:-200}"
        if [ "${#t}" -gt "$max" ]; then printf '%s…' "${t:0:$max}"
        else printf '%s' "$t"; fi
    }
fi

# Si una rafaga es tan grande que hay que recortar, que el aviso diga donde
# esta lo que falta en vez de dejarlo en "y N mas". Recortado en Telegram no
# es lo mismo que perdido: las conexiones siguen enteras en la base de Dionaea
# y las IPs siguen su camino hacia AbuseIPDB por el reporter.
TG_NOTA_RECORTE="… y %d lineas mas. Estan todas en la base de Dionaea; el aviso se corta aqui para no perder mensajes por exceso de envios."

TEST=0
# Cuantas conexiones hacia atras mira el modo prueba. Se puede pedir mas para
# ENSAYAR UNA RAFAGA: "--test 400" reconstruye un aviso del tamano de un
# barrido a un /24 y deja ver como se trocea de verdad, sin esperar a que
# vuelva a pasar. Con el valor por defecto salen cuatro lineas y eso no prueba
# nada del troceo --- que es exactamente lo que nos paso el 2026-08-20.
TEST_N=40
if [ "${1:-}" = "--test" ]; then
    TEST=1
    case "${2:-}" in
        ''|*[!0-9]*) : ;;
        *) TEST_N="$2" ;;
    esac
fi

[ -f "$DB" ] || { echo "dionaea-watch: no existe $DB" >&2; exit 0; }
command -v sqlite3 >/dev/null || { echo "dionaea-watch: falta sqlite3" >&2; exit 1; }
mkdir -p "$STATE_DIR"

# --- Estado: ultimo id de conexion y de descarga reportados ---
last_conn=0; last_dl=0
MUDO_AVISADO=0
RESUMEN_ULTIMO=0
if [ -f "$STATE" ]; then
    # shellcheck source=/dev/null
    source "$STATE"
    last_conn=${LAST_CONN:-0}; last_dl=${LAST_DL:-0}
    MUDO_AVISADO=${MUDO_AVISADO:-0}
    RESUMEN_ULTIMO=${RESUMEN_ULTIMO:-0}
fi

# --- DIONAEA VIVO PERO MUDO -------------------------------------------------
#
# El 2026-08-23 a las 17:11 Dionaea se quedo en bucle y no volvio a anotar una
# sola conexion hasta el 28. Cinco dias. Y nada lo dijo, porque todo lo que se
# suele mirar decia que estaba bien: "docker ps" daba Up 6 days, el proceso
# existia ---vivo, quemando un nucleo, con cinco dias de CPU acumulados--- y
# el DNAT contaba los paquetes que entraban. Este mismo script se ejecutaba
# puntual cada cinco minutos y escribia "sin actividad nueva", que es
# exactamente lo que escribe un dia tranquilo.
#
# Ni "esta el contenedor levantado" ni "existe el proceso" valen: las dos
# cosas eran ciertas mientras el senuelo estaba muerto para lo que sirve. Lo
# unico que distingue "no le ataca nadie" de "esta bloqueado" es CUANDO anoto
# la ultima conexion, y eso ya lo tenemos aqui delante: este script abre esa
# base cada cinco minutos.
#
# El umbral por defecto es mas corto que el del resumen diario (6 h) porque
# aqui se puede: pasamos cada cinco minutos, asi que se avisa el mismo dia y
# no a la manana siguiente. Dos horas sin una sola conexion en tres puertos
# que reciben barridos constantes ya es anormal.
DIONAEA_MUDO_HORAS="${DIONAEA_MUDO_HORAS:-2}"
# Y se REPITE de tarde en tarde, no cada cinco minutos: un aviso que sale 288
# veces al dia se silencia, y silenciado no avisa de nada.
DIONAEA_MUDO_REPETIR="${DIONAEA_MUDO_REPETIR:-6}"

vigilar_silencio() {
    local ultima ahora horas
    ultima=$(sqlite3 "$DB" \
        "SELECT COALESCE(MAX(connection_timestamp),0) FROM connections;" 2>/dev/null) \
        || return 0
    case "${ultima:-0}" in ''|*[!0-9]*) return 0 ;; esac
    # Base recien creada: no hay con que comparar. El dia de la instalacion
    # diria "hace 500000 horas" y se aprenderia a ignorar el aviso.
    [ "$ultima" -eq 0 ] && return 0

    ahora=$(date -u +%s)
    horas=$(( (ahora - ultima) / 3600 ))

    if [ "$horas" -lt "$DIONAEA_MUDO_HORAS" ]; then
        # SE AVISA TAMBIEN DE QUE HA VUELTO. Sin esto, el que recibio la
        # alarma no sabe si sigue caido o si ya se arreglo, y acaba teniendo
        # que ir a mirarlo a mano ---que es lo que veniamos a evitar---.
        if [ "$MUDO_AVISADO" -ne 0 ]; then
            send_telegram "<strong>[Dionaea]</strong>

✅ Vuelve a anotar conexiones. Estuvo ${DIONAEA_MUDO_HORAS} h o mas sin registrar nada."
            MUDO_AVISADO=0
        fi
        return 0
    fi

    if [ "$MUDO_AVISADO" -ne 0 ] \
       && [ $(( (ahora - MUDO_AVISADO) / 3600 )) -lt "$DIONAEA_MUDO_REPETIR" ]; then
        return 0
    fi

    # Las dos ordenes van ESCRITAS en el aviso. El sintoma no se parece a la
    # causa: lo primero que hace uno es mirar "docker ps", ve "Up", y se va
    # tranquilo. Lo que hay que mirar es el tiempo de CPU del proceso.
    send_telegram "<strong>[Dionaea]</strong>

⚠️ <b>SIN ANOTAR NADA DESDE HACE ${horas} h</b>
Ultima conexion: <code>$(date -u -d "@$ultima" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')</code> UTC

Puede estar vivo y en bucle: el contenedor sigue <i>Up</i> y el proceso existe. Compruebalo con <code>docker top dirtyland_dionaea</code> ---si el TIME son dias, es eso--- y levantalo con <code>docker restart dirtyland_dionaea</code>."
    MUDO_AVISADO=$ahora
}

max_conn=$(sqlite3 "$DB" "SELECT COALESCE(MAX(connection),0) FROM connections;")
max_dl=$(sqlite3 "$DB" "SELECT COALESCE(MAX(download),0) FROM downloads;")

# Primera ejecucion sin --test: fija la linea base y no reporta el historico.
if [ ! -f "$STATE" ] && [ "$TEST" -eq 0 ]; then
    printf 'LAST_CONN=%s\nLAST_DL=%s\n' "$max_conn" "$max_dl" > "$STATE"
    echo "dionaea-watch: linea base fijada (conn=$max_conn, dl=$max_dl), sin reporte."
    exit 0
fi

# En modo test, mira hacia atras $TEST_N conexiones y las ultimas descargas.
if [ "$TEST" -eq 1 ]; then
    last_conn=$(sqlite3 "$DB" "SELECT COALESCE(MAX(connection),0)-${TEST_N} FROM connections;")
    last_dl=$(sqlite3 "$DB" "SELECT COALESCE(MAX(download),0)-3 FROM downloads;")
    echo "dionaea-watch: modo prueba, mirando ${TEST_N} conexiones hacia atras." >&2
fi

is_global() {
    # Rechaza IPv4 no globales; deja pasar el resto (incl. IPv6 publicas).
    case "$1" in
        10.*|127.*|169.254.*|192.168.*|0.*|255.*) return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 1 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
        *) return 0 ;;
    esac
}
blocked() { es_propia "${1:-}"; }

svc_label() {
    case "$1" in
        smbd) echo "SMB" ;; mssqld) echo "MSSQL" ;; epmapper) echo "MSRPC" ;;
        mysqld) echo "MySQL" ;; SipSession|sip) echo "SIP" ;; httpd) echo "HTTP" ;;
        *) echo "$1" ;;
    esac
}

body=""

# --- MEMORIA POR IP: dejar de repetir el mismo aviso ------------------------
#
# Este script reporta lo NUEVO desde la ultima vez, y eso, con un atacante
# insistente, no es un aviso: es un grifo abierto. Un mismo escaner de SMB
# dejaba una linea en CADA pasada de cinco minutos ---la misma IP, el mismo
# puerto, solo cambiaba el numero--- o sea 288 avisos al dia por una sola IP.
# Y un aviso que llega 288 veces se aprende a ignorar, que es la unica forma
# de que la vigilancia falle del todo.
#
# La regla es la MISMA que ya usa el plugin de Cowrie, y a proposito: cada
# combinacion de IP + servicio + puerto avisa sus primeras AVISOS_POR_IP
# veces y luego se calla. Callarse no es olvidarse: lo silenciado se cuenta y
# sale resumido al final del mensaje, y de tarde en tarde ---REAVISO_HORAS---
# vuelve a avisar una vez con el total acumulado, para que una campana que
# dura dias no desaparezca del radar.
#
# Lo que NO se calla nunca son las DESCARGAS. Una muestra de malware es el
# evento que justifica el senuelo entero y no hay ninguna cantidad de
# repeticion que la haga menos interesante.
AVISOS_POR_IP="${DIONAEA_AVISOS_POR_IP:-2}"
REAVISO_HORAS="${DIONAEA_REAVISO_HORAS:-6}"
# Lo que se recuerda de una IP que deja de aparecer. Con esto el fichero se
# queda en unos pocos miles de lineas aunque el senuelo lleve meses.
MEMORIA_DIAS="${DIONAEA_MEMORIA_DIAS:-30}"
# Cada cuanto se manda el resumen de lo callado CUANDO NO HAY NADA MAS que
# contar. Si en la misma pasada hay algo que avisar, el resumen viaja con el
# y no cuesta un mensaje: lo que no puede ser es mandar uno cada cinco
# minutos para decir que no se manda nada, que es cambiar un spam por otro.
RESUMEN_HORAS="${DIONAEA_RESUMEN_HORAS:-1}"
MEMORIA="$STATE_DIR/dionaea-repetidas.state"

declare -A MEM_VECES MEM_ULTIMO MEM_ACUM
memoria_cargar() {
    [ -f "$MEMORIA" ] || return 0
    local clave veces ultimo acum
    # LA CLAVE VA LA ULTIMA, y no es un capricho: lleva "|" dentro
    # ---ip|servicio|puerto--- que es el mismo separador del fichero. Con la
    # clave delante, el "read" la partia en tres y los numeros se leian
    # corridos: la memoria cargaba siempre "0 veces" y no callaba nunca a
    # nadie. Es exactamente la razon por la que la URL de una descarga
    # tambien va la ultima en el SELECT de mas abajo: la ultima variable de
    # un "read" se queda con todo el resto de la linea, separadores incluidos.
    while IFS='|' read -r veces ultimo acum clave; do
        [ -z "${clave:-}" ] && continue
        MEM_VECES["$clave"]="${veces:-0}"
        MEM_ULTIMO["$clave"]="${ultimo:-0}"
        MEM_ACUM["$clave"]="${acum:-0}"
    done < "$MEMORIA"
    return 0
}

memoria_guardar() {
    local ahora clave viejo
    ahora=$(date -u +%s)
    viejo=$(( ahora - MEMORIA_DIAS * 86400 ))
    : > "${MEMORIA}.tmp"
    for clave in "${!MEM_VECES[@]}"; do
        [ "${MEM_ULTIMO[$clave]:-0}" -lt "$viejo" ] && continue
        printf '%s|%s|%s|%s\n' "${MEM_VECES[$clave]:-0}" \
            "${MEM_ULTIMO[$clave]:-0}" "${MEM_ACUM[$clave]:-0}" "$clave" \
            >> "${MEMORIA}.tmp"
    done
    # Se cambia de golpe: si el script muere a mitad de escritura, el fichero
    # de antes sigue entero y se pierde una pasada, no la memoria entera.
    mv -f "${MEMORIA}.tmp" "$MEMORIA"
    return 0
}

memoria_cargar
calladas_ips=0
calladas_conn=0

# --- Nuevas conexiones de ataque (accept), agrupadas por IP + servicio ---
rows=$(sqlite3 -separator '|' "$DB" "
    SELECT remote_host, connection_protocol, local_port, COUNT(*),
           datetime(MAX(connection_timestamp),'unixepoch')
    FROM connections
    WHERE connection > $last_conn AND connection_type='accept'
    GROUP BY remote_host, connection_protocol, local_port
    ORDER BY remote_host;" 2>/dev/null || true)

# Dos entities por linea y ni una mas, que es lo que se puede permitir un
# mensaje con decenas de IPs. Antes eran tres --- <code> en la IP, <code> en
# la hora y un enlace suelto "<ip> en AbuseIPDB" en una lista aparte al final
# --- y con 33 IPs eso son 99 entities de las 100 que caben. El 2026-08-20
# llegaron 33 IPs de un barrido a /24 y el mensaje se paso a 106.
#
#   - El <code> de la hora se ha ido: era decoracion, y costaba una entity por
#     linea. La informacion se lee igual de bien sin fuente monoespaciada.
#   - El <code> de la IP SE QUEDA, y este no es negociable: sin el, Telegram
#     detecta la IP suelta y le pone enlace automatico a http://esa-ip. Un
#     aviso de honeypot no puede ofrecer un enlace pulsable a la maquina del
#     atacante.
#   - El enlace a AbuseIPDB pasa a la propia linea, en vez de repetir las
#     mismas IPs otra vez en una lista al final. Se ahorra una entity, se
#     ahorran tantas lineas como IPs, y consultar una IP ya no obliga a
#     buscarla dos veces en el mismo mensaje.
conn_block=""
while IFS='|' read -r ip proto port cnt last_ts; do
    [ -z "${ip:-}" ] && continue
    blocked "$ip" && continue
    is_global "$ip" || continue
    label=$(svc_label "$proto")

    # ¿Toca avisar de esta, o ya se ha avisado bastante?
    clave="${ip}|${label}|${port}"
    ahora_ep=$(date -u +%s)
    veces=${MEM_VECES[$clave]:-0}
    ultimo=${MEM_ULTIMO[$clave]:-0}
    acum=${MEM_ACUM[$clave]:-0}
    extra=""
    if [ "$veces" -lt "$AVISOS_POR_IP" ]; then
        :                                   # dentro del cupo: se avisa
    elif [ $(( (ahora_ep - ultimo) / 3600 )) -ge "$REAVISO_HORAS" ]; then
        # Reaviso: se dice lo que se ha callado desde la vez anterior, o el
        # resumen diria que "vuelve" algo que no se ha ido nunca.
        extra="  <i>sigue ahi: ${acum} conexiones calladas desde el ultimo aviso</i>"
        acum=0
    else
        calladas_ips=$(( calladas_ips + 1 ))
        calladas_conn=$(( calladas_conn + cnt ))
        MEM_ACUM["$clave"]=$(( acum + cnt ))
        continue
    fi
    MEM_VECES["$clave"]=$(( veces + 1 ))
    MEM_ULTIMO["$clave"]=$ahora_ep
    MEM_ACUM["$clave"]=$acum

    conn_block+="
Source: <code>${ip}</code>$(pais_de "${ip}")  ${label} (${port}) ×${cnt}  ${last_ts} UTC  <a href=\"https://www.abuseipdb.com/check/${ip}\">AbuseIPDB</a>${extra}"
done <<< "$rows"

if [ -n "$conn_block" ]; then
    body+="
<u>Nuevas conexiones de ataque</u>${conn_block}"
fi

# Lo callado se DICE. Un contador que no sale a ninguna parte es lo mismo que
# no tenerlo: nadie sabria si el senuelo esta tranquilo o es que se ha vuelto
# mudo, que es justo la duda que este script existe para quitar.
resumen="<i>Calladas ${calladas_ips} repetidas (${calladas_conn} conexiones): ya avisadas ${AVISOS_POR_IP} veces. Vuelven a avisar a las ${REAVISO_HORAS} h.</i>"
if [ "$calladas_ips" -gt 0 ]; then
    if [ -n "$body" ]; then
        # Hay algo que contar de todas formas: el resumen se pega y sale
        # gratis.
        body+="
${resumen}"
        RESUMEN_ULTIMO=$(date -u +%s)
    elif [ $(( ($(date -u +%s) - ${RESUMEN_ULTIMO:-0}) / 3600 )) \
            -ge "$RESUMEN_HORAS" ]; then
        body="${resumen}"
        RESUMEN_ULTIMO=$(date -u +%s)
    fi
fi

# --- Nuevas descargas de malware ---
#
# AGRUPADO, igual que las conexiones de arriba. Sin agrupar, un bot que sube
# el mismo fichero varias veces llenaba el aviso de repeticiones: el
# 2026-08-20 a las 08:00 salieron seis bloques para dos hashes distintos, con
# su "Ver hash en VirusTotal" repetido cuatro veces para el mismo fichero. Eso
# no es informacion, es ruido --- y ademas gasta entities, que es el recurso
# escaso de estos mensajes.
#
# Se cuentan CONEXIONES DISTINTAS y no filas. Dos motivos:
#   - Es lo que de verdad se quiere saber: cuantas veces han intentado
#     colarnos ese fichero, no cuantos apuntes hizo Dionaea.
#   - Y protege de una duplicacion conocida: segun la version, Dionaea puede
#     apuntar la misma descarga dos veces (un incidente ".hash" y otro
#     ".unique"). Contando filas dirian "x4" dos subidas reales; contando
#     conexiones sale el numero correcto pase lo que pase.
#
# La URL va la ULTIMA del SELECT a proposito. Con IFS='|', la ultima variable
# del "read" se queda con todo el resto de la linea, separadores incluidos, y
# eso importa porque la URL la escribe el atacante y puede llevar un "|" que
# desplazaria los demas campos. Estando en medio, como estaba, una URL asi
# hacia que la IP de origen saliera mal. Los saltos de linea se aplanan en el
# propio SQL por la misma razon: partirian la fila en dos.
dls=$(sqlite3 -separator '|' "$DB" "
    SELECT d.download_md5_hash,
           COALESCE(c.remote_host,''),
           COUNT(DISTINCT d.connection),
           replace(replace(COALESCE(d.download_url,''), char(10), ' '),
                   char(13), ' ')
    FROM downloads d LEFT JOIN connections c ON c.connection=d.connection
    WHERE d.download > $last_dl
    GROUP BY d.download_md5_hash, COALESCE(c.remote_host,''),
             COALESCE(d.download_url,'')
    ORDER BY MAX(d.download);" 2>/dev/null || true)

# --- MD5 -> SHA-256, para poder enlazar a MalwareBazaar ---------------------
#
# Dionaea solo apunta el MD5 en su base. VirusTotal acepta cualquier hash,
# pero la ficha de MalwareBazaar va por SHA-256, asi que con el MD5 a secas no
# hay enlace posible.
#
# El SHA-256 sale del propio fichero. El binario esta en el directorio de
# capturas y --- en esta version de Dionaea --- se llama por su SHA-256, pero
# eso NO se da por hecho: se calcula. Dar por buena la convencion de nombres
# es exactamente el error que tuvo el collector durante meses.
#
# El mapa se construye una sola vez y SOLO si hay descargas nuevas, que es
# como mucho unas pocas veces al dia. Son unas decenas de ficheros pequenos:
# el md5sum del directorio entero tarda milisegundos.
BINARIES="${BINARIES:-/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/binaries}"
declare -A SHA_DE_MD5
mapa_hecho=0

# Se recorren los ficheros directamente y de cada uno se sacan los dos hashes.
# Nada de parsear la salida de "md5sum" sobre una lista de rutas: en modo
# binario antepone un "*" al nombre, y ese asterisco se colaba en la ruta que
# luego se le pasaba a sha256sum, que no encontraba el fichero. El mapa salia
# vacio y todo seguia funcionando "bien", solo que sin enlace a MalwareBazaar
# nunca. De la salida de cada hash se coge el PRIMER campo, que siempre es el
# hash, y la ruta no se lee de ahi porque ya la tenemos.
construir_mapa() {
    [ "$mapa_hecho" -eq 1 ] && return 0
    mapa_hecho=1
    [ -d "$BINARIES" ] || { echo "dionaea-watch: no existe $BINARIES" >&2; return 0; }
    command -v md5sum >/dev/null || return 0
    command -v sha256sum >/dev/null || return 0
    local ruta m s
    for ruta in "$BINARIES"/*; do
        [ -f "$ruta" ] && [ -s "$ruta" ] || continue
        m=$(md5sum -- "$ruta" 2>/dev/null | cut -d' ' -f1)
        s=$(sha256sum -- "$ruta" 2>/dev/null | cut -d' ' -f1)
        [ -n "$m" ] && [ -n "$s" ] && SHA_DE_MD5["$m"]="$s"
    done
    return 0
}

dl_block=""
while IFS='|' read -r md5 rip veces url; do
    [ -z "${md5:-}" ] && continue

    construir_mapa
    sha="${SHA_DE_MD5[${md5,,}]:-}"

    # Se ensena el SHA-256 cuando se conoce: es el hash con el que trabajan
    # las dos plataformas, y el que sirve para pegar en cualquier sitio.
    if [ -n "$sha" ]; then
        dl_block+="
SHA256: <code>${sha}</code>"
    else
        dl_block+="
MD5: <code>$(tg_escapar "$md5")</code>"
    fi
    [ "${veces:-1}" -gt 1 ] && dl_block+="  en ${veces} conexiones"
    # Con su bandera, igual que la de arriba. Es la MISMA clase de dato ---la
    # IP del atacante--- y que saliera con pais en un bloque y sin el en el
    # otro no es una decision, es un olvido: se quedo fuera al anadir las
    # banderas porque aqui la variable se llama rip y no ip.
    [ -n "${rip:-}" ] && dl_block+="  desde <code>$(tg_escapar "$rip")</code>$(pais_de "$rip")"
    # Escapada y recortada: la escribe el atacante. Un "<" suelto convertiria
    # el mensaje en un 400 y perderiamos el aviso entero.
    [ -n "${url:-}" ] && dl_block+="
Origin: <code>$(tg_escapar "$(tg_recortar "$url" 180)")</code>"

    # Los hashes van dentro de un href, asi que ahi no basta con escapar: si
    # no son hexadecimales no son hashes y no se pone enlace. Meter texto
    # ajeno en un atributo es peor que meterlo en el cuerpo.
    #
    # VirusTotal dice QUE ES; MalwareBazaar dice SI YA ESTA PUBLICADO, que es
    # lo que uno quiere saber antes de plantearse subir nada. Un 404 alli
    # tambien es una respuesta: no la tienen.
    case "$md5" in
        ""|*[!0-9a-fA-F]*) : ;;
        *) dl_block+="
<a href=\"https://www.virustotal.com/gui/file/${sha:-$md5}\">Ver en VirusTotal</a>"
           [ -n "$sha" ] && dl_block+="  |  <a href=\"https://bazaar.abuse.ch/sample/${sha}/\">Ver en MalwareBazaar</a>"
           ;;
    esac
done <<< "$dls"

[ -n "$dl_block" ] && body+="
<u>Malware capturado</u>${dl_block}"

# --- Enviar ---
#
# En trozos si hace falta. Un barrido a /24 son decenas de IPs distintas en un
# minuto, y eso no es un caso raro que quepa dar por imposible: es lo normal
# aqui. El troceo va en lib-telegram.sh y la cabecera se repite en cada trozo,
# para que el segundo mensaje se entienda solo sin haber leido el primero.
if [ -n "$body" ]; then
    ts=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    cabecera="<strong>[Dionaea]</strong>

Time: <code>${ts}</code>"
    # Sin el salto inicial que arrastra $body, o cada trozo empezaria con una
    # linea en blanco.
    tg_enviar_troceado send_telegram "$cabecera" "${body#$'\n'}"
    echo "dionaea-watch: reporte enviado."
else
    echo "dionaea-watch: sin actividad nueva."
fi

# --- Persistir estado (salvo en modo test) ---
#
# La vigilancia del silencio va AQUI, despues del reporte: si hubiera avisos
# que mandar, se mandan primero. Y solo fuera del modo prueba, porque escribe
# en el estado ---la marca de "ya avise"--- y --test no toca el estado.
if [ "$TEST" -eq 0 ]; then
    vigilar_silencio
    printf 'LAST_CONN=%s\nLAST_DL=%s\nMUDO_AVISADO=%s\nRESUMEN_ULTIMO=%s\n' \
        "$max_conn" "$max_dl" "$MUDO_AVISADO" "$RESUMEN_ULTIMO" > "$STATE"
    memoria_guardar
fi
