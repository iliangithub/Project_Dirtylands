#!/usr/bin/env bash
# daily-digest.sh
# Resumen diario del estado del host y del honeypot. Pensado para
# ejecutarse una vez al dia via cron/systemd timer.
set -euo pipefail

ALERT="${ALERT:-/opt/dirtyland/monitor/send-alert.sh}"
DIONAEA_DB="/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite"

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

ts=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
since="24 hours ago"

NL=$'\n'

# --- Logins SSH exitosos en las ultimas 24h ---------------------------
#
# Con la HORA, no solo el recuento: saber que hubo un acceso de root no sirve
# de gran cosa si no se puede cruzar con lo que estaba pasando en ese momento.
# De una sola vez se da la hora; de varias, la primera y la ultima.
#
# Se sacan usuario, IP y hora como CAMPOS separados por "|", en vez de
# componer la linea y volver a leerla despues. Asi se hacia antes y era un
# fallo silencioso: para recuperar la IP se cogia el ultimo trozo que
# pareciera hexadecimal, y en "- user desde 192.0.2.190 (45x)" eso es
# "45". Se preguntaba si 45 era una IP nuestra, siempre decia que no, y la
# marca de acceso propio no aparecia jamas.
#
# La IP se ancla con " port " detras y se coge la ULTIMA de la linea, igual
# que en ssh-watch.sh. Motivo: el nombre de usuario aparece en el log tal como
# lo escribio quien se conecta, espacios incluidos, asi que un "from 1.2.3.4
# port 22" metido ahi dentro se colaba como origen. Aqui el riesgo es menor
# que en los intentos fallidos --- un "Accepted publickey" exige una cuenta
# real --- pero las dos lineas se leen igual y no merece la pena que una este
# bien y la otra no.
registros=$(journalctl -u ssh --since "$since" -o short-iso --no-pager 2>/dev/null \
    | grep 'Accepted publickey' \
    | sed -E 's/^[0-9-]+T([0-9]{2}:[0-9]{2})[^ ]*[[:space:]].*Accepted publickey for ([^ ]+) .*from ([0-9a-fA-F:.]+) port .*/\2|\3|\1/' \
    | awk -F'|' 'NF==3 { k=$1"|"$2; n[k]++; if (!(k in primera)) primera[k]=$3; ultima[k]=$3 }
                 END { for (k in n) print k"|"primera[k]"|"ultima[k]"|"n[k] }' \
    | sort -t'|' -k5 -rn || true)

logins_fmt=""
while IFS='|' read -r usuario ip desde hasta veces; do
    [ -z "${usuario:-}" ] && continue
    if [ "${veces:-1}" -gt 1 ]; then cuando="${desde}–${hasta}"; else cuando="${desde}"; fi
    # La IP es el enlace a AbuseIPDB. Antes iba SUELTA en el texto, y una IP
    # suelta la enlaza Telegram por su cuenta hacia http://esa-ip: el resumen
    # ofrecia un enlace pulsable a la maquina desde la que se han conectado,
    # que es lo ultimo que quieres tocar sin querer desde el movil. Dentro de
    # un <a> nuestro eso ya no puede pasar, porque el destino lo ponemos
    # nosotros. La consulta la hace tu movil, no la VPS.
    logins_fmt+="  - ${usuario} desde <a href=\"https://www.abuseipdb.com/check/${ip}\">${ip}</a>$(marca_propia "$ip")$(pais_de "$ip")  ${veces}x  <code>${cuando}</code>${NL}"
done <<< "$registros"
[ -z "$logins_fmt" ] && logins_fmt="  (ninguno)"

# --- Intentos fallidos en las ultimas 24h ------------------------------
failed_count=$(journalctl -u ssh --since "$since" --no-pager 2>/dev/null \
    | grep -cE 'Failed password|Failed publickey|Invalid user' || true)
failed_count=${failed_count:-0}

# --- Uso de sudo en las ultimas 24h ------------------------------------
sudo_fmt=$(journalctl --since "$since" --no-pager 2>/dev/null \
    | grep -E 'sudo\[[0-9]+\]:' | grep 'COMMAND=' \
    | sed -E 's/.*sudo\[[0-9]+\]:[[:space:]]+([^ ]+)[[:space:]]+:.*/\1/' \
    | sort | uniq -c | sort -rn \
    | sed -E 's/^ *([0-9]+) (.*)/  - \2: \1 comandos/' || true)
[ -z "$sudo_fmt" ] && sudo_fmt="  (ninguno)"

# --- Estado de contenedores ---------------------------------------------
containers=$(docker ps -a --format '  - {{.Names}}: {{.Status}}' 2>/dev/null || echo "  (error consultando docker)")

# --- RAM ------------------------------------------------------------------
ram=$(free -h | awk '/^Mem:/ {print $3 " / " $2}')

# --- Disco ------------------------------------------------------------------
disk=$(df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 " usado)"}')

# --- Drops de egress del honeypot en las ultimas 24h -----------------------
egress_drops=$(journalctl --since "$since" --no-pager 2>/dev/null \
    | grep -c 'DL-EGRESS' || true)
egress_drops=${egress_drops:-0}

# --- Actividad Dionaea en las ultimas 24h -----------------------------------
#
# CUANTAS HORAS LLEVA SIN ANOTAR NADA. Esto no es un adorno del apartado: es
# la unica pregunta que detecta que el senuelo esta caido.
#
# El 2026-08-23 a las 17:11 Dionaea se quedo en bucle. Cinco dias. Y NADA lo
# dijo: el contenedor seguia "Up 6 days", el proceso seguia vivo ---quemando
# un nucleo al 77%, con cinco dias de CPU acumulados---, el DNAT seguia
# contando paquetes que entraban, y este mismo apartado escribia
# "(sin conexiones)", que se lee como "hoy no ha atacado nadie". Se descubrio
# porque al usuario le extrano el silencio, no porque nada avisara.
#
# Por eso no vale mirar si el contenedor esta levantado ni si el proceso
# existe: las dos cosas eran ciertas mientras estaba muerto para lo que sirve.
# Lo unico que distingue "no le ataca nadie" de "esta bloqueado" es CUANDO
# anoto la ultima conexion.
DIONAEA_MUDO_HORAS="${DIONAEA_MUDO_HORAS:-6}"

dionaea_resumen() {
    local since_epoch ultima horas
    [ -f "$DIONAEA_DB" ] || { printf '  (sin datos)'; return 0; }
    since_epoch=$(date -u -d "$since" +%s)
    local resumen
    resumen=$(sqlite3 "$DIONAEA_DB" "
        SELECT '  - ' || connection_protocol || ': ' || COUNT(*) || ' conexiones, ' ||
               COUNT(DISTINCT remote_host) || ' IPs distintas'
        FROM connections
        WHERE connection_timestamp >= $since_epoch
        GROUP BY connection_protocol;
    " 2>/dev/null) || { printf '  (error consultando dionaea.sqlite)'; return 0; }
    [ -z "$resumen" ] && resumen="  (sin conexiones)"

    ultima=$(sqlite3 "$DIONAEA_DB" \
        "SELECT COALESCE(MAX(connection_timestamp),0) FROM connections;" 2>/dev/null) || ultima=0
    case "${ultima:-0}" in ''|*[!0-9]*) ultima=0 ;; esac

    if [ "$ultima" -eq 0 ]; then
        # Base recien creada: no hay nada que comparar y decir "hace 500000
        # horas" seria una alarma falsa el dia de la instalacion.
        printf '%s\n  <i>(aun no hay ninguna conexion registrada)</i>' "$resumen"
        return 0
    fi

    horas=$(( ( $(date -u +%s) - ultima ) / 3600 ))
    if [ "$horas" -ge "$DIONAEA_MUDO_HORAS" ]; then
        # La orden va escrita porque a las 6 de la manana nadie se acuerda de
        # cual era, y porque el sintoma NO se parece a la causa: lo que hay
        # que mirar es el tiempo de CPU del proceso, no si esta vivo.
        printf '%s\n  \342\232\240\357\270\217 <b>SIN ANOTAR NADA DESDE HACE %d h</b> (ultima: %s UTC)\n  Puede estar vivo y en bucle. Miralo con <code>docker top dirtyland_dionaea</code> ---si el TIME son dias, es eso--- y levantalo con <code>docker restart dirtyland_dionaea</code>.' \
            "$resumen" "$horas" "$(date -u -d "@$ultima" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')"
        return 0
    fi
    printf '%s' "$resumen"
}
dionaea_summary=$(dionaea_resumen)

# --- Salud del reporter de telemetria --------------------------------------
#
# Antes esto leia /var/log/dirtyland-reporter/{cowrie,dionaea}.log, que son
# los logs del reporter VIEJO, el de dos scripts gemelos. El actual escribe
# en reporter.log, asi que la seccion decia "REVISAR (sin log)" todos los
# dias pasara lo que pasara --- y una alarma que siempre suena es una alarma
# que se deja de leer.
REPORTER_LOG="/var/log/dirtyland-reporter/reporter.log"
CFG_REPORTER="${CFG_REPORTER:-/opt/dirtyland/platform-reporter/config.ini}"
BASE_REPORTER="${BASE_REPORTER:-/var/lib/dirtyland-reporter/state.sqlite3}"

# punto_plataforma SECCION -> circulo verde si publica, rojo si no.
#
# El emoji lo escribe bash y no Python, para no depender del locale con el
# que arranque cron: alli Python escribiria en ASCII y el print reventaria
# con UnicodeEncodeError, dejando el parte sin colores y sin explicacion.
CRON_REPORTER="${CRON_REPORTER:-/etc/cron.d/dirtyland-reporter}"

# El cron manda sobre todo lo demas. Si no esta en --live, da igual lo que
# diga el config.ini: NADA se publica. Por eso esto se consulta antes que el
# "enabled" de cada plataforma, y no despues.
cron_en_live() {
    [ -f "$CRON_REPORTER" ] \
        && grep -qE '^[[:space:]]*\*/15 .*malware-watch\.sh --live' "$CRON_REPORTER"
}

# Si una plataforma esta encendida en el config, al margen del cron.
plataforma_encendida() {
    python3 -c '
import configparser, sys
cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
cp.read(sys.argv[1], encoding="utf-8")
sys.exit(0 if cp.getboolean(sys.argv[2], "enabled", fallback=False) else 1)
' "$CFG_REPORTER" "${1:-}" 2>/dev/null
}

punto_plataforma() {
    # Verde exige LAS DOS cosas: que el cron publique y que la plataforma este
    # encendida. Antes solo miraba el config, asi que con el cron en simulacion
    # el parte ensenaba puntos verdes y ceros al lado ---todo apagado, pintado
    # de encendido--- que es como se paso mas de un dia sin reportar nada.
    if cron_en_live && plataforma_encendida "${1:-}"; then
        printf '\360\237\237\242'      # verde
    else
        printf '\360\237\224\264'      # rojo
    fi
}

# Aviso si las tres de abuse.ch no dicen lo mismo. Comparten cuenta y clave,
# asi que media apagada no protege de nada; y con un punto por linea ese
# desacuerdo se ve pero no se explica solo.
# La linea de MOTIVO que va DEBAJO de las plataformas. Existe porque una
# columna de ceros no dice por que: puede ser que el cron no publique, que
# esten todas apagadas a mano, o que solo falten algunas. Son tres situaciones
# muy distintas y hasta ahora las tres se veian igual.
#
# Si todo esta encendido y publicando no se escribe nada: no hay motivo que
# explicar, y una linea que sale siempre se deja de leer.
motivo_apagado() {
    local total=0 encendidas=0 s
    for s in virustotal malwarebazaar threatfox urlhaus abuseipdb; do
        total=$((total + 1))
        plataforma_encendida "$s" && encendidas=$((encendidas + 1))
    done

    if ! cron_en_live; then
        printf '  [MOTIVO: <i>crontab esta usando modo simulacion</i>]%s' "$NL"
    elif [ "$encendidas" -eq 0 ]; then
        printf '  [MOTIVO: <i>El crontab esta bien, simplemente todo apagado</i>]%s' "$NL"
    elif [ "$encendidas" -lt "$total" ]; then
        printf '  [MOTIVO: <i>El crontab esta bien, simplemente ciertos servicios estan apagados</i>]%s' "$NL"
    fi
}

aviso_parcial() {
    local encendidas=0 s
    for s in malwarebazaar threatfox urlhaus; do
        [ "$(punto_plataforma "$s")" = "$(printf '\360\237\237\242')" ] \
            && encendidas=$((encendidas + 1))
    done
    if [ "$encendidas" -gt 0 ] && [ "$encendidas" -lt 3 ]; then
        printf '  \360\237\237\241 abuse.ch a medias (%d de 3): comparten cuenta, asi que eso no protege de nada.%s' \
            "$encendidas" "$NL"
    fi
}

# cuentas_24h --- lo publicado y lo descartado por plataforma, en 24 horas.
#
# Imprime una linea por plataforma, en ASCII puro y separada por tabuladores:
#
#     plataforma \t publicadas \t simuladas \t resto
#
# POR QUE LA BASE Y NO EL LOG. Esto leia el ultimo "--- resumen ---" del
# reporter.log, y ese resumen es de UNA PASADA: los contadores del reporter se
# ponen a cero al empezar cada una y el cron corre cada 15 minutos. O sea que
# la seccion, titulada "(24h)", ensenaba en realidad los ultimos 15 minutos.
# De ahi el sintoma: AbuseIPDB acumulando cientos de denuncias al dia y el
# parte diciendo "1 enviados", que es lo que se habia publicado desde y cuarto.
#
# La base es ademas la fuente de verdad, no un derivado: es la misma tabla que
# consulta el reporter para no repetir un envio, y la que lee
# que_pasa_con_las_plataformas.py. El log era una reconstruccion a partir de
# un texto pensado para leerlo una persona, y se rompia sola en cuanto ese
# texto cambiara de forma.
#
# Los grupos de motivos son los MISMOS que usa reporters/base.py, y a
# proposito: si alli aparece un motivo nuevo y aqui no, cae en "descartadas",
# que es exactamente lo que hace el reporter con lo que no conoce.
#
# El emoji NO se imprime aqui, sino en bash: bajo cron el locale puede ser
# ASCII y a Python le reventaria el print con UnicodeEncodeError, dejando el
# parte sin colores y sin explicacion.
cuentas_24h() {
    [ -r "$BASE_REPORTER" ] || return 1
    python3 - "$BASE_REPORTER" <<'FIN_PY' 2>/dev/null
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

PLATAFORMAS = ["virustotal", "malwarebazaar", "threatfox", "urlhaus", "abuseipdb"]

# La llave de cierre va SANGRADA, y no es un descuido: las pruebas sacan esta
# funcion del fichero de verdad recortando en la primera linea que sea "}" a
# solas, para no trabajar sobre una copia que se quede vieja. Una llave en la
# columna 0 aqui dentro cortaria la funcion por la mitad.
GRUPOS = {
    "rechazo-plataforma": "rechazadas por la plataforma",
    "resultado-incierto": "sin confirmar",
    "tope-por-pasada": "aplazadas",
    "cuota": "aplazadas",
    "tope-diario": "aplazadas",
    "tope-semanal": "aplazadas",
    "duplicado": "ya cubiertas",
    "enfriamiento": "ya cubiertas",
    "capa1-local": "ya cubiertas",
    "capa2-remota": "ya cubiertas",
    "capa3-similitud": "ya cubiertas",
    "capa4-campana": "ya cubiertas",
    "capa5-rafaga": "ya cubiertas",
    }
ORDEN = ("ya cubiertas", "descartadas", "aplazadas", "sin confirmar",
         "rechazadas por la plataforma")

# Sin microsegundos, porque asi es como el reporter escribe sus marcas: con
# ellos, la comparacion de textos deja fuera el ultimo segundo.
corte = (datetime.now(timezone.utc) - timedelta(hours=24)) \
    .replace(microsecond=0).isoformat()

try:
    db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True, timeout=10)
except sqlite3.Error:
    sys.exit(1)

for plataforma in PLATAFORMAS:
    try:
        # Un envio SIMULADO tambien deja fila, con estado "simulado". No se
        # ha publicado nada, asi que no puede contar como publicado: contarlo
        # es como se pinta de verde lo que esta muerto.
        publicadas = db.execute(
            "SELECT COUNT(*) FROM sent WHERE platform=? AND sent_at>=?"
            " AND status<>'simulado'", (plataforma, corte)).fetchone()[0]
        simuladas = db.execute(
            "SELECT COUNT(*) FROM sent WHERE platform=? AND sent_at>=?"
            " AND status='simulado'", (plataforma, corte)).fetchone()[0]
        filas = db.execute(
            "SELECT gate, COUNT(*) FROM rejections WHERE platform=? AND ts>=?"
            " GROUP BY gate", (plataforma, corte)).fetchall()
        # ThreatFox responde "ok" tanto si crea el indicador como si lo funde
        # con uno que ya tenia, asi que el reporter lo comprueba despues y
        # apunta cual de las dos fue. Sin este matiz, "1 publicadas" se lee
        # como "una contribucion mas" y no tiene por que serlo.
        detalles = db.execute(
            "SELECT detail FROM sent WHERE platform=? AND sent_at>=?"
            " AND status<>'simulado'", (plataforma, corte)).fetchall()
    except sqlite3.Error:
        sys.exit(1)

    matiz = ""
    if plataforma == "threatfox" and publicadas:
        nuevos = sum(1 for (d,) in detalles if "| nuevo" in (d or ""))
        refrescos = sum(1 for (d,) in detalles if "| refresco" in (d or ""))
        a_ciegas = publicadas - nuevos - refrescos
        trozos = []
        if nuevos:
            trozos.append("%d nuevo%s" % (nuevos, "s" if nuevos != 1 else ""))
        if refrescos:
            trozos.append("%d ya era%s de otro" % (refrescos, "n" if refrescos != 1 else ""))
        if a_ciegas:
            trozos.append("%d sin verificar" % a_ciegas)
        if trozos:
            matiz = " (%s)" % ", ".join(trozos)

    grupos = {}
    for gate, n in filas:
        etiqueta = GRUPOS.get(gate, "descartadas")
        grupos[etiqueta] = grupos.get(etiqueta, 0) + n

    partes = []
    for etiqueta in ORDEN:
        n = grupos.get(etiqueta, 0)
        if not n:
            continue
        # En mayusculas las dos que piden actuar hoy. "Sin confirmar" es una
        # publicacion que pudo entrar o no: si entro y la damos por perdida,
        # reenviarla la duplica, y duplicar es lo que penalizan.
        if etiqueta == "rechazadas por la plataforma":
            partes.append("%d RECHAZADAS POR LA PLATAFORMA" % n)
        elif etiqueta == "sin confirmar":
            partes.append("%d SIN CONFIRMAR" % n)
        else:
            partes.append("%d %s" % (n, etiqueta))

    # El matiz va ANTES de `resto` porque en bash la ultima variable de un
    # read se traga todo lo que sobra: si fuera el ultimo campo, acabaria
    # pegado a los motivos de descarte.
    #
    # Y va con un guion cuando esta vacio porque el tabulador es un separador
    # BLANCO para `read`: dos tabuladores seguidos cuentan como uno, el campo
    # vacio desaparece y todo lo de detras se corre un puesto. Aqui eso salia
    # como "0 publicadas0" ---el numero de simuladas pegado detras---, que es
    # de las averias que se ven raras pero no se entienden a la primera.
    print("\t".join([plataforma, str(publicadas), matiz or "-", str(simuladas),
                     ", ".join(partes)]))
FIN_PY
}

reporters_health() {
    local out="" alarm=0 last le mins crashes errores resumen f

    # LOS ROTADOS CUENTAN. El log usa RotatingFileHandler (10 MB, 5 backups) y
    # con el volumen del reporter se parte una o mas veces al dia. Mirar solo
    # reporter.log dejaba la ventana de "24h" ---errores, tracebacks, ultima
    # pasada--- coja justo despues de una rotacion, contando de menos.
    local -a LOGS=()
    for f in "$REPORTER_LOG" "$REPORTER_LOG".*; do
        [ -f "$f" ] && LOGS+=("$f")
    done
    if [ "${#LOGS[@]}" -eq 0 ]; then
        printf '  ⚠️ REVISAR%s  - sin log en <code>%s</code>%s' "$NL" "$REPORTER_LOG" "$NL"
        return 0
    fi

    # Cada cuanto corre: el cron son 15 minutos, asi que mas de una hora sin
    # escribir significa que algo lo tiene parado.
    # Va en la CABECERA, no en una linea suelta: es un dato de una palabra y
    # ocupaba un renglon entero para nada.
    # La ultima linea sale del fichero mas reciente que tenga contenido: justo
    # despues de rotar, reporter.log puede estar casi vacio y la de verdad
    # esta en reporter.log.1.
    local pasada
    last=""
    for f in "$REPORTER_LOG" "$REPORTER_LOG".1; do
        [ -s "$f" ] && { last=$(tail -1 "$f"); break; }
    done
    last=$(printf '%s' "$last" | awk '{print $1" "$2}' | sed -E 's/,[0-9]+//')
    le=$(date -d "$last" +%s 2>/dev/null || echo 0)
    if [ "$le" -eq 0 ]; then
        pasada="ultima pasada: ? (fecha ilegible)"; alarm=1
    else
        mins=$(( ( $(date +%s) - le ) / 60 ))
        if [ "$mins" -le 60 ]; then
            pasada="ultima pasada hace ${mins} min"
        else
            pasada="<b>PARADO</b>: ultima pasada hace ${mins} min"; alarm=1
        fi
    fi

    # EN QUE MODO ESTA. Es la comprobacion mas barata y la que mas falta hace:
    # el cron se instala en simulacion a proposito, y el "install" del apartado
    # 3.5.8 lo devuelve a simulacion cada vez que se ejecuta. Si alguien para el
    # reporter y lo repone, o lo reinstala, vuelve a simulacion SIN QUE NADA
    # FALLE: las pasadas siguen corriendo cada 15 minutos, el log sigue
    # creciendo y no se publica nada. Paso: 381 denuncias reales y luego 510
    # simuladas sin que nadie lo notara durante mas de un dia.
    #
    # Por eso se mira el fichero de cron y no el log: el log de una pasada
    # simulada se parece mucho al de una real.
    #
    # Se mira $CRON_REPORTER, el mismo que consulta cron_en_live() para pintar
    # los puntos de color. Aqui habia otra vez la ruta escrita a mano, asi que
    # la linea del modo y los puntos salian de dos sitios distintos: en cuanto
    # no coincidieran, el parte podia decir "publicando" con los puntos rojos
    # (o al reves), que es justo la clase de contradiccion que este apartado
    # existe para evitar. Ademas hacia imposible probar la seccion entera.
    # EL MODO SOLO SE ESCRIBE CUANDO ES MALO. Si el cron publica, los puntos
    # de las plataformas ya salen verdes ---y solo salen verdes si publica---,
    # asi que decirlo ademas es repetirse, y una linea que sale siempre se
    # deja de leer. Cuando NO publica hay que gritarlo: por eso existe esta
    # comprobacion, y por eso se paso mas de un dia reportando en simulacion
    # sin que nada lo dijera.
    if [ ! -f "$CRON_REPORTER" ]; then
        out+="  - <b>SIN CRON</b>: no hay ${CRON_REPORTER}${NL}"; alarm=1
    elif ! cron_en_live; then
        out+="  - <b>modo: SIMULACION</b>, no se publica nada${NL}"; alarm=1
    fi

    # Las lineas CRITICAL de ipguard son NORMALES --- es la barrera probandose
    # a si misma --- asi que no cuentan como fallo. Traceback y ERROR si.
    #
    # Y se cuentan SOLO las de las ultimas 24 h, que es lo que promete el
    # titulo de la seccion. Antes se recorria el log entero: dos errores de
    # un self-test de hace semanas seguian saliendo cada manana como si
    # fueran de anoche, y una alarma que no se apaga nunca se deja de leer.
    #
    # Nada de "|| echo 0": grep -c YA imprime 0 cuando no encuentra nada, y
    # ademas sale con codigo 1, asi que ese "|| echo 0" anadia un segundo
    # cero. La variable valia "0\n0" y el [ -gt ] se atragantaba con un
    # "integer expression expected".
    #
    # Sin -u: el log lo escribe logging.Formatter con %(asctime)s, que es hora
    # LOCAL de la maquina. Comparandolo con un corte en UTC, en un anfitrion
    # que no vaya en UTC la ventana se desplaza esas horas y los errores de
    # anoche se cuentan o se pierden segun el signo del desfase. Las otras dos
    # lecturas de este fichero ("ultima pasada") ya lo trataban como local.
    local corte
    corte=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null \
            || echo '1970-01-01 00:00:00')
    crashes=$(awk -v s="$corte" '{t=$1" "$2; sub(/,[0-9]+/,"",t);
                                  if (t>=s && /Traceback/) c++} END {print c+0}' \
              "${LOGS[@]}" 2>/dev/null)
    errores=$(awk -v s="$corte" '{t=$1" "$2; sub(/,[0-9]+/,"",t);
                                  if (t>=s && / ERROR /) c++} END {print c+0}' \
              "${LOGS[@]}" 2>/dev/null)
    if [ "${crashes:-0}" -gt 0 ]; then
        out+="  - <b>${crashes} tracebacks</b>${NL}"; alarm=1
    fi
    if [ "${errores:-0}" -gt 0 ]; then
        out+="  - errores registrados: ${errores}${NL}"
    fi

    # Una linea por plataforma con lo publicado en 24 h, y un punto de color
    # delante segun este encendida o apagada.
    #
    # El color va AQUI y no en el apartado de "me han baneado", que responde
    # otra pregunta distinta: si la cuenta sigue viva. Pegado a los numeros
    # tiene sentido inmediato --- una linea de ceros queda explicada por el
    # punto rojo de al lado, sin tener que ir a buscar por que.
    local crudo plataforma pub matiz sim resto texto vistos leyenda
    crudo=$(cuentas_24h || true)
    vistos=""
    if [ -n "$crudo" ]; then
        while IFS=$'\t' read -r plataforma pub matiz sim resto; do
            [ -z "$plataforma" ] && continue
            [ "$matiz" = "-" ] && matiz=""
            texto="${pub} publicadas${matiz}"
            # Una publicacion simulada no ha existido, y decirlo importa: es
            # asi como se paso mas de un dia con el cron en simulacion
            # creyendo que se estaba reportando.
            if [ "${sim:-0}" -gt 0 ]; then
                texto+=", ${sim} SIMULADAS (no se publicaron)"
            fi
            if [ -n "$resto" ]; then
                texto+=", ${resto}"
            fi
            # El nombre se rellena a 15 para que los numeros queden en columna.
            # "malwarebazaar" son 13 mas los dos puntos.
            out+=$(printf '  \342\200\242 %s %-15s %s' \
                   "$(punto_plataforma "$plataforma")" "${plataforma}:" "$texto")
            out+="$NL"
            vistos+="${resto}|"
        done <<< "$crudo"
        # LA LEYENDA SOLO NOMBRA LOS GRUPOS QUE HAN SALIDO HOY. Explicarlos
        # los cuatro siempre seria media pantalla fija que se deja de leer a
        # la semana; y sin explicar nada, "ya cubiertas" no dice si la
        # descartamos nosotros o si ya la tenia la plataforma --que es
        # justo la duda que hizo falta preguntar.
        leyenda=""
        case "$vistos" in *"ya cubiertas"*)
            leyenda+="ya cubiertas = ya la mandamos hace poco o la plataforma ya la tiene" ;;
        esac
        case "$vistos" in *aplazadas*)
            [ -n "$leyenda" ] && leyenda+=" \302\267 "
            leyenda+="aplazadas = no cabian en la cuota, van en la proxima" ;;
        esac
        case "$vistos" in *descartadas*)
            [ -n "$leyenda" ] && leyenda+=" \302\267 "
            leyenda+="descartadas = no cumplen los criterios para publicar" ;;
        esac
        case "$vistos" in *"SIN CONFIRMAR"*)
            [ -n "$leyenda" ] && leyenda+=" \302\267 "
            leyenda+="sin confirmar = se mando y no se sabe si llego; NO se reenvia sola" ;;
        esac
        case "$vistos" in *"RECHAZADAS POR LA PLATAFORMA"*)
            [ -n "$leyenda" ] && leyenda+=" \302\267 "
            leyenda+="rechazadas = se mando y la plataforma dijo que no" ;;
        esac
        if [ -n "$leyenda" ]; then
            out+=$(printf '  <i>%b</i>' "$leyenda")
            out+="$NL"
        fi
        out+="$(motivo_apagado)"
    else
        # Sin base no hay cuentas que dar, y callarselo dejaria el apartado
        # con solo las dos lineas de cabecera, que se lee como "no paso nada".
        out+="  - <b>sin poder leer</b> <code>${BASE_REPORTER}</code>${NL}"
        alarm=1
    fi

    out+="$(aviso_parcial)"

    if [ "$alarm" -eq 0 ]; then
        printf '  ✅ OK --- %s%s%s' "$pasada" "$NL" "$out"
    else
        printf '  ⚠️ REVISAR --- %s%s%s' "$pasada" "$NL" "$out"
    fi
}

# --- Me han baneado? --------------------------------------------------------
# En un script aparte porque hace peticiones autenticadas y tiene que poder
# probarse solo: /opt/dirtyland/monitor/estado-cuentas.py
estado_cuentas() {
    local salida
    salida=$(PYTHONIOENCODING=utf-8 python3 /opt/dirtyland/monitor/estado-cuentas.py 2>&1) || true
    [ -z "$salida" ] && salida="  (no se pudo comprobar)"
    printf '%s' "$salida"
}

cuentas_fmt="$(estado_cuentas)"

reporters_fmt="$(reporters_health)"

# --- Ordenes tecleadas en el anfitrion (24h) ---------------------------
#
# Lo normal es "(ninguna)". Esa linea es el dato: la maquina principal no se
# toca, asi que cualquier otra cosa aqui pide una explicacion. Las anota
# registro-comandos.sh desde /etc/profile.d/.
comandos_fmt=$(journalctl -t dirtyland-cmd --since "$since" -o cat --no-pager 2>/dev/null \
    | sed -nE 's/^user=([^ ]+) tty=([^ ]+) from=([^ ]+) .*/\1|\3/p' \
    | sort | uniq -c | sort -rn \
    | sed -E 's/^ *([0-9]+) (.*)\|(.*)/  \xe2\x80\xa2 \2 desde \3: \1 ordenes/' || true)
comandos_total=$(journalctl -t dirtyland-cmd --since "$since" -o cat --no-pager 2>/dev/null \
    | grep -c ' cmd=' || true)
comandos_total=${comandos_total:-0}
[ -z "$comandos_fmt" ] && comandos_fmt="  (ninguna)"

# QUE EL GANCHO SIGA CARGADO EN LOS DOS SITIOS. Aqui "(ninguna)" es la
# respuesta buena ---a esa maquina no se entra--- y por eso mismo es
# indistinguible de "el registro no esta puesto". Sin esta comprobacion,
# perder el gancho se leeria durante meses como tranquilidad.
#
# Hacen falta los dos: /etc/profile.d solo lo leen los shells de LOGIN, asi
# que sin la linea de /etc/bash.bashrc un shell de root abierto con "sudo su"
# no anota NADA de lo que se teclee dentro. Es el punto ciego que se
# encontro el 2026-08-29.
REGISTRO_PERFIL="${REGISTRO_PERFIL:-/etc/profile.d/dirtyland-registro.sh}"
REGISTRO_BASHRC="${REGISTRO_BASHRC:-/etc/bash.bashrc}"

registro_incompleto() {
    local falta=""
    [ -r "$REGISTRO_PERFIL" ] || falta="falta <code>${REGISTRO_PERFIL}</code>"
    if ! grep -q dirtyland-registro "$REGISTRO_BASHRC" 2>/dev/null; then
        [ -n "$falta" ] && falta+="; "
        falta+="<code>${REGISTRO_BASHRC}</code> no lo carga, asi que se pierde"
        falta+=" lo que se teclee con <code>sudo su</code>"
    fi
    [ -z "$falta" ] && return 0
    printf '  \342\232\240\357\270\217 <b>EL REGISTRO NO ESTA COMPLETO</b>: %s' "$falta"
}

aviso_registro=$(registro_incompleto)
[ -n "$aviso_registro" ] && comandos_fmt+="${NL}${aviso_registro}"

# --- Estado del silenciador --------------------------------------------
#
# Va en el resumen porque el resumen es lo unico que llega estando callado.
# Sin esta linea, una vigilancia apagada y olvidada seria indistinguible de
# una noche tranquila --- que es el mismo fallo que ya se cometio con el cron
# del reporter en simulacion: el parte pintaba de verde lo que estaba muerto.
SILENCIO="${SILENCIO:-/opt/dirtyland/monitor/silencio}"
CARRETE="${CARRETE:-/opt/dirtyland/monitor/silenciadas.log}"

estado_silencio() {
    local hasta ahora quedan retenidas
    retenidas=0
    [ -f "$CARRETE" ] && retenidas=$(wc -l < "$CARRETE" 2>/dev/null || echo 0)

    if [ ! -f "$SILENCIO" ]; then
        printf '\xf0\x9f\x9f\xa2 <b>VIGILANDO</b> --- los avisos llegan al movil'
        return
    fi
    hasta=$(sed -n 's/^hasta=\([0-9]*\)$/\1/p' "$SILENCIO" | head -1)
    ahora=$(date +%s)
    if [ -z "$hasta" ]; then
        printf '\xf0\x9f\x9f\xa2 <b>VIGILANDO</b> --- hay un fichero de silencio ilegible, se ignora'
    elif [ "$hasta" = "0" ]; then
        printf '\xf0\x9f\x94\xb4 <b>SILENCIADA SIN PLAZO</b> --- no se enciende sola'
    elif [ "$ahora" -lt "$hasta" ]; then
        quedan=$(( (hasta - ahora + 59) / 60 ))
        printf '\xf0\x9f\x94\xb4 <b>SILENCIADA</b> --- vuelve sola en %s min' "$quedan"
    else
        printf '\xf0\x9f\x9f\xa2 <b>VIGILANDO</b> --- el plazo vencio y volvio sola'
    fi
    [ "${retenidas:-0}" -gt 0 ] && printf '\n  \xf0\x9f\x9f\xa1 %s aviso(s) retenidos en <code>%s</code>' "$retenidas" "$CARRETE"
}
silencio_fmt="$(estado_silencio)"

# --- Componer mensaje --------------------------------------------------
msg="<strong>[Dirtyland] Resumen diario</strong>
Time: <code>${ts}</code>

<u><b>¿Me han baneado?</b></u>
${cuentas_fmt}

<u>Logins SSH admin (24h)</u>
${logins_fmt}
Intentos fallidos: <code>${failed_count}</code>

<u>Vigilancia del anfitrion</u>
${silencio_fmt}

<u>Ordenes tecleadas en el anfitrion (24h)</u>
Total: <code>${comandos_total}</code>
${comandos_fmt}

<u>Uso de sudo (24h)</u>
${sudo_fmt}

<u>Contenedores</u>
${containers}

<u>Recursos</u>
RAM: <code>${ram}</code>
Disco: <code>${disk}</code>

<u>Egress bloqueado (drops DL-EGRESS, 24h)</u>
<code>${egress_drops}</code>

<u>Actividad Dionaea (24h)</u>
${dionaea_summary}

<u>Reporters telemetria (24h)</u>
${reporters_fmt}"

# --siempre: el resumen es lo unico que atraviesa el silenciador. Si tambien
# se callara, no quedaria nada capaz de avisar de que la vigilancia esta
# apagada, que es precisamente lo que esta seccion existe para contar.
"$ALERT" --siempre "$msg"
