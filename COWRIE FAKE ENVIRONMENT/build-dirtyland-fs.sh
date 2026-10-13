#!/usr/bin/env bash

# =================================================================
# build-dirtyland-fs.sh
# Genera el fs.pickle de Cowrie a partir de un Debian 13 real + el /home falso.
# No expone nada ni toca nftables: solo construye artefactos en el host.
# =================================================================

set -euo pipefail

# Rutas por defecto: las de la VPS. El procedimiento del README no cambia.
# Se dejan sobreescribibles por entorno para poder ENSAYAR la regeneracion en
# otra maquina --- contra un Debian de verdad, no contra un arbol de mentira ---
# sin escribir en /opt/dirtyland ni pisar el senuelo que esta en produccion.
#
#   SUDO="" OUT_DIR=/tmp/prueba/fs HONEYFS_DIR=/tmp/prueba/honeyfs \
#   HOME_TAR=... CREATEFS=... bash build-dirtyland-fs.sh
#
# SUDO se expande con "-" y no con ":-" a proposito: asi SUDO="" significa
# "sin sudo", que es lo que hace falta cuando el usuario ya esta en el grupo
# docker. Con ":-" la cadena vacia caeria en el valor por defecto.
IMAGE="${IMAGE:-debian:13}"
HOME_TAR="${HOME_TAR:-/tmp/home.tar}"
CREATEFS="${CREATEFS:-/tmp/createfs.py}"
OUT_DIR="${OUT_DIR:-/opt/dirtyland/cowrie/fs}"
HONEYFS_DIR="${HONEYFS_DIR:-/opt/dirtyland/cowrie/honeyfs}"
SUDO="${SUDO-sudo}"

# Son los paquetes que definen la superficie del SO que vera el atacante.
# Son importantes apra relatar la supuesta historia que buscamos dar.

PACKAGES="openssh-server openssh-client sudo vim curl wget git nodejs npm \
net-tools iproute2 procps htop ca-certificates gnupg cron rsyslog systemd \
less nano unzip tar postgresql-client file netcat-openbsd \
openbsd-inetd inetutils-telnetd libpam-systemd"

# "file" esta aqui porque el senuelo YA LO EMULA. Sin el, la maquina se
# contradecia al reves de lo habitual: "file /bin/su" contestaba como un file
# de verdad mientras "which file" no lo encontraba, "ls -l /usr/bin/file" decia
# que no existe y "dpkg -l" no declaraba el paquete. En Debian "file" es de
# prioridad standard ---lo lleva cualquier instalacion normal--- y solo falta
# aqui porque esto se monta con --no-install-recommends, asi que anadirlo
# ademas hace la leyenda mas creible, no menos.
#
# ESTO NO SE APLICA SOLO: hay que REGENERAR EL PICKLE para que el binario
# aparezca. Hasta entonces la contradiccion sigue en pie en la VPS.

# "netcat-openbsd" entra por lo mismo, y el caso es mas claro todavia: Cowrie
# trae de fabrica su modulo "nc" y lo carga ---esta en command_modules--- asi
# que un "nc -z -w2 10.10.4.12 6379" SE EJECUTA. Pero el paquete no estaba, o
# sea que "which nc" no lo encontraba, "ls /usr/bin/nc" decia que no existe y
# "dpkg -l" no lo declaraba. Un comando que funciona en una maquina que jura no
# tenerlo es la misma contradiccion de "file", del reves.
#
# No es un caso inventado: en una captura de verdad un atacante uso "nc -z"
# veintidos veces para barrer la red interna que le prometia el .env del cebo,
# y antes tecleo un "nc -h" ---que es justo la pregunta de "existe esto?"---.
#
# En Debian el paquete instala /usr/bin/nc.openbsd y deja /usr/bin/nc como
# alternativa apuntando a el, asi que al regenerar aparecen los dos y el enlace
# entre ellos. Es la variante de Debian desde hace anos: la "traditional" hay
# que pedirla a mano.

# Los dos ultimos son para que ofrecer telnet sea COHERENTE. Si el 23 contesta,
# la maquina tiene que parecer una que sirve telnet: con su /etc/inetd.conf,
# su binario en /usr/sbin y sus paginas de manual. Instalarlos y regenerar sale
# gratis y deja todo consistente entre si; colocar esos ficheros a mano obliga
# a acertar en las DOS mitades --- el pickle da el listado y el honeyfs el
# contenido --- y basta fallar en una para que un fichero salga visible pero no
# legible, o legible pero invisible.
#
# libpam-systemd es el que hace que un login abra sesion en logind. Sin el no
# habria ni /run/user/<uid> ni variables XDG_*, y nuestro ps_command_output.json
# declara "systemd-logind", un "systemd --user" y hasta el proceso "(sd-pam)",
# que es justamente el ayudante que crea este modulo. Sin el paquete, "ps aux"
# ensena procesos que "dpkg -l" no sabe explicar.
#
# En Debian 13 el paquete "telnetd" es solo un envoltorio de transicion: el que
# trae el servidor de verdad es "inetutils-telnetd", y necesita un
# super-servidor, de ahi "openbsd-inetd" (que ademas es quien crea
# /etc/inetd.conf). Puestos con --no-install-recommends, apt resolveria la
# dependencia solo, pero se escriben los dos para que se vea la intencion.


# Usuarios y uid fijados. El orden de uid cuenta una historia:
# mihail es el 1000 (el primero), alyosha el 1004 (el ultimo en llegar).

USERS="mihail:1000 admin:1001 user-ssh:1002 mykhailo:1003 alyosha:1004"

for f in "$HOME_TAR" "$CREATEFS"; do
    [ -f "$f" ] || { echo "ERROR: falta $f" >&2; exit 1; }
done

# createfs.py se niega a pisar su propia salida y aborta con un escueto
# "File: ... exists!" DESPUES de haber montado el contenedor entero e instalado
# los paquetes. Se avisa aqui, antes de gastar esos minutos, y se dice que hay
# que borrar: el que rehace la regeneracion suele estar repitiendo un ensayo.
if [ -e "$OUT_DIR/fs.pickle.new" ]; then
    echo "ERROR: ya existe $OUT_DIR/fs.pickle.new" >&2
    echo "       createfs.py no lo sobreescribe. Borralo o mueve el anterior." >&2
    exit 1
fi

$SUDO mkdir -p "$OUT_DIR" "$HONEYFS_DIR"

# LIMITES DE RECURSOS, VACIOS POR DEFECTO Y A PROPOSITO.
#
# Este script corre en la VPS, que es UNA maquina de un solo procesador. Aqui
# se habian puesto los limites del portatil de desarrollo ---medio hilo y
# anclado a las CPU 12 a 19, que ahi son los E-cores--- y en la VPS eso no es
# que vaya lento: no arranca. Docker contesta
#
#     Requested CPUs are not available - requested 12-19, available: 0
#
# y el pickle no se regenera. Ademas este contenedor no solo comprueba cosas:
# INSTALA los paquetes de la leyenda, asi que un techo de memoria pequeno
# tampoco es gratis.
#
# Asi que los limites son OPCIONALES y se piden por entorno. En la VPS no se
# ponen; para ensayar la regeneracion en el portatil, si:
#
#     LIMITES_CPU=0.5 LIMITES_CPUSET=12-19 LIMITES_MEM=2g \
#         bash build-dirtyland-fs.sh
LIMITES=""
[ -n "${LIMITES_CPU:-}" ]    && LIMITES="$LIMITES --cpus=$LIMITES_CPU"
[ -n "${LIMITES_CPUSET:-}" ] && LIMITES="$LIMITES --cpuset-cpus=$LIMITES_CPUSET"
[ -n "${LIMITES_MEM:-}" ]    && LIMITES="$LIMITES --memory=$LIMITES_MEM"

# LA BARRA DE PROGRESO.
#
# Esto tarda varios minutos y suelta CUATROCIENTAS Y PICO lineas de dpkg
# ---"Unpacking", "Setting up", "Selecting previously unselected"--- que no
# dicen nada util y esconden lo que si importa. Se cuentan esas mismas lineas
# y se dibuja una barra, como hace apt.
#
# La barra se dibuja AQUI, en el anfitrion, y no dentro del contenedor: el
# contenedor corre sin terminal ---no hay "-t"--- asi que la barra bonita de
# apt no se renderiza. Aqui si hay terminal, que es la sesion de quien lo
# lanzo.
#
# El total sale de la propia linea de apt ("N newly installed"), y cada
# paquete cuenta DOS pasos, desempaquetar y configurar, que es como va de
# verdad. Lo que no es ruido ---el resumen del final y cualquier error--- se
# deja pasar tal cual.
#
# NO HAY BANDERA PARA VER LA SALIDA ENTERA, y no hace falta: todo lo que sale
# se guarda ADEMAS en un fichero, y si el build falla se vuelca solo el final.
# Una bandera solo sirve cuando ya sabes que la necesitas, y eso pasa despues
# de haber perdido la pista.
REGISTRO="${REGISTRO:-/tmp/dirtyland-build.log}"

barra() {
    local total=0 hechos=0 fase="preparando" ancho=28 pct=0 llenos i pintada
    local limpia='\r\033[2K'
    while IFS= read -r linea; do
        case "$linea" in
            *" newly installed"*)
                total=${linea#*, }; total=${total%% *} ;;
            "Unpacking "*)
                hechos=$((hechos + 1)); fase="instalando" ;;
            "Setting up "*)
                hechos=$((hechos + 1)); fase="configurando" ;;
            "== "*|"Pickle generado"*|"  honeyfs"*|"  dpkg-packages"*)
                printf "$limpia%s\n" "$linea"; continue ;;
            E:*|Err:*|ERROR*|"dpkg: error"*|"docker:"*|*"Traceback"*)
                printf "$limpia%s\n" "$linea"; continue ;;
            *) continue ;;
        esac
        if [ "$total" -gt 0 ] 2>/dev/null; then
            pct=$(( hechos * 100 / (total * 2) ))
            [ "$pct" -gt 100 ] && pct=100
        fi
        llenos=$(( pct * ancho / 100 ))
        pintada=""
        i=0
        while [ "$i" -lt "$ancho" ]; do
            if [ "$i" -lt "$llenos" ]; then pintada="$pintada#"
            else pintada="$pintada."; fi
            i=$((i + 1))
        done
        printf "$limpia[%s] %3d%%  %s" "$pintada" "$pct" "$fase"
    done
    printf "$limpia"
}

# "-q" y no "-qq": con dos, apt se calla tambien la linea del total
# ---"N newly installed"--- y la barra se queda sin saber cuanto falta.

$SUDO docker run --rm --network host $LIMITES \
    -v "$CREATEFS:/cowrie-build/createfs.py:ro" \
    -v "$HOME_TAR:/cowrie-build/home.tar:ro" \
    -v "$OUT_DIR:/cowrie-out" \
    -e PACKAGES="$PACKAGES" \
    -e USERS="$USERS" \
    "$IMAGE" \
    bash -eu -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -q --no-install-recommends python3 $PACKAGES
        apt-get clean

        # ====== 0. Activar telnet en el inetd.conf de Debian ======
        #
        # Instalar inetutils-telnetd NO basta: en trixie ese paquete solo
        # deja el binario en /usr/sbin/telnetd. No trae postinst y no registra
        # nada, asi que /etc/inetd.conf se queda entero comentado mientras el
        # senuelo contesta en el 23. Un "cat /etc/inetd.conf" mostraria una
        # maquina que no explica su propio puerto abierto.
        #
        # No se anade la linea a mano: openbsd-inetd ya trae la suya, en su
        # seccion :STANDARD:, desactivada con el marcador "#<off>#".
        # "update-inetd --enable" le quita ese prefijo en su sitio. Es lo que
        # hace Debian cuando se habilita el servicio de verdad, asi que el
        # formato ---los tabuladores, el orden de los campos, el envoltorio
        # /usr/sbin/tcpd--- sale de Debian y no de nuestra imaginacion. Es el
        # mismo criterio que con issue.net: lo de serie se copia, no se
        # inventa, porque es al inventarse el formato cuando se cuela el
        # detalle que no cuadra.
        #
        # tcpd y update-inetd son ambos Depends de openbsd-inetd, asi que
        # estan aunque se instale con --no-install-recommends: la linea cita
        # un /usr/sbin/tcpd que existe de verdad en el arbol.
        #
        # En el log saldran dos quejas de invoke-rc.d ("could not determine
        # current runlevel" y "policy-rc.d denied execution of start"). Son
        # inofensivas: update-inetd intenta reiniciar inetd, y en un
        # contenedor no hay init que reiniciar. Devuelve 0 y es idempotente.
        update-inetd --enable telnet

        # ====== 1. Crear usuarios ANTES de traer el arbol ======
        # Deben existir para que /etc/passwd los liste (el atacante hara
        # "cat /etc/passwd"). useradd -m crea /home/<user> con esqueleto;
        # el tar del paso siguiente lo pisara con el arbol real.

        for pair in $USERS; do
            u="${pair%%:*}"; id="${pair##*:}"
            groupadd -g "$id" "$u" 2>/dev/null || true
            useradd -m -u "$id" -g "$id" -s /bin/bash "$u" 2>/dev/null || true
        done

        # ====== 2. Traer el arbol falso encima ======
        # -p preserva permisos; como root, tar restaura el mtime del archivo.
        # Ese mtime es el dato que luego leera createfs.py: si se perdiera,
        # todos los ficheros apareceria creados "hoy" y delatarian el senuelo.

        tar -xpf /cowrie-build/home.tar -C /

        # ====== 3. Reaplicar propietario ======
        # El tar viene de un origen sin uid/gid utiles, asi que todo cae como
        # root. Reasignamos cada home a su usuario usando ids NUMERICOS.
        # chown NO modifica el mtime, asi que las fechas sobreviven.

        # El permiso del home va en 0750, no en el 0755 que deja "useradd -m".
        # Con 0755 cualquier usuario puede entrar en el home de otro y listarlo,
        # y entonces el control de permisos de los modulos (ls, cat, cd, find...)
        # no tiene nada que denegar: un "ls /home/admin" desde otra cuenta
        # mostraria el proyecto entero. Con 0750 solo entran su dueno y root.
        for pair in $USERS; do
            u="${pair%%:*}"; id="${pair##*:}"
            [ -d "/home/$u" ] && chown -R "$id:$id" "/home/$u" && chmod 750 "/home/$u"
        done

        # ====== 4. Permisos criticos de SSH ======
        # OpenSSH exige 700 en ~/.ssh y 600 en claves privadas: un .ssh con
        # permisos laxos es un tell inmediato de que el sistema es falso.

        for pair in $USERS; do
            u="${pair%%:*}"
            d="/home/$u/.ssh"
            if [ -d "$d" ]; then
                chmod 700 "$d"
                find "$d" -type f ! -name "*.pub" ! -name "known_hosts" \
                    ! -name "authorized_keys" -exec chmod 600 {} \;
                find "$d" -type f \( -name "*.pub" -o -name "known_hosts" \) \
                    -exec chmod 644 {} \;
                [ -f "$d/authorized_keys" ] && chmod 600 "$d/authorized_keys"
                find "$d" -type d -exec chmod 700 {} \;
            fi
        done

        find /home -type d -name "deploy-keys" | while read -r dk; do
            find "$dk" -type f ! -name "*.pub" -exec chmod 600 {} \;
        done
        find "/home/admin" -name ".env" -exec chmod 600 {} \; 2>/dev/null || true

        # ====== 5. Borrar el rastro de Docker ======
        # Su presencia delataria que el sistema se genero en un contenedor.

        # El directorio /home en si pertenece a root en cualquier Linux real.
        # Sin esto quedaria como propiedad del primer usuario creado (mihail).
        chown root:root /home
        chmod 755 /home

        rm -f /.dockerenv

        # Las claves de host que genero openssh-server al instalarse llevan el
        # hostname del contenedor en su comentario. Se borran: Cowrie no las usa.
        rm -f /etc/ssh/ssh_host_*

        # ====== 6. Generar el pickle ======
        # createfs.py recorre TODO el contenedor (-l /) haciendo os.stat() a
        # cada fichero: la base Debian 13 real mas nuestro /home inyectado.
        # El pickle es la foto del disco tal y como lo hemos dejado arriba.

        python3 /cowrie-build/createfs.py -l / -o /cowrie-out/fs.pickle.new
        chmod 0644 /cowrie-out/fs.pickle.new
        echo "Pickle generado: fs.pickle.new"

        # ====== 7. Exportar los /etc que el honeyfs necesita ======
        #
        # El honeyfs venia teniendo SOLO /home, y para telnet eso no basta:
        # Cowrie lee el banner de "etc/issue.net" DENTRO del honeyfs
        # (read_honeyfs_bytes), y si no esta escribe "ERROR: Failed to load
        # /etc/issue.net" en el log y saca un banner vacio. Un telnet de Debian
        # de verdad imprime esa linea antes del "login:", asi que un banner
        # vacio es un delator --- y ademas ensucia el log en cada arranque.
        #
        # Se exportan DESDE ESTE MISMO CONTENEDOR y no se escriben a mano: es
        # el que acaba de generar el pickle, asi que el listado y el contenido
        # salen de la misma foto por construccion. Escritos aparte, bastaria
        # que uno cambiase para que el fichero saliera visible pero no legible.
        mkdir -p /cowrie-out/honeyfs-etc
        for f in issue issue.net inetd.conf; do
            if [ -f "/etc/$f" ]; then
                cp -a "/etc/$f" /cowrie-out/honeyfs-etc/
                echo "  honeyfs /etc/$f  ($(wc -c < /etc/$f) bytes)"
            else
                echo "  AVISO: no existe /etc/$f en la imagen" >&2
            fi
        done

        # El sshd_config, con PermitRootLogin coherente con el userdb.
        #
        # Debian lo deja en "#PermitRootLogin prohibit-password", que es su
        # valor por defecto: root NO entra con contrasena. Pero el senuelo
        # acepta root con contrasena ---es la cuenta contra la que van casi
        # todos los intentos, apartado 3.4---, asi que quien entre como root
        # y haga un cat de este fichero leeria que lo que acaba de hacer esta
        # prohibido. Se deja dicho lo que la maquina hace de verdad.
        if [ -f /etc/ssh/sshd_config ]; then
            sed -i "s/^#*PermitRootLogin .*/PermitRootLogin yes/" /etc/ssh/sshd_config
            grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
            mkdir -p /cowrie-out/honeyfs-etc/ssh
            cp -a /etc/ssh/sshd_config /cowrie-out/honeyfs-etc/ssh/
            echo "  honeyfs /etc/ssh/sshd_config  ($(wc -c < /etc/ssh/sshd_config) bytes)"
        else
            echo "  AVISO: no existe /etc/ssh/sshd_config en la imagen" >&2
        fi
        chmod 0644 /cowrie-out/honeyfs-etc/* 2>/dev/null || true

        # ====== 8. Exportar la lista de paquetes para el "dpkg -l" ======
        #
        # El dpkg emulado no lleva la lista escrita dentro: la lee de aqui.
        # Sale de ESTE contenedor, el mismo que acaba de generar el pickle,
        # asi que lo que dice "dpkg -l" y lo que hay en el disco falso no
        # pueden discrepar. Escrita a mano si discrepaba: llego a tener 26
        # paquetes con 20 versiones desfasadas, y una de ellas contradecia al
        # banner que anuncia el propio SSH.
        #
        # Se usa binary:Package y no Package porque "dpkg -l" anade el sufijo
        # ":amd64" a los paquetes multi-arch, y sin el la salida no coincide
        # con la de un dpkg de verdad.
        dpkg-query -W \
            -f="\${binary:Package}\t\${Version}\t\${Architecture}\t\${binary:Summary}\n" \
            > /cowrie-out/dpkg-packages.tsv
        chmod 0644 /cowrie-out/dpkg-packages.tsv
        echo "  dpkg-packages.tsv  ($(wc -l < /cowrie-out/dpkg-packages.tsv) paquetes)"
    ' > "$REGISTRO" 2>&1 &
espera=$!
tail -n +1 -f --pid="$espera" "$REGISTRO" 2>/dev/null | barra
if ! wait "$espera"; then
    # La barra se come el ruido, asi que cuando algo falla se ensena el final
    # del registro: es donde esta el motivo, y sin esto quedaria una barra a
    # medias y ninguna pista.
    echo
    echo "FALLO la regeneracion. Ultimas lineas de $REGISTRO:"
    echo "---------------------------------------------------------------"
    tail -n 25 "$REGISTRO"
    echo "---------------------------------------------------------------"
    echo "El registro completo esta en $REGISTRO"
    exit 1
fi

echo "== Pickle en $OUT_DIR/fs.pickle.new =="
echo "== /etc de serie para el honeyfs en $OUT_DIR/honeyfs-etc =="
echo "== Lista de paquetes para dpkg -l en $OUT_DIR/dpkg-packages.tsv =="
echo
# NO se imprime aqui el comando de saneado, y es a proposito. Lo lleva escrito
# el apartado 3.4.2.4 del README, y tenerlo en dos sitios es garantizar que
# algun dia digan cosas distintas: se cambia una ruta en la guia y este eco
# sigue diciendo la de antes, sin que nada avise. Manda el README.
echo "Siguiente paso: apartado 3.4.2.4 del README, sanear el pickle."
echo
echo "NO hay que instalar esos /etc a mano: sanitize-pickle.py los busca en"
echo "honeyfs-etc/, al lado del pickle de entrada, y los copia al honeyfs en"
echo "la misma pasada."
echo
echo "Entre ellos va etc/issue.net, que es el banner de telnet. Sin el, Cowrie"
echo "escribe 'ERROR: Failed to load /etc/issue.net' en cada arranque y sirve"
echo "un banner vacio."
