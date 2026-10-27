#!/usr/bin/env bash
#
# acceder_ssh_para_vagos.sh
#
# Entra al senuelo desde DENTRO de la propia VPS, que es como hay que
# probarlo. No hace falta recordar el puerto, ni la IP del contenedor, ni las
# opciones de ssh que evitan que se ensucie el known_hosts.
#
#   ./acceder_ssh_para_vagos.sh                entra como alyosha
#   ./acceder_ssh_para_vagos.sh admin          entra como admin
#   ./acceder_ssh_para_vagos.sh admin --pedir  y que pregunte la contrasena
#
# NO PREGUNTA LA CONTRASENA, la pone el solo. Y no pasa nada por escribirlas
# aqui: son las del CEBO. Estan puestas a proposito para que las adivine
# cualquiera ---root:root es la que mas--- y lo unico que abren es un sistema
# de ficheros emulado dentro del contenedor, que no tiene forma de tocar el
# anfitrion. Ahi el acceso por root esta desactivado y solo se entra con clave
# desde el VPN. Ver la nota del apartado 3.4.2.4 del README.
#
# Con --pedir se comporta como antes y las pregunta, que es lo que hace falta
# para probar un login FALLIDO (por ejemplo, para ver si salta la alerta).
#
# POR QUE DESDE DENTRO, y no desde casa: la IP de origen es entonces privada
# (172.20.0.1), y la barrera del reporter descarta sola todo lo que no sea una
# direccion global. Probando desde fuera, esa conexion entra como una sesion
# atacante mas y acabaria denunciada en AbuseIPDB --- que ademas suele ser un
# nodo de VPN compartido, o sea perjudicando a terceros. Los nodos de salida
# estan en la [blocklist] justo para eso, pero esa lista hay que mantenerla a
# mano y las IP rotan. Entrando por aqui no hay nada que mantener.
#
# Las credenciales son las del userdb:
#   sudo cat /opt/dirtyland/cowrie/etc/userdb.txt
set -euo pipefail

USUARIO="${1:-alyosha}"
PEDIR=""
for a in "$@"; do [ "$a" = "--pedir" ] && PEDIR=1; done
[ "$USUARIO" = "--pedir" ] && USUARIO="alyosha"

# Por variable de entorno para poder probarlo contra un puerto local; en la
# VPS nadie las toca. Misma razon que el NFT del baneador.
DESTINO="${DESTINO:-172.20.0.10}"
PUERTO="${PUERTO:-2222}"
USERDB="${USERDB:-/opt/dirtyland/cowrie/etc/userdb.txt}"

# La copia de aqui es el ULTIMO recurso. Primero se lee el userdb de verdad,
# si se puede: asi cambiar una contrasena alli no deja este guion mintiendo.
# El fichero es de root, asi que sin sudo casi nunca se podra --- y por eso
# hay copia.
CLAVES_CONOCIDAS="root:root
admin:admin
alyosha:alyosha123
user-ssh:987654321"

clave_de() {
    local u="$1" c=""
    if [ -r "$USERDB" ]; then
        c=$(awk -F: -v u="$u" '$1 == u { print $3; exit }' "$USERDB")
    fi
    if [ -z "$c" ]; then
        c=$(printf '%s\n' "$CLAVES_CONOCIDAS" \
            | awk -F: -v u="$u" '$1 == u { print $2; exit }')
    fi
    [ -n "$c" ] || return 1
    printf '%s' "$c"
}

# Sin esto, cada vez que se recrea el contenedor cambia la clave de host y ssh
# se planta con el aviso de REMOTE HOST IDENTIFICATION HAS CHANGED. Aqui da
# igual: es nuestro propio senuelo en una red interna, no hay nada que
# autenticar. Y no se toca el known_hosts de verdad.
OPCIONES=(
    -p "$PUERTO"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o PreferredAuthentications=password
    -o PubkeyAuthentication=no
    # Un solo intento: si la contrasena no vale, que lo diga ya en vez de
    # reintentar tres veces con la misma.
    -o NumberOfPasswordPrompts=1
)

if ! command -v ssh >/dev/null 2>&1; then
    echo "Falta el cliente de ssh:  sudo apt install -y openssh-client" >&2
    exit 1
fi

# Comprobar que hay alguien escuchando antes de intentarlo, para no dejar al
# usuario mirando un "connection refused" sin contexto.
if ! timeout 3 bash -c "</dev/tcp/${DESTINO}/${PUERTO}" 2>/dev/null; then
    echo "Nadie escucha en ${DESTINO}:${PUERTO}." >&2
    echo "El contenedor puede estar parado. Comprueba con:" >&2
    echo "  sudo docker ps --filter name=dirtyland_cowrie" >&2
    echo "Y si lo paraste con el boton del panico, reanudalo con:" >&2
    echo "  sudo ~/boton_del_panico.sh --reanudar" >&2
    exit 1
fi

CLAVE=""
[ -z "$PEDIR" ] && CLAVE=$(clave_de "$USUARIO") || true

if [ -z "$CLAVE" ]; then
    if [ -z "$PEDIR" ]; then
        echo "No se conoce la contrasena de '${USUARIO}'; se pedira." >&2
        echo "Las cuentas del senuelo:  sudo cat ${USERDB}" >&2
    fi
    echo "Entrando al senuelo como '${USUARIO}'."
    echo "(Ctrl+D o 'exit' para salir.)"
    echo
    exec ssh "${OPCIONES[@]}" "${USUARIO}@${DESTINO}"
fi

# LA CONTRASENA NO SE ESCRIBE EN NINGUN FICHERO. El ayudante que ssh ejecuta
# solo la lee de una variable de entorno que le llega heredada; en el disco
# queda un guion de dos lineas sin ningun secreto dentro, y se borra al salir.
#
# SSH_ASKPASS_REQUIRE=force es lo que hace que ssh lo use TENIENDO terminal
# (sin eso solo se usa cuando no hay ninguno). Necesita OpenSSH 8.4 o
# posterior; en uno anterior la variable se ignora y ssh pregunta, que es
# exactamente lo que hacia antes. No se rompe nada.
AYUDANTE=$(mktemp)
trap 'rm -f "$AYUDANTE"' EXIT
cat > "$AYUDANTE" <<'FIN'
#!/bin/sh
printf '%s\n' "$DIRTYLAND_CLAVE"
FIN
chmod 700 "$AYUDANTE"

echo "Entrando al senuelo como '${USUARIO}' (contrasena puesta sola)."
echo "(Ctrl+D o 'exit' para salir.)"
echo
DIRTYLAND_CLAVE="$CLAVE" \
SSH_ASKPASS="$AYUDANTE" \
SSH_ASKPASS_REQUIRE=force \
DISPLAY="${DISPLAY:-:0}" \
    ssh "${OPCIONES[@]}" "${USUARIO}@${DESTINO}"
