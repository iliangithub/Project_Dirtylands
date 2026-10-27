#!/usr/bin/env bash
#
# ssh-watch.sh
# Vigila en tiempo real el log de sshd y alerta por Telegram en login
# exitoso o fallido al puerto admin. Corre como servicio systemd.
#
set -euo pipefail

ALERT="${ALERT:-/opt/dirtyland/monitor/send-alert.sh}"

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

# tg_escapar: lo que escribe el atacante no entra crudo en el HTML.
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

# ip_de_linea LINEA -> la IP de origen REAL de una linea de sshd.
#
# Esto no es una comodidad, es un control. El nombre de usuario que aparece en
# "Invalid user X from IP port N" lo elige el atacante, espacios incluidos, y
# sshd lo escribe tal cual. Antes se cogia la PRIMERA coincidencia de "from ":
#
#   Invalid user "admin from 198.51.100.146 port 22" from 203.0.113.9 port 51234
#                             ^^^^^^^^^^^^^ esto es lo que se mostraba
#
# O sea que cualquiera podia elegir que IP aparece como origen en tu alerta.
# Poniendo una IP NUESTRA, marca_propia la sellaba con "(nuestro)" y el aviso
# de una intrusion ajena pasaba por una comprobacion tuya. Un atacante que
# sepa esto se vuelve invisible en el canal de avisos.
#
# Se arregla por los dos lados: se exige que a la IP le siga " port ", que es
# lo que sshd escribe siempre, y se coge la ULTIMA --- la que anade sshd va
# despues de todo lo que haya escrito el atacante.
ip_de_linea() {
    printf '%s' "${1:-}" \
        | grep -oP 'from \K[0-9a-fA-F:.]+(?= port )' \
        | tail -1
}

# Puerta para las pruebas: con esto se puede hacer "source" del fichero y
# quedarse solo con las funciones, sin arrancar el seguimiento del journal.
# Un extractor de IP que decide si una intrusion se marca como propia tiene
# que poder probarse; si para probarlo hay que copiar la expresion a otro
# sitio, se prueba una copia y no lo que corre de verdad.
if [ "${SSH_WATCH_SOLO_FUNCIONES:-0}" = "1" ]; then
    return 0
fi

journalctl -u ssh -f -n 0 -o short-iso --no-pager | while IFS= read -r line; do
    ts=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

    # --- Login exitoso -------------------------------------------------
    if echo "$line" | grep -q 'Accepted publickey'; then
        user=$(echo "$line" | grep -oP 'Accepted publickey for \K\S+')
        ip=$(ip_de_linea "$line")
        propia=$(marca_propia "$ip")
        "$ALERT" "<strong>[Host] Login SSH exitoso</strong>
Time: <code>${ts}</code>
User: <code>$(tg_escapar "$user")</code>
Source: <code>${ip:-desconocida}</code>${propia}$(pais_de "${ip:-}")"

    # --- Intento contra root (se trata aparte por su gravedad) ---------
    # Con PermitRootLogin desactivado, OpenSSH registra mensajes del tipo
    # "User root ... not allowed because ..." o "ROOT LOGIN REFUSED", que
    # los patrones genericos de fallo no siempre capturan.
    elif echo "$line" | grep -qiE 'root.*(not allowed|refused)|ROOT LOGIN REFUSED|(Failed|Invalid).*root'; then
        ip=$(ip_de_linea "$line")
        propia=$(marca_propia "${ip:-}")
        "$ALERT" "<strong>[Host] INTENTO DE ACCESO A ROOT</strong>
Time: <code>${ts}</code>
Source: <code>${ip:-desconocida}</code>${propia}$(pais_de "${ip:-}")
Detalle: <pre>$(tg_escapar "$line")</pre>"

    # --- Resto de fallos de autenticacion ------------------------------
    elif echo "$line" | grep -qE 'Failed password|Failed publickey|Invalid user|not allowed because|authentication failure'; then
        ip=$(ip_de_linea "$line")
        propia=$(marca_propia "${ip:-}")
        "$ALERT" "<strong>[Host] Intento de login SSH FALLIDO</strong>
Time: <code>${ts}</code>
Source: <code>${ip:-desconocida}</code>${propia}$(pais_de "${ip:-}")
Detalle: <pre>$(tg_escapar "$line")</pre>"
    fi
done
