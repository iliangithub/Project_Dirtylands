#!/usr/bin/env bash
# test-ssh-watch.sh — de que IP avisa el vigilante de SSH.
#
#   bash "TELEGRAM SCRIPTS/tests/test-ssh-watch.sh"
#
# Esto no es una prueba de formato: es una prueba de un CONTROL. El nombre de
# usuario que sale en el log de sshd lo elige quien se conecta, espacios
# incluidos, asi que la linea contiene texto del atacante ANTES de la IP de
# verdad. Cogiendo la primera coincidencia de "from ", cualquiera podia elegir
# que direccion aparece como origen en la alerta --- y poniendo una nuestra,
# marca_propia la sellaba con "(nuestro)" y el aviso de una intrusion ajena
# pasaba por una comprobacion tuya.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Solo las funciones: sin esto, hacer source arrancaria a seguir el journal.
SSH_WATCH_SOLO_FUNCIONES=1
# shellcheck source=/dev/null
. "$AQUI/../ssh-watch.sh"

OK=0; MAL=0
comprueba() {
    local que="$1" esperado="$2" obtenido="$3"
    if [ "$esperado" = "$obtenido" ]; then
        OK=$((OK + 1)); printf '  ok    %s\n' "$que"
    else
        MAL=$((MAL + 1))
        printf '  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>\n' \
            "$que" "$esperado" "$obtenido"
    fi
}

P='2026-08-20T11:02:03+0000 pc sshd[123]: '

echo
echo "Lineas normales de sshd"
comprueba "usuario invalido" "203.0.113.9" \
    "$(ip_de_linea "${P}Invalid user admin from 203.0.113.9 port 51234")"
comprueba "contrasena fallida" "198.51.100.7" \
    "$(ip_de_linea "${P}Failed password for root from 198.51.100.7 port 40022 ssh2")"
comprueba "login correcto" "203.0.113.9" \
    "$(ip_de_linea "${P}Accepted publickey for admin from 203.0.113.9 port 51234 ssh2: ED25519 SHA256:x")"
comprueba "IPv6" "2001:db8::1" \
    "$(ip_de_linea "${P}Invalid user test from 2001:db8::1 port 2222")"

echo
echo "El atacante intenta elegir la IP que se muestra"
# El nombre de usuario es "admin from 198.51.100.146 port 22". sshd lo escribe
# tal cual, y detras pone la IP de verdad.
FALSA="${P}Invalid user admin from 198.51.100.146 port 22 from 203.0.113.9 port 51234"
comprueba "gana la IP que pone sshd, no la del nombre de usuario" "203.0.113.9" \
    "$(ip_de_linea "$FALSA")"
comprueba "y no es una IP NUESTRA lo que se muestra" "no" \
    "$( [ "$(ip_de_linea "$FALSA")" = "198.51.100.146" ] && echo si || echo no )"

# La otra mitad del mismo truco: colar la IP propia al final del texto libre,
# sin el " port " detras. El ancla lo impide.
SIN_PUERTO="${P}Invalid user x from 203.0.113.9 port 51234 mensaje: from 198.51.100.146"
comprueba "una IP sin ' port ' detras no se toma por el origen" "203.0.113.9" \
    "$(ip_de_linea "$SIN_PUERTO")"

echo
echo "Casos de borde"
comprueba "una linea sin IP no devuelve nada" "" \
    "$(ip_de_linea "${P}Connection closed by authenticating user root")"
comprueba "una linea vacia tampoco" "" "$(ip_de_linea "")"

echo
echo "Escapado del texto del atacante"
# El nombre de usuario va al mensaje dentro de <pre>. Un "<" sin escapar deja
# el aviso en un 400 de Telegram, y ese aviso no se reintenta.
comprueba "las etiquetas se escapan" "&lt;b&gt;" "$(tg_escapar '<b>')"
comprueba "y el & tambien, que antes se quedaba crudo" "a&amp;b" "$(tg_escapar 'a&b')"
comprueba "un nombre de usuario hostil queda inerte" "no" \
    "$( case "$(tg_escapar 'admin<script>x</script>')" in *'<'*) echo si;; *) echo no;; esac )"

echo
echo "-------------------------------------"
printf 'ok: %d   fallos: %d\n' "$OK" "$MAL"
[ "$MAL" -eq 0 ] || exit 1
