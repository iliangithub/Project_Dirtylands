#!/usr/bin/env bash
# test-acceder-ssh.sh --- entrar al senuelo sin teclear la contrasena.
#
#   bash "3.6 Para facilitarnos la vida/tests/test-acceder-ssh.sh"
#
# El `ssh` de estas pruebas es de mentira: lo unico que hace es EJECUTAR el
# ayudante que le pasamos por SSH_ASKPASS y apuntar lo que devuelve. Asi se
# comprueba lo que de verdad importa ---que ssh recibe la contrasena correcta
# sin que nadie la teclee--- y no que un fichero contenga cierto texto.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUION="$AQUI/../acceder_ssh_para_vagos.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; [ -n "${OYENTE:-}" ] && kill "$OYENTE" 2>/dev/null' EXIT

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

# Alguien tiene que escuchar, o el guion se para antes de llegar al ssh.
python3 -c "
import socket, sys, threading
s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(8)
print(s.getsockname()[1], flush=True)
while True:
    try: s.accept()[0].close()
    except Exception: break
" > "$TMP/puerto" &
OYENTE=$!
for _ in $(seq 1 50); do [ -s "$TMP/puerto" ] && break; sleep 0.1; done
PUERTO_LOCAL=$(head -1 "$TMP/puerto")

# ssh de mentira: llama al ayudante y apunta usuario, opciones y contrasena.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/ssh" <<'FIN'
#!/usr/bin/env bash
{
  printf 'ARGS:%s\n' "$*"
  printf 'ASKPASS_REQUIRE:%s\n' "${SSH_ASKPASS_REQUIRE:-}"
  if [ -n "${SSH_ASKPASS:-}" ] && [ -x "${SSH_ASKPASS}" ]; then
      printf 'CLAVE:%s\n' "$("$SSH_ASKPASS")"
      printf 'AYUDANTE_EN_DISCO:%s\n' "$(cat "$SSH_ASKPASS")"
  else
      printf 'CLAVE:(ninguna)\n'
  fi
} > "$SALIDA_TEST"
FIN
chmod +x "$TMP/bin/ssh"

correr() {
    ( export PATH="$TMP/bin:$PATH" DESTINO=127.0.0.1 PUERTO="$PUERTO_LOCAL" \
             SALIDA_TEST="$TMP/salida" USERDB="${1:-/no/existe}"
      shift || true
      bash "$GUION" "$@" >/dev/null 2>&1 )
    cat "$TMP/salida" 2>/dev/null
}

echo
echo "La contrasena la pone el guion, no el usuario"
salida=$(correr "" )
comprueba "por defecto entra como alyosha" "1" \
    "$(printf '%s' "$salida" | grep -c 'ARGS:.*alyosha@127.0.0.1')"
comprueba "y con su contrasena del cebo" "1" \
    "$(printf '%s' "$salida" | grep -c '^CLAVE:alyosha123$')"
comprueba "forzando el ayudante aun habiendo terminal" "1" \
    "$(printf '%s' "$salida" | grep -c '^ASKPASS_REQUIRE:force$')"

salida=$(correr "" root)
comprueba "root entra con la suya" "1" \
    "$(printf '%s' "$salida" | grep -c '^CLAVE:root$')"
salida=$(correr "" user-ssh)
comprueba "y user-ssh con la suya" "1" \
    "$(printf '%s' "$salida" | grep -c '^CLAVE:987654321$')"

echo
echo "La contrasena no se escribe en ningun fichero"
# El ayudante que queda en disco solo lee una variable de entorno. Si algun
# dia alguien la escribe dentro, esto lo caza.
salida=$(correr "" admin)
comprueba "el ayudante no la lleva dentro" "0" \
    "$(printf '%s' "$salida" | grep -c 'AYUDANTE_EN_DISCO:.*admin')"
comprueba "aunque ssh si la reciba" "1" \
    "$(printf '%s' "$salida" | grep -c '^CLAVE:admin$')"

echo
echo "El userdb de verdad manda sobre la copia"
printf 'alyosha:x:OTRACOSA\n' > "$TMP/userdb"
salida=$(correr "$TMP/userdb")
comprueba "si el userdb se puede leer, gana el" "1" \
    "$(printf '%s' "$salida" | grep -c '^CLAVE:OTRACOSA$')"

echo
echo "Y se puede seguir tecleando a mano"
# Hace falta para probar un login FALLIDO, que es otra cosa que se quiere ver.
salida=$(correr "" alyosha --pedir)
comprueba "con --pedir no se pone ninguna" "1" \
    "$(printf '%s' "$salida" | grep -c '^CLAVE:(ninguna)$')"
salida=$(correr "" nadie)
comprueba "y un usuario desconocido tampoco" "1" \
    "$(printf '%s' "$salida" | grep -c '^CLAVE:(ninguna)$')"

echo
echo "No deja restos"
comprueba "el ayudante se borra al salir" "0" \
    "$(ls /tmp/tmp.* 2>/dev/null | xargs -r grep -l DIRTYLAND_CLAVE 2>/dev/null | wc -l)"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
