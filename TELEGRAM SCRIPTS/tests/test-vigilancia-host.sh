#!/usr/bin/env bash
# test-vigilancia-host.sh — el registro de ordenes del anfitrion y el silenciador.
#
#   bash "TELEGRAM SCRIPTS/tests/test-vigilancia-host.sh"
#
# Cubre las tres piezas que hacen que el canal del anfitrion sea util:
#
#   1. El TROCEADO de la linea del registro. Aqui hay un control, no un
#      formato: la orden tecleada es lo ultimo de la linea y puede contener
#      cualquier cosa, "pwd=" incluido. Si el aviso leyera los campos a lo
#      bruto, bastaria teclear  echo pwd=/falso  para elegir que directorio
#      aparece en la alerta. Se prueba explicitamente.
#
#   2. El SILENCIADOR. Que calle cuando debe, que NO calle con el plazo
#      vencido ---la red de seguridad para el dia que alguien lo apague y se
#      olvide--- y que el resumen diario lo atraviese con "--siempre". Si el
#      resumen tambien se callara, nada avisaria de que la vigilancia esta
#      apagada.
#
#   3. Que un aviso SIN cuerpo se envie. Un mensaje de una sola linea no
#      producia ningun trozo y se perdia entero, sin error y sin rastro.
#
# No toca la red: el curl se sustituye por uno de mentira que deja un fichero.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RAIZ=$(cd "$AQUI/.." && pwd)

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

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- 1. campos
echo
echo "== troceado de la linea del registro =="

COMANDOS_WATCH_SOLO_FUNCIONES=1
# shellcheck source=/dev/null
. "$RAIZ/comandos-watch.sh"

LINEA='user=admin tty=pts/0 from=203.0.113.9 pwd=/opt/dirtyland rc=0 cmd=ls -la'
comprueba "usuario"            "admin"           "$(campo user "$LINEA")"
comprueba "terminal"           "pts/0"           "$(campo tty "$LINEA")"
comprueba "origen"             "203.0.113.9"     "$(campo from "$LINEA")"
comprueba "directorio"         "/opt/dirtyland"  "$(campo pwd "$LINEA")"
comprueba "codigo de salida"   "0"               "$(campo rc "$LINEA")"
comprueba "la orden entera"    "ls -la"          "$(campo cmd "$LINEA")"

# El control: la orden lleva dentro lo que parece otro campo.
TRAMPA='user=admin tty=pts/0 from=203.0.113.9 pwd=/root rc=0 cmd=echo pwd=/falso from=1.2.3.4'
comprueba "una orden con pwd= dentro NO cambia el directorio del aviso" \
          "/root"        "$(campo pwd "$TRAMPA")"
comprueba "ni el origen" \
          "203.0.113.9"  "$(campo from "$TRAMPA")"
comprueba "y la orden se ensena entera, sin recortar" \
          "echo pwd=/falso from=1.2.3.4" "$(campo cmd "$TRAMPA")"

# Una orden con espacios y con signos de HTML sobrevive al troceado.
RARA='user=a tty=b from=c pwd=/d rc=2 cmd=grep -r "<script>" /var || echo no'
comprueba "una orden con comillas y tuberias llega entera" \
          'grep -r "<script>" /var || echo no' "$(campo cmd "$RARA")"

# ---------------------------------------------------- 2. agrupacion y envio
echo
echo "== agrupacion por sesion =="

ALERTA_FALSA="$TMP/alerta.sh"
cat > "$ALERTA_FALSA" <<'EOF'
#!/usr/bin/env bash
printf '<<<AVISO>>>\n%s\n' "$1" >> "$SALIDA"
EOF
chmod +x "$ALERTA_FALSA"

: > "$TMP/salida.txt"
printf '%s\n' \
  'user=admin tty=pts/0 from=203.0.113.9 pwd=/root rc=0 cmd=ls' \
  'user=admin tty=pts/0 from=203.0.113.9 pwd=/root rc=0 cmd=id' \
  'user=otro tty=pts/1 from=198.51.100.7 pwd=/tmp rc=1 cmd=whoami' \
  | SALIDA="$TMP/salida.txt" ALERT="$ALERTA_FALSA" COMANDOS_ESPERA=1 \
    bash "$RAIZ/comandos-watch.sh" --stdin >/dev/null 2>&1

avisos=$(grep -c '<<<AVISO>>>' "$TMP/salida.txt" || true)
comprueba "dos sesiones distintas -> dos avisos, no uno mezclado" "2" "$avisos"
comprueba "el de admin dice 2 ordenes" "1" \
          "$(grep -c '<b>2 ordenes  ---' "$TMP/salida.txt" || true)"

# QUIEN AVISA Y DE QUE MAQUINA, en la primera linea. Por el mismo chat llegan
# los avisos de los dos senuelos, y un aviso de ordenes ejecutadas se lee muy
# distinto segun de donde venga: dentro de Cowrie es lo normal ---para eso
# esta--- y en el anfitrion es que hay alguien dentro de la maquina de verdad.
comprueba "el aviso dice que servicio lo manda" "2" \
          "$(grep -c '\[dirtyland-cmdwatch\]' "$TMP/salida.txt" || true)"
comprueba "y de que maquina habla" "2" \
          "$(grep -c 'Maquina VPS principal' "$TMP/salida.txt" || true)"
comprueba "y avisa de que NO son los senuelos" "2" \
          "$(grep -c 'NO son los senuelos' "$TMP/salida.txt" || true)"

# NINGUNA SECUENCIA DE ESCAPE SE PUEDE COLAR TAL CUAL. Bash NO interpreta
# "\xNN" dentro de comillas dobles, asi que un emoji escrito asi sale literal
# en el mensaje: llego al movil un "\xf0\x9f\x9a\xa8" en vez del icono. Se
# construyen con printf, como los puntos de color del resumen diario.
comprueba "ningun \\x se cuela sin interpretar" "0" \
          "$(grep -c '\\x[0-9a-f][0-9a-f]' "$TMP/salida.txt" || true)"
comprueba "y el emoji llega como emoji" "2" \
          "$(grep -c "$(printf '\360\237\232\250')" "$TMP/salida.txt" || true)"
comprueba "el de otro dice 1 orden, en singular" "1" \
          "$(grep -c '<b>1 orden  ---' "$TMP/salida.txt" || true)"
comprueba "el codigo de salida distinto de 0 se ensena" "1" \
          "$(grep -c 'rc=1' "$TMP/salida.txt" || true)"
comprueba "y el 0 no ensucia el mensaje" "0" \
          "$(grep -c 'rc=0' "$TMP/salida.txt" || true)"

: > "$TMP/salida.txt"
printf '%s\n' \
  'user=a tty=p from=c pwd=/x rc=0 cmd=echo <b>hola</b>' \
  | SALIDA="$TMP/salida.txt" ALERT="$ALERTA_FALSA" COMANDOS_ESPERA=1 \
    bash "$RAIZ/comandos-watch.sh" --stdin >/dev/null 2>&1
comprueba "el HTML de una orden se escapa antes de mandarlo" "1" \
          "$(grep -c '&lt;b&gt;hola&lt;/b&gt;' "$TMP/salida.txt" || true)"
comprueba "y no llega ninguna etiqueta cruda" "0" \
          "$(grep -c '<b>hola</b>' "$TMP/salida.txt" || true)"

# ------------------------------------------------------------ 3. silenciador
echo
echo "== el silenciador =="

# send-alert.sh de verdad, con un curl de mentira delante.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/sh
echo ENVIADO >> "$ENVIADOS"
printf '%s' '{"ok":true}'
EOF
chmod +x "$TMP/bin/curl"
printf 'BOT_TOKEN=x\nCHAT_ID=y\n' > "$TMP/telegram.env"

manda() {
    : > "$TMP/enviados.txt"
    PATH="$TMP/bin:$PATH" ENVIADOS="$TMP/enviados.txt" \
    ENV_FILE="$TMP/telegram.env" LIB_TELEGRAM="$RAIZ/lib-telegram.sh" \
    SILENCIO="$TMP/silencio" CARRETE="$TMP/carrete" \
        bash "$RAIZ/send-alert.sh" "$@" >/dev/null 2>&1 || true
    # "grep -c" devuelve 1 cuando no encuentra nada, asi que un "|| echo 0"
    # detras imprime DOS lineas: la del grep y la del echo.
    local n; n=$(grep -c ENVIADO "$TMP/enviados.txt" 2>/dev/null) || n=0
    printf '%s' "$n"
}

rm -f "$TMP/silencio" "$TMP/carrete"
comprueba "sin fichero de silencio se envia" "1" \
          "$(manda "<b>uno</b>
cuerpo")"

comprueba "un aviso de UNA SOLA LINEA tambien se envia" "1" \
          "$(manda "<b>solo cabecera</b>")"

printf 'desde=1\nhasta=0\n' > "$TMP/silencio"
comprueba "silencio sin plazo: no se envia" "0" \
          "$(manda "<b>dos</b>
cuerpo")"
comprueba "pero se anota en el carrete" "1" \
          "$(wc -l < "$TMP/carrete" 2>/dev/null | tr -d ' ' || echo 0)"
comprueba "y el carrete guarda el titulo sin etiquetas" "1" \
          "$(grep -c '|dos$' "$TMP/carrete" || true)"

comprueba "el resumen diario atraviesa el silencio con --siempre" "1" \
          "$(manda --siempre "<b>resumen</b>
cuerpo")"

printf 'desde=1\nhasta=%s\n' "$(( $(date +%s) + 3600 ))" > "$TMP/silencio"
comprueba "silencio con plazo vigente: no se envia" "0" \
          "$(manda "<b>tres</b>
cuerpo")"

printf 'desde=1\nhasta=%s\n' "$(( $(date +%s) - 10 ))" > "$TMP/silencio"
comprueba "PLAZO VENCIDO: vuelve a enviar sin que nadie lo toque" "1" \
          "$(manda "<b>cuatro</b>
cuerpo")"

printf 'desde=1\nhasta=basura\n' > "$TMP/silencio"
comprueba "un fichero de silencio ilegible NO deja la maquina muda" "1" \
          "$(manda "<b>cinco</b>
cuerpo")"

echo
echo "-------------------------------------"
printf 'ok: %d   fallos: %d\n' "$OK" "$MAL"
[ "$MAL" -eq 0 ]
