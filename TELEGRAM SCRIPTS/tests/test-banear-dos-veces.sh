#!/usr/bin/env bash
# test-banear-dos-veces.sh — banear una IP que ya esta baneada.
#
#   bash "TELEGRAM SCRIPTS/tests/test-banear-dos-veces.sh"
#
# Pasa mas de lo que parece: el aviso de una IP sigue en el chat despues de
# banearla, con su boton debajo, y ese boton se puede pulsar. Antes eso
# devolvia un error ---nftables se queja al anadir un elemento que ya existe,
# y con "set -e" tumbaba el guion--- y el boton se quedaba con un aviso de
# fallo en un caso que no es un fallo: el resultado que se buscaba ya esta.
#
# El `nft` de estas pruebas es de mentira: un fichero hace de set y se queja
# igual que el de verdad al meter algo repetido.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUION="$AQUI/../COWRIE/telegram-notification-ban"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SET="$TMP/set.txt"

cat > "$TMP/nft" <<EOF
#!/bin/bash
SET="$SET"
case "\$1" in
  list) [ -s "\$SET" ] && cat "\$SET"; exit 0 ;;
  add)  ip=\$(printf '%s' "\$*" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        grep -qF "\$ip" "\$SET" 2>/dev/null && { echo "Error: File exists" >&2; exit 1; }
        echo "  \$ip comment \"sin-comentario\"" >> "\$SET"; exit 0 ;;
  -f)   read -r linea
        ip=\$(printf '%s' "\$linea" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        com=\$(printf '%s' "\$linea" | sed -n 's/.*comment "\([^"]*\)".*/\1/p')
        [ -n "\$ip" ] || exit 0
        grep -qF "\$ip" "\$SET" 2>/dev/null && { echo "Error: File exists" >&2; exit 1; }
        echo "  \$ip comment \"\$com\"" >> "\$SET"; exit 0 ;;
esac
exit 0
EOF
printf '#!/bin/bash\nexit 0\n' > "$TMP/logger"
chmod +x "$TMP/nft" "$TMP/logger"

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

banear() {   # $1 = ip, $2 = auto|manual
    ( PATH="$TMP:$PATH"; NFT="$TMP/nft"; export NFT
      bash "$GUION" "$1" "${2:-}" 2>&1 )
}

: > "$SET"

echo
echo "La primera vez, se banea"
salida=$(banear 1.2.3.4 auto); rc=$?
comprueba "sale bien" "0" "$rc"
comprueba "y queda en el set" "1" "$(grep -c '1.2.3.4' "$SET")"
comprueba "con la etiqueta de automatico" "1" \
    "$(grep -c 'AUTOMATICO' "$SET")"

echo
echo "La segunda no es un fallo"
antes=$(md5sum < "$SET")
salida=$(banear 1.2.3.4 manual); rc=$?
comprueba "sale bien igualmente" "0" "$rc"
comprueba "y lo dice" "1" "$(printf '%s' "$salida" | grep -c 'ya estaba')"
# NO SE REESCRIBE EL COMENTARIO. Si una IP se baneo sola y luego alguien
# pulsa el boton, sigue siendo un baneo automatico: lo que cuenta es de donde
# salio, no quien lo repitio.
comprueba "sin tocar el set" "$antes" "$(md5sum < "$SET")"
comprueba "y sigue constando como automatica" "1" \
    "$(grep -c 'AUTOMATICO' "$SET")"

echo
echo "Y otra IP distinta se banea con normalidad"
salida=$(banear 5.6.7.8 manual); rc=$?
comprueba "sale bien" "0" "$rc"
comprueba "con la etiqueta de manual" "1" \
    "$(grep -c 'MANUAL DESDE TELEGRAM' "$SET")"

echo
echo "Lo que sigue sin admitir"
salida=$(banear "no-soy-una-ip" manual); rc=$?
comprueba "algo que no es una IP se rechaza" "1" \
    "$( [ "$rc" -ne 0 ] && echo 1 || echo 0 )"
# El segundo argumento acaba dentro de un comment que nft REPARSEA como
# script: solo se admiten dos valores, y nada mas pasa de aqui.
salida=$(banear 9.9.9.9 'x"; add rule inet dirtyland input accept #'); rc=$?
comprueba "un origen inventado se rechaza" "2" "$rc"
comprueba "y esa IP no llega al set" "0" "$(grep -c '9.9.9.9' "$SET")"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
