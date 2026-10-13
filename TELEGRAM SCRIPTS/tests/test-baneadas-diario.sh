#!/usr/bin/env bash
# test-baneadas-diario.sh — las IPs bloqueadas, y de donde vino cada baneo.
#
#   bash "TELEGRAM SCRIPTS/tests/test-baneadas-diario.sh"
#
# El `nft` de estas pruebas es de mentira y devuelve la forma REAL de un
# "nft list set": elementos separados por comas, repartidos en varias lineas
# y con su comentario detras. Todo lo demas es el guion de verdad.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUION="$AQUI/../baneadas-diario.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# El aviso, en vez de irse a Telegram, se queda en un fichero.
printf '#!/bin/bash\nshift\nprintf "%%s\\n" "$1"\n' > "$TMP/alerta.sh"
# Bandera de mentira: la de verdad necesita las tablas, que no viajan en el
# repositorio.
printf 'pais_de() { printf "  [%%s]" "$1"; }\n' > "$TMP/paises.sh"
chmod +x "$TMP/alerta.sh"

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

# $1 = contenido de ban4 (lineas de elementos, ya con su comentario)
nft_con() {
    cat > "$TMP/nft" <<EOF
#!/bin/bash
for a in "\$@"; do ultimo="\$a"; done
[ "\$ultimo" = ban4 ] || exit 1
cat <<'FIN'
table inet dirtyland {
	set ban4 {
		type ipv4_addr
		flags interval
		elements = { $1 }
	}
}
FIN
EOF
    chmod +x "$TMP/nft"
}

correr() {
    ( ALERT="$TMP/alerta.sh"; NFT="$TMP/nft"; LIB_PAISES="$TMP/paises.sh"
      export ALERT NFT LIB_PAISES; bash "$GUION" 2>&1 )
}

echo
echo "De donde vino cada baneo"
# El automatico y el del boton escriben comentarios distintos desde el
# 2026-08-29. Antes escribian el MISMO, asi que de aquellos no se sabe: ese es
# el tercer grupo, y no es un adorno --- meterlos en "a mano" seria afirmar
# algo que no consta.
nft_con '1.1.1.1 comment "IP BANEADA COWRIE AUTOMATICO",
			     2.2.2.2 comment "IP BANEADA COWRIE MANUAL DESDE TELEGRAM",
			     3.3.3.3 comment "IP BANEADA COWRIE POR ADMIN DESDE TELEGRAM"'
salida=$(correr)
comprueba "el automatico va con los automaticos" "1" \
    "$(printf '%s' "$salida" | grep -A2 'Automaticas' | grep -c '1.1.1.1')"
comprueba "el del boton va con los de a mano" "1" \
    "$(printf '%s' "$salida" | grep -A2 'A mano' | grep -c '2.2.2.2')"
# La etiqueta vieja ya no la escribe nadie, asi que el grupo se vacia solo
# segun se desbanean o caducan.
comprueba "y la etiqueta vieja va a origen desconocido" "1" \
    "$(printf '%s' "$salida" | grep -A2 'origen desconocido' | grep -c '3.3.3.3')"
comprueba "se cuentan las tres" "1" \
    "$(printf '%s' "$salida" | grep -c 'baneadas: 3')"

echo
echo "Lo que se pierde si no se lee bien la salida de nft"
# LA ULTIMA LINEA DE UN SET NO ACABA EN SALTO DE LINEA, asi que "read" devuelve
# falso y el cuerpo del bucle no se ejecuta. Se perdia UN elemento de cada
# set, callando: el aviso salia bien formado, solo que con una IP menos.
nft_con '9.9.9.1 comment "IP BANEADA COWRIE AUTOMATICO",
			     9.9.9.2 comment "IP BANEADA COWRIE AUTOMATICO",
			     9.9.9.3 comment "IP BANEADA COWRIE AUTOMATICO"'
salida=$(correr)
comprueba "no se pierde la ultima del set" "1" \
    "$(printf '%s' "$salida" | grep -c '9.9.9.3')"
comprueba "y el total cuadra" "1" "$(printf '%s' "$salida" | grep -c 'baneadas: 3')"

echo
echo "Un set sin comentarios tampoco rompe nada"
# Las versiones de nftables anteriores a la 0.9.7 no admiten comentarios en
# los elementos, y el baneador lo contempla: entonces no se sabe el origen.
nft_con '8.8.8.8'
salida=$(correr)
comprueba "la IP sale igual" "1" "$(printf '%s' "$salida" | grep -c '8.8.8.8')"
comprueba "como de origen desconocido" "1" \
    "$(printf '%s' "$salida" | grep -c 'origen desconocido')"

echo
echo "Ninguna tambien se manda"
# Un canal que solo habla cuando hay algo no se distingue de uno averiado: si
# un dia no llega nada, no se sabe si es que no hubo baneos o es que el aviso
# dejo de funcionar.
printf '#!/bin/bash\nexit 1\n' > "$TMP/nft"; chmod +x "$TMP/nft"
salida=$(correr)
comprueba "se envia el aviso igualmente" "1" \
    "$(printf '%s' "$salida" | grep -c 'IP.s baneadas: 0')"
comprueba "diciendo que ninguna" "1" "$(printf '%s' "$salida" | grep -c 'ninguna')"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
