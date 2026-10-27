#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# baneadas-diario.sh --- las IPs bloqueadas en el cortafuegos, una vez al dia.
#
# Va como MENSAJE APARTE del resumen diario, aunque salga a la misma hora: son
# dos cosas distintas y mezclarlas hace que ninguna se lea. El resumen dice
# como esta el sistema; esto dice a quien se le ha cerrado la puerta.
#
# DE DONDE SALE: de la tabla de nftables, no de un registro nuestro. Es la
# unica fuente que dice lo que de verdad esta bloqueando la maquina AHORA. Un
# fichero de anotaciones puede quedarse desfasado ---si alguien desbanea a
# mano con "nft delete element", el fichero no se entera--- y entonces el
# aviso diario contaria como bloqueado a quien ya no lo esta.
#
# AUTOMATICO O MANUAL sale del comentario que dejo el baneador al ponerla.
# Los baneos anteriores al 2026-08-29 llevan todos el comentario de "por
# admin" porque hasta entonces los dos caminos escribian el mismo: no es que
# no hubiera automaticos, es que no se distinguian.
# ---------------------------------------------------------------------------
set -uo pipefail

ALERT="${ALERT:-/opt/dirtyland/monitor/send-alert.sh}"
NFT="${NFT:-/usr/sbin/nft}"
TABLA="${TABLA:-inet dirtyland}"
SERVICIO="${SERVICIO:-nftables}"
MAQUINA="${MAQUINA:-Maquina VPS principal}"

# La bandera de cada IP, de la tabla local. Si falta, sale sin bandera y ya:
# esto es un adorno del mensaje, y quedarse sin el aviso por un adorno seria
# cambiar un problema pequeno por uno grande.
LIB_PAISES="${LIB_PAISES:-/opt/dirtyland/monitor/lib-paises.sh}"
if [ -r "$LIB_PAISES" ]; then
    # shellcheck source=/dev/null
    . "$LIB_PAISES"
else
    pais_de() { return 0; }
fi

NL=$'\n'
PROHIBIDO=$(printf '\360\237\232\253')

# Saca "IP<TAB>auto|manual" de un set de nftables.
#
# Los elementos vienen separados por comas y repartidos en varias lineas, con
# su comentario detras, asi que se aplana todo y se corta por comas. El
# comentario puede no estar: las versiones de nftables anteriores a la 0.9.7
# no lo admiten, y el baneador lo contempla.
elementos() {   # $1 = ban4 | ban6
    "$NFT" list set $TABLA "$1" 2>/dev/null \
        | tr '\n' ' ' \
        | sed -n 's/.*elements = {\(.*\)}.*/\1/p' \
        | tr ',' '\n' \
        | while IFS= read -r trozo || [ -n "$trozo" ]; do
            ip=$(printf '%s' "$trozo" | awk '{print $1}')
            [ -n "$ip" ] || continue
            # TRES GRUPOS, y el tercero no es un adorno. Hasta el
            # 2026-08-29 los dos caminos escribian el mismo comentario ---"POR
            # ADMIN DESDE TELEGRAM"--- asi que de esos baneos NO SE SABE de
            # donde vinieron. Meterlos en "a mano" seria afirmar algo que no
            # consta: se comprobo con el log del contenedor y solo llega a un
            # dia atras, asi que once de los catorce se quedaron sin saber.
            #
            # Se reconocen por el texto viejo, que ya no lo escribe nadie: el
            # grupo se vacia solo segun se desbanean o caducan.
            case "$trozo" in
                *AUTOMATICO*)     printf '%s\tauto\n' "$ip" ;;
                *"MANUAL DESDE"*) printf '%s\tmanual\n' "$ip" ;;
                *)                printf '%s\tdesconocido\n' "$ip" ;;
            esac
        done
}

autos="" ; manuales="" ; viejas="" ; n=0
# El "|| [ -n ... ]" no es un adorno: la ultima linea que sale del corte por
# comas NO acaba en salto de linea, y sin eso "read" devuelve falso y el
# cuerpo no se ejecuta. Se perdia UN elemento de cada set, callando ---el
# aviso salia bien formado, solo que con una IP menos---.
while IFS=$'\t' read -r ip origen || [ -n "${ip:-}" ]; do
    [ -n "${ip:-}" ] || continue
    n=$((n + 1))
    linea="  <code>${ip}</code>$(pais_de "$ip")${NL}"
    case "$origen" in
        auto)   autos+="$linea" ;;
        manual) manuales+="$linea" ;;
        *)      viejas+="$linea" ;;
    esac
done < <(elementos ban4; elementos ban6)

# NINGUNA ES UNA RESPUESTA, y se manda igual. Un canal que solo habla cuando
# hay algo no se distingue de un canal averiado: si un dia no llega nada, no
# se sabe si es que no hay baneos o es que el aviso dejo de funcionar.
cuerpo=""
if [ -n "$autos" ]; then
    cuerpo+="${NL}<b>Automaticas</b>${NL}${autos}"
fi
if [ -n "$manuales" ]; then
    cuerpo+="${NL}<b>A mano, desde Telegram</b>${NL}${manuales}"
fi
if [ -n "$viejas" ]; then
    cuerpo+="${NL}<b>De origen desconocido</b> <i>(anteriores al 29/08, cuando"
    cuerpo+=" los dos caminos escribian la misma etiqueta)</i>${NL}${viejas}"
fi
[ "$n" -eq 0 ] && cuerpo="${NL}  (ninguna)"

"$ALERT" --siempre "<b>[${SERVICIO}] ${MAQUINA}</b>
<b>${PROHIBIDO} IP's baneadas: ${n}</b>
${cuerpo}"
