#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# lib-paises.sh --- la bandera y el pais de una IP, para pegarlo en un aviso.
#
#   . /opt/dirtyland/monitor/lib-paises.sh
#   pais_de 153.117.13.106      ->  "  🇵🇰 Pakistan"   (con dos espacios delante)
#   pais_de 192.168.1.1         ->  ""
#
# Se carga igual que lib-ips.sh y por la misma razon: la definicion vive en un
# solo sitio y los tres vigilantes la comparten, en vez de tres copias que
# acaban diciendo cosas distintas.
#
# QUIEN HACE EL TRABAJO es paises.py, que busca en una tabla en disco sacada
# de los ficheros publicos de los cinco RIR. No sale ni una peticion a la red
# ni se gasta cuota de ninguna API: por eso puede ir en cada aviso.
#
# QUE PAIS ES: el del REGISTRO del rango, no el de la maquina. Un atacante
# detras de un VPS holandes sale de Paises Bajos.
#
# SI ALGO FALTA, DEVUELVE VACIO. Esto es un adorno del mensaje; que no salga
# la bandera se nota poco, que no salga el aviso se nota mucho.

GEOIP_PAISES="${GEOIP_PAISES:-/opt/dirtyland/geoip/paises.py}"

pais_de() {
    local ip="${1:-}"
    [ -n "$ip" ] || return 0
    [ -r "$GEOIP_PAISES" ] || return 0
    local salida
    # El timeout no es paranoia: esto se llama desde el camino de un aviso, y
    # un python colgado dejaria el aviso sin enviar. Mejor sin bandera.
    salida=$(timeout 5 python3 "$GEOIP_PAISES" "$ip" 2>/dev/null) || return 0
    # La salida es "IP <bandera> <Pais>"; nos quedamos con lo de despues.
    salida="${salida#"$ip"}"
    salida="${salida# }"
    [ -n "$salida" ] && printf '  %s' "$salida"
    return 0
}
