# shellcheck shell=bash
# lib-ips.sh — quien somos nosotros. Se SOURCEA, no se ejecuta.
#
#   . /opt/dirtyland/monitor/lib-ips.sh
#
# La lista de "esto somos nosotros" vive en UN solo sitio: la [blocklist] del
# config.ini del reporter. Ahi estan las IP publicas de la VPS y todos los
# nodos de salida del VPN desde los que se administra, y es la que ya se
# mantiene al dia porque de ella depende no denunciarnos a nosotros mismos.
#
# Este fichero existe porque esa pregunta --- "esta IP es nuestra?" --- la
# hacen tres programas distintos: ssh-watch.sh para marcar los accesos
# propios, daily-digest.sh para el resumen y dionaea-watch.sh para no avisar
# de nuestras propias comprobaciones. Cada uno tenia su copia escrita a mano,
# y las tres estaban desactualizadas de formas distintas. Una copia por
# programa es una copia que algun dia dice otra cosa.

CFG_REPORTER="${CFG_REPORTER:-/opt/dirtyland/platform-reporter/config.ini}"

# Red de seguridad para el caso de que el reporter no este instalado todavia.
# Lo normal es dejarlo vacio y que todo salga del config.ini.
IPS_PROPIAS_EXTRA="${IPS_PROPIAS_EXTRA:-}"

# es_propia IP  ->  codigo 0 si es nuestra, 1 si no.
#
# La comparacion la hace Python porque la lista admite rangos CIDR, y comparar
# redes a mano en shell es la clase de codigo que parece funcionar hasta el dia
# que no. Solo devuelve un codigo de salida: nada de imprimir, para que no
# dependa del locale con el que arranque un servicio de systemd.
#
# Ante cualquier duda --- config ilegible, IP mal formada, Python ausente ---
# responde "no es nuestra". Es el lado seguro: una alerta de mas nunca hace
# dano, una de menos si.
es_propia() {
    local ip="${1:-}"
    [ -z "$ip" ] && return 1
    python3 -c '
import configparser, ipaddress, re, sys

def trocear(v):
    return [x for x in re.split(r"[,\s]+", v or "") if x and not x.startswith("<")]

ips, redes = [], []
try:
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cp.read(sys.argv[2], encoding="utf-8")
    ips = trocear(cp.get("blocklist", "ips", fallback=""))
    redes = trocear(cp.get("blocklist", "cidrs", fallback=""))
except Exception:
    pass
ips += trocear(sys.argv[3])

try:
    addr = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)

for uno in ips:
    try:
        if addr == ipaddress.ip_address(uno):
            sys.exit(0)
    except ValueError:
        continue
for red in redes:
    try:
        if addr in ipaddress.ip_network(red, strict=False):
            sys.exit(0)
    except ValueError:
        continue
sys.exit(1)
' "$ip" "$CFG_REPORTER" "$IPS_PROPIAS_EXTRA" 2>/dev/null
}

# marca_propia IP  ->  imprime " (nuestro)" con su emoji, o nada.
#
# El emoji lo escribe bash, no Python, y eso no es casual: un servicio de
# systemd arranca sin locale y Python escribiria en ASCII, con lo que el
# print reventaria con UnicodeEncodeError y la marca desapareceria en
# silencio. Funcionaria a mano y fallaria como servicio, que es la peor
# combinacion para depurar.
marca_propia() {
    if es_propia "${1:-}"; then
        printf ' (nuestro \360\237\230\207)'
    fi
    return 0
}
