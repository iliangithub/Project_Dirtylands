#!/usr/bin/env bash
# test-proxy-watch.sh --- el vigilante de los proxys de acceso, sin red.
#
#   bash "TELEGRAM SCRIPTS/tests/test-proxy-watch.sh"
#
# La API de Mullvad se sustituye por un doble que devuelve el JSON que le
# pongamos, y send-alert.sh por otro que escribe a un fichero. Todo lo demas
# es el guion de verdad.
#
# Lo que se comprueba:
#   - Que avisa en la transicion y SOLO en la transicion (un aviso que se
#     repite cada media hora se acaba silenciando).
#   - Que distingue "dado de baja" (active:false) de "fuera de la lista": el
#     segundo obliga a elegir otro relay y tocar tres ficheros.
#   - Que la primera pasada calla lo que ya esta bien pero avisa de lo malo.
#   - Que un fallo de la API no se confunde con una caida.
#   - Que la lista sale de proxys.conf, con comentarios y vacias fuera.
#   - Que la BANDERA sale del country_code de la API y vale para cualquier
#     pais, y que sin jq el plan B da el mismo resultado (regresion 2026-09-10).
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUION="$AQUI/../proxy-watch.sh"
OK=0; MAL=0

comprueba() {
    if [ "$2" = "$3" ]; then OK=$((OK+1)); else
        MAL=$((MAL+1)); printf '  FALLO: %s\n    esperado [%s]  obtenido [%s]\n' "$1" "$2" "$3"
    fi
}
contiene() {
    if grep -qF "$2" "$3" 2>/dev/null; then OK=$((OK+1)); else
        MAL=$((MAL+1)); printf '  FALLO: %s\n    no aparece [%s] en %s\n' "$1" "$2" "$3"
        sed 's/^/      /' "$3" 2>/dev/null | head -30
    fi
}

BASE=$(mktemp -d); trap 'rm -rf "$BASE"' EXIT
BIN="$BASE/bin"; mkdir -p "$BIN"

cat > "$BIN/curl" <<'SH'
#!/usr/bin/env bash
[ "${FAKE_JSON_FAIL:-0}" = "1" ] && exit 7
dest=""
while [ $# -gt 0 ]; do case "$1" in -o) dest="$2"; shift 2;; *) shift;; esac; done
[ -n "$dest" ] && printf '%s' "$FAKE_JSON" > "$dest"
exit 0
SH
cat > "$BIN/send-alert" <<'SH'
#!/usr/bin/env bash
printf 'ALERT %s\n' "$*" >> "$FAKE_ALERT_LOG"
SH
chmod +x "$BIN"/*

CONF="$BASE/proxys.conf"
cat > "$CONF" <<'EOF'
# comentario
ch-zrh-wg-socks5-002.relays.mullvad.net

se-got-wg-socks5-001.relays.mullvad.net   # inline
nl-ams-wg-socks5-001.relays.mullvad.net
EOF

# JSON con el MISMO orden de campos que el de Mullvad: country_code y active
# van ANTES de socks_name. Si se pusieran despues, el plan B sin jq pasaria
# aqui y fallaria en produccion.
json() {   # json  ch se nl   con A=activo I=inactivo X=fuera de la lista
    local out="["
    obj() {   # obj  ACTIVE cc nombre socks
        printf '{"hostname":"x","country_code":"%s","country_name":"%s","active":%s,"status_messages":[],"socks_name":"%s","socks_port":1080}' "$2" "$3" "$1" "$4"
    }
    act() { case "$1" in A) echo true;; I) echo false;; esac; }
    [ "$1" != X ] && out+="$(obj "$(act "$1")" ch Switzerland ch-zrh-wg-socks5-002.relays.mullvad.net),"
    [ "$2" != X ] && out+="$(obj "$(act "$2")" se Sweden se-got-wg-socks5-001.relays.mullvad.net),"
    [ "$3" != X ] && out+="$(obj "$(act "$3")" nl Netherlands nl-ams-wg-socks5-001.relays.mullvad.net),"
    out+="$(obj true xx Otro otro-relay-000.relays.mullvad.net)]"
    printf '%s' "$out"
}

correr() {
    PROXY_WATCH_ALERT="$BIN/send-alert" PROXY_WATCH_CONF="$CONF" \
    PROXY_WATCH_STATE_DIR="$D" PROXY_WATCH_API="http://x/relays" \
    PROXY_WATCH_NOMBRES="$AQUI/../geoip/nombres.txt" \
    FAKE_ALERT_LOG="$D/alert" PATH="$BIN:$PATH" \
    bash "$GUION" "$@"
}
caja() { D=$(mktemp -d "$BASE/d.XXXX"); : > "$D/alert"; }
ST="proxy-watch.state"
CH="\xf0\x9f\x87\xa8\xf0\x9f\x87\xad"   # 🇨🇭
NL="\xf0\x9f\x87\xb3\xf0\x9f\x87\xb1"   # 🇳🇱

# ======================================================================
echo "1. proxys.conf: comentarios y vacías fuera, tres relays dentro"
caja
salida=$(FAKE_JSON="$(json A A A)" correr --test)
comprueba "tres líneas de estado" 3 "$(printf '%s\n' "$salida" | grep -c '^estado|')"
comprueba "activos = 3" "activos|3" "$(printf '%s\n' "$salida" | grep '^activos|')"
comprueba "guarda el country_code" "estado|nl-ams-wg-socks5-001.relays.mullvad.net|activo|nl" \
    "$(printf '%s\n' "$salida" | grep '^estado|nl-')"

echo "2. Primera pasada con los tres activos: ni un aviso"
caja
FAKE_JSON="$(json A A A)" correr >/dev/null
comprueba "sin avisos" 0 "$(grep -c ALERT "$D/alert")"
contiene "pero fija la línea base" "estado|ch-zrh-wg-socks5-002.relays.mullvad.net|activo|ch" "$D/$ST"

echo "3. Cae Amsterdam: un aviso con su bandera"
FAKE_JSON="$(json A A I)" correr >/dev/null
comprueba "un aviso" 1 "$(grep -c ALERT "$D/alert")"
contiene "nombra el relay"      "nl-ams-wg-socks5-001" "$D/alert"
contiene "dice inactivo"        "inactivo" "$D/alert"
printf "$NL" > "$D/nlflag"
contiene "lleva la bandera de Países Bajos" "$(cat "$D/nlflag")" "$D/alert"
echo "   ...repetir no vuelve a avisar"
: > "$D/alert"
FAKE_JSON="$(json A A I)" correr >/dev/null
comprueba "silencio" 0 "$(grep -c ALERT "$D/alert")"

echo "4. Vuelve Amsterdam: aviso de recuperación con los relays en pie"
: > "$D/alert"
FAKE_JSON="$(json A A A)" correr >/dev/null
comprueba "un aviso" 1 "$(grep -c ALERT "$D/alert")"
contiene "de recuperación" "recuperado" "$D/alert"
contiene "lista los relays en pie" "Relays en pie" "$D/alert"

echo "5. Un relay FUERA de la lista: aviso distinto, manda tocar 3 ficheros"
: > "$D/alert"
FAKE_JSON="$(json X A A)" correr >/dev/null
contiene "habla de fuera de la lista" "fuera de la lista" "$D/alert"
contiene "manda tocar proxys.conf"    "proxys.conf" "$D/alert"
contiene "y el cortafuegos"           "ip saddr" "$D/alert"
contiene "estado ausente"             "|ausente|" "$D/$ST"
printf "$CH" > "$D/chflag"
contiene "conserva la última bandera conocida" "$(cat "$D/chflag")" "$D/alert"

echo "6. Primera pasada con uno YA caído: sí avisa (estado inicial)"
caja
FAKE_JSON="$(json A A I)" correr >/dev/null
comprueba "un aviso" 1 "$(grep -c ALERT "$D/alert")"
contiene "marcado como inicial" "estado inicial" "$D/alert"

echo "7. Caen los tres: aviso de gravedad SIN ACCESO con las tres banderas"
caja
FAKE_JSON="$(json A A A)" correr >/dev/null
: > "$D/alert"
FAKE_JSON="$(json I I I)" correr >/dev/null
contiene "grita SIN ACCESO" "SIN ACCESO" "$D/alert"
contiene "menciona la consola del proveedor" "proveedor" "$D/alert"
contiene "detalla cada relay" "nl-ams-wg-socks5-001</code> — inactivo" "$D/alert"

echo "8. Baja a un solo activo: aviso 'sin respaldo'"
caja
FAKE_JSON="$(json A A A)" correr >/dev/null
: > "$D/alert"
FAKE_JSON="$(json A I I)" correr >/dev/null
contiene "avisa de sin respaldo" "sin respaldo" "$D/alert"

echo "9. Falla la API: ni avisa ni toca el estado"
caja
FAKE_JSON="$(json A A A)" correr >/dev/null
antes=$(md5sum < "$D/$ST")
: > "$D/alert"
FAKE_JSON_FAIL=1 FAKE_JSON="" correr >/dev/null; rc=$?
comprueba "sale sin error" 0 "$rc"
comprueba "sin avisos"     0 "$(grep -c ALERT "$D/alert")"
comprueba "estado intacto" "$antes" "$(md5sum < "$D/$ST")"

echo "10. --test no escribe el estado ni avisa"
caja
FAKE_JSON="$(json A I A)" correr --test >/dev/null
comprueba "no crea state" "no" "$([ -e "$D/$ST" ] && echo si || echo no)"
comprueba "no avisa"      0    "$(grep -c ALERT "$D/alert")"

echo "11. SIN jq: el plan B da el mismo resultado y la misma bandera"
cat > "$BIN/jq" <<'SH'
#!/usr/bin/env bash
exit 1
SH
chmod +x "$BIN/jq"
caja
salida=$(FAKE_JSON="$(json A A I)" correr --test)
comprueba "ch activo sin jq"   "estado|ch-zrh-wg-socks5-002.relays.mullvad.net|activo|ch"   "$(printf '%s\n' "$salida" | grep '^estado|ch-')"
comprueba "se activo sin jq"   "estado|se-got-wg-socks5-001.relays.mullvad.net|activo|se"   "$(printf '%s\n' "$salida" | grep '^estado|se-')"
comprueba "nl inactivo sin jq" "estado|nl-ams-wg-socks5-001.relays.mullvad.net|inactivo|nl" "$(printf '%s\n' "$salida" | grep '^estado|nl-')"
comprueba "activos = 2 sin jq" "activos|2" "$(printf '%s\n' "$salida" | grep '^activos|')"
rm -f "$BIN/jq"

echo "12. SIN jq y con el JSON CON FORMATO: espacios y saltos no deciden nada"
# La API puede devolver el JSON compacto o con formato; las dos cosas son
# JSON igual de valido y no es cosa nuestra cual manda hoy. El plan B
# comparaba contra '"active":true' SIN espacio: con formato no casaba
# ninguna rama y los tres relays salian "ausente", o sea tres avisos de
# "fuera de la lista" y un SIN ACCESO, los cuatro falsos. Y encima tapaban
# una caida de verdad, porque el estado quedaba igual pasara lo que pasara.
#
# La prueba 11 no lo cazaba porque su JSON es compacto, como el de la API
# de hoy. El ensayo de probar-avisos.sh escribe el suyo con espacios, y por
# eso sus cuatro pasos de proxy llevaban tiempo ensenando el aviso
# equivocado sin que la suite dijera nada.
cat > "$BIN/jq" <<'SH'
#!/usr/bin/env bash
exit 1
SH
chmod +x "$BIN/jq"
caja
# El MISMO contenido que la prueba 11 (ch y se activos, nl no), pero
# escrito como lo escribiria un servidor que formatea la respuesta: un
# espacio detras de cada dos puntos y un objeto por varias lineas. Va a
# pelo y no generado, para que se vea de un vistazo que es lo que se prueba.
cat > "$D/conformato.json" <<'EOF'
[
  {
    "hostname": "x",
    "country_code": "ch",
    "country_name": "Switzerland",
    "active": true,
    "status_messages": [],
    "socks_name": "ch-zrh-wg-socks5-002.relays.mullvad.net",
    "socks_port": 1080
  },
  {
    "hostname": "x",
    "country_code": "se",
    "country_name": "Sweden",
    "active": true,
    "status_messages": [],
    "socks_name": "se-got-wg-socks5-001.relays.mullvad.net",
    "socks_port": 1080
  },
  {
    "hostname": "x",
    "country_code": "nl",
    "country_name": "Netherlands",
    "active": false,
    "status_messages": [],
    "socks_name": "nl-ams-wg-socks5-001.relays.mullvad.net",
    "socks_port": 1080
  }
]
EOF
salida=$(FAKE_JSON="$(cat "$D/conformato.json")" correr --test)
comprueba "ch activo con formato"     "estado|ch-zrh-wg-socks5-002.relays.mullvad.net|activo|ch"     "$(grep '^estado|ch-' <<< "$salida")"
comprueba "nl inactivo con formato"     "estado|nl-ams-wg-socks5-001.relays.mullvad.net|inactivo|nl"     "$(grep '^estado|nl-' <<< "$salida")"
comprueba "activos = 2 con formato" "activos|2"     "$(grep '^activos|' <<< "$salida")"
comprueba "y ninguno sale ausente" 0     "$(grep -c '|ausente|' <<< "$salida")"
rm -f "$BIN/jq"

echo "13. País cualquiera: la bandera sale del country_code, no de una lista fija"
caja
cat > "$CONF" <<'EOF'
jp-tyo-wg-socks5-004.relays.mullvad.net
EOF
JP="\xf0\x9f\x87\xaf\xf0\x9f\x87\xb5"   # 🇯🇵
J='[{"country_code":"jp","country_name":"Japan","active":false,"status_messages":[],"socks_name":"jp-tyo-wg-socks5-004.relays.mullvad.net","socks_port":1080}]'
FAKE_JSON="$J" correr >/dev/null
printf "$JP" > "$D/jpflag"
contiene "bandera de Japón en el aviso" "$(cat "$D/jpflag")" "$D/alert"
contiene "y el nombre del país en español" "Japon" "$D/alert"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
