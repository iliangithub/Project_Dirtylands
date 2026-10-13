#!/usr/bin/env bash
# test-lib-telegram.sh — pruebas del troceo de mensajes de Telegram.
#
#   bash "TELEGRAM SCRIPTS/tests/test-lib-telegram.sh"
#
# No toca la red ni necesita claves: comprueba las cuentas y el reparto, que
# es donde estaba el fallo. Se puede correr en el portatil y en la VPS.
#
# La prueba que da sentido a todo el fichero es la del 2026-08-20: se
# reconstruye la alerta real que llego rota y se comprueba que con el formato
# viejo se pasaba de 100 entities, que con el nuevo no, y que en cualquier
# caso el troceo la deja dentro de limites sin perder ni una linea.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
. "$AQUI/../lib-telegram.sh"

OK=0; MAL=0

comprueba() {
    local que="$1" esperado="$2" obtenido="$3"
    if [ "$esperado" = "$obtenido" ]; then
        OK=$((OK + 1))
        printf '  ok    %s\n' "$que"
    else
        MAL=$((MAL + 1))
        printf '  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>\n' \
            "$que" "$esperado" "$obtenido"
    fi
}

# --- Las cuentas -----------------------------------------------------------
echo
echo "Contar entities y longitud"

comprueba "sin etiquetas" "0" "$(tg_entidades 'Source: 1.2.3.4')"
comprueba "un <code>" "1" "$(tg_entidades 'IP: <code>1.2.3.4</code>')"
comprueba "un <a href> cuenta 1, no 2" "1" \
    "$(tg_entidades '<a href="https://x/a?b=1&amp;c=2">texto</a>')"
comprueba "linea completa de Dionaea" "2" \
    "$(tg_entidades 'Source: <code>1.2.3.4</code>  SMB (445) ×2  ts  <a href="https://www.abuseipdb.com/check/1.2.3.4">AbuseIPDB</a>')"

comprueba "longitud sin etiquetas" "7" "$(tg_longitud '1.2.3.4')"
comprueba "las etiquetas no cuentan" "11" "$(tg_longitud 'IP: <code>1.2.3.4</code>')"
comprueba "el href tampoco cuenta" "5" \
    "$(tg_longitud '<a href="https://www.abuseipdb.com/check/1.2.3.4">texto</a>')"
# Un emoji son 4 bytes en UTF-8 y 2 unidades para Telegram: medir en bytes se
# pasa de prudente, que es justo lo que se busca.
comprueba "un emoji cuenta 4 (bytes), nunca menos de los 2 reales" "4" \
    "$(tg_longitud '😇')"

# --- Lo que escribe el atacante --------------------------------------------
echo
echo "Escapado y recorte de texto ajeno"

comprueba "un < se escapa" "a&lt;b" "$(tg_escapar 'a<b')"
comprueba "un > se escapa" "a&gt;b" "$(tg_escapar 'a>b')"
comprueba "el & se escapa una sola vez, no dos" "a&amp;lt;b" "$(tg_escapar 'a&lt;b')"
comprueba "una URL normal no se estropea" \
    "smb://46.46.121.73/transaction/\\PIPE\\" \
    "$(tg_escapar 'smb://46.46.121.73/transaction/\PIPE\')"
comprueba "una URL con parametros queda valida" \
    "http://x/a?b=1&amp;c=2" "$(tg_escapar 'http://x/a?b=1&c=2')"

comprueba "lo corto no se recorta" "hola" "$(tg_recortar 'hola' 10)"
comprueba "lo largo se recorta y se avisa" "abcde…" "$(tg_recortar 'abcdefghij' 5)"

# El ataque concreto: una URL de descarga con una etiqueta dentro. Sin
# escapar, Telegram contesta 400 y el aviso NO llega --- y el vigilante ya ha
# marcado el evento como visto, asi que no vuelve. Es una forma barata de
# dejarnos ciegos justo cuando hay algo que ver.
malicioso='http://x/<b>?a=1&b=2'
linea="Origin: <code>$(tg_escapar "$malicioso")</code>"
comprueba "una URL con etiquetas no abre ninguna entity de mas" "1" \
    "$(tg_entidades "$linea")"
comprueba "y no deja ningun < suelto fuera de las etiquetas nuestras" "si" \
    "$( case "$(printf '%s' "$linea" | sed 's/<\/\?code>//g')" in *'<'*) echo no;; *) echo si;; esac )"

# Recortar va ANTES de escapar: al reves se podria partir un "&amp;" y dejar
# un "&am" suelto, que es justo lo que rompe el parseo.
comprueba "recortar y luego escapar no parte ninguna entidad" "si" \
    "$( case "$(tg_escapar "$(tg_recortar 'aaaa&bbbb' 5)")" in *'&am'*'&'*|*'&amp;'*) echo si;; *'&'*) echo no;; *) echo si;; esac )"

# --- Reconstruccion de la alerta que llego rota ----------------------------
echo
echo "La alerta del 2026-08-20 (33 IPs de un barrido a /24)"

IPS=()
for n in 125 126 127 128 129 130 131 132 133 135 137 138 140 143 144 146 147 149; do
    IPS+=("104.152.52.$n")
done
for n in 200 202 203 204 205 206 207 208 209 210 211 212 213 214; do
    IPS+=("104.152.52.$n")
done
IPS+=("114.4.240.82")
MD5=1c7eb62ee673a66fdb7f2db820875e34

CABECERA="<strong>[Dionaea]</strong>
Time: <code>2026-08-20 03:30:05 UTC</code>"

# Formato VIEJO: <code> tambien en la hora, y una lista aparte de enlaces.
viejo="<u>Nuevas conexiones de ataque</u>"
for ip in "${IPS[@]}"; do
    viejo+="
Source: <code>${ip}</code>  SMB (445) ×2  <code>2026-08-20 03:25:53 UTC</code>"
done
for ip in "${IPS[@]}"; do
    viejo+="
<a href=\"https://www.abuseipdb.com/check/${ip}\">${ip} en AbuseIPDB</a>"
done
viejo+="
<u>Malware capturado</u>
MD5: <code>${MD5}</code>  desde <code>190.13.177.114</code>
<a href=\"https://www.virustotal.com/gui/file/${MD5}\">Ver hash en VirusTotal</a>"

# Formato NUEVO: dos entities por linea, sin lista repetida.
nuevo="<u>Nuevas conexiones de ataque</u>"
for ip in "${IPS[@]}"; do
    nuevo+="
Source: <code>${ip}</code>  SMB (445) ×2  2026-08-20 03:25:53 UTC  <a href=\"https://www.abuseipdb.com/check/${ip}\">AbuseIPDB</a>"
done
nuevo+="
<u>Malware capturado</u>
MD5: <code>${MD5}</code>  desde <code>190.13.177.114</code>
<a href=\"https://www.virustotal.com/gui/file/${MD5}\">Ver hash en VirusTotal</a>"

ent_viejo=$(( $(tg_entidades "$CABECERA") + $(tg_entidades "$viejo") ))
ent_nuevo=$(( $(tg_entidades "$CABECERA") + $(tg_entidades "$nuevo") ))

comprueba "el formato viejo llegaba a 106 entities (limite 100)" "106" "$ent_viejo"
comprueba "el nuevo se queda en 73" "73" "$ent_nuevo"
# El texto SIEMPRE cabia: por eso Telegram no protesto y el mensaje llego.
comprueba "el texto renderizado cabia de sobra (<=4096)" "si" \
    "$( [ "$(tg_longitud "$viejo")" -le 4096 ] && echo si || echo no )"

# --- El troceo -------------------------------------------------------------
echo
echo "Troceo"

# Comprueba que ningun trozo se pasa, contando la cabecera que se le repite.
revisa_trozos() {
    local etiqueta="$1" cab="$2"
    local ec lc i=0 e l abre cierra malos=0 desbalance=0
    ec=$(tg_entidades "$cab"); lc=$(tg_longitud "$cab")
    for t in "${TG_TROZOS[@]}"; do
        i=$((i + 1))
        e=$(( ec + $(tg_entidades "$t") ))
        l=$(( lc + $(tg_longitud "$t") ))
        [ "$e" -gt 100 ] && malos=$((malos + 1))
        [ "$l" -gt 4096 ] && malos=$((malos + 1))
        # HTML cerrado en cada trozo: si el corte partiera una etiqueta,
        # Telegram devolveria 400 y se perderia el aviso entero.
        #
        # "<[a-z]" solo casa aperturas: en "</a>" al "<" le sigue una barra,
        # que no esta en el rango. Asi que aperturas y cierres tienen que
        # salir iguales, uno a uno.
        abre=$(printf '%s' "$t" | grep -o '<[a-z]' | wc -l | tr -d '[:space:]')
        cierra=$(printf '%s' "$t" | grep -o '</' | wc -l | tr -d '[:space:]')
        [ "$abre" != "$cierra" ] && desbalance=$((desbalance + 1))
    done
    comprueba "$etiqueta: ningun trozo se pasa de los limites" "0" "$malos"
    comprueba "$etiqueta: todos los trozos con el HTML cerrado" "0" "$desbalance"
}

tg_trocear "$CABECERA" "$nuevo"
comprueba "el formato nuevo cabe en un solo mensaje" "1" "${#TG_TROZOS[@]}"
revisa_trozos "nuevo" "$CABECERA"

tg_trocear "$CABECERA" "$viejo"
comprueba "el formato viejo se reparte en varios" "si" \
    "$( [ "${#TG_TROZOS[@]}" -ge 2 ] && echo si || echo no )"
revisa_trozos "viejo" "$CABECERA"

# Nada se pierde por el camino: los trozos, unidos, son el cuerpo original.
unido=$(printf '%s\n' "${TG_TROZOS[@]}")
comprueba "no se pierde ni se duplica ninguna linea" \
    "$(printf '%s' "$viejo" | wc -l)" "$(printf '%s' "$unido" | wc -l)"
comprueba "las lineas son las mismas y en el mismo orden" "si" \
    "$( [ "$(printf '%s' "$unido")" = "$viejo" ] && echo si || echo no )"

# Un cuerpo corto no se toca.
tg_trocear "$CABECERA" "una linea"
comprueba "un cuerpo corto sale de una pieza" "1" "${#TG_TROZOS[@]}"
comprueba "y sale intacto" "una linea" "${TG_TROZOS[0]}"

# Una linea que por si sola no cabe sale igualmente: mas vale un mensaje que
# Telegram quiza rechace --- y eso se ve en el journal --- que un evento que
# nunca se reporta.
larga=$(printf 'x%.0s' $(seq 1 5000))
tg_trocear "$CABECERA" "$larga"
comprueba "una linea gigante no se descarta" "1" "${#TG_TROZOS[@]}"

# --- Rafagas grandes: el tope de mensajes ----------------------------------
echo
echo "Rafagas grandes"

# Genera un cuerpo con N lineas del formato actual (2 entities cada una).
rafaga() {
    local n="$1" i=0 ip out="<u>Nuevas conexiones de ataque</u>"
    while [ "$i" -lt "$n" ]; do
        ip="10.$(( i / 65536 % 256 )).$(( i / 256 % 256 )).$(( i % 256 ))"
        out+="
Source: <code>${ip}</code>  SMB (445) ×2  2026-08-20 03:25:53 UTC  <a href=\"https://www.abuseipdb.com/check/${ip}\">AbuseIPDB</a>"
        i=$((i + 1))
    done
    printf '%s' "$out"
}

# Lo de esta manana sigue cabiendo en uno: ese es el caso que hay que
# proteger, y el tope no debe estropearlo.
tg_trocear "$CABECERA" "$(rafaga 33)"
comprueba "33 IPs (lo del 20/08) siguen en un solo mensaje" "1" "${#TG_TROZOS[@]}"
comprueba "y sin aviso de recorte" "0" "$TG_OMITIDAS"

# Un barrido a un /24 entero: se trocea, pero con tope.
tg_trocear "$CABECERA" "$(rafaga 254)"
comprueba "254 IPs no pasan de $TG_MAX_TROZOS mensajes" "si" \
    "$( [ "${#TG_TROZOS[@]}" -le "$TG_MAX_TROZOS" ] && echo si || echo no )"
comprueba "254 IPs avisan de lo recortado" "si" \
    "$( [ "$TG_OMITIDAS" -gt 0 ] && echo si || echo no )"
comprueba "el aviso va en el ultimo trozo" "si" \
    "$( case "${TG_TROZOS[$(( ${#TG_TROZOS[@]} - 1 ))]}" in *"$TG_OMITIDAS lineas mas"*) echo si;; *) echo no;; esac )"
comprueba "el aviso no gasta ninguna entity" "si" \
    "$( [ "$(tg_entidades "… y 94 lineas mas, no mostradas.")" -eq 0 ] && echo si || echo no )"

# Y la cuenta cuadra: mostradas + omitidas = todas. Un aviso que miente sobre
# cuanto ha recortado es peor que no avisar.
mostradas=0
for t in "${TG_TROZOS[@]}"; do
    mostradas=$(( mostradas + $(printf '%s\n' "$t" | grep -c '^Source: ') ))
done
comprueba "mostradas + omitidas = 254" "254" "$(( mostradas + TG_OMITIDAS ))"

# Sin tope, 3000 IPs eran 74 mensajes --- muy por encima de los ~20/min que
# admite Telegram, asi que los ultimos se perdian --- y el troceo tardaba mas
# de dos minutos, con el vigilante corriendo en un cron cada pocos minutos.
#
# El limite de 10 s no es un numero al azar: es un guardarrail contra volver a
# medir con "$(funcion ...)" dentro del bucle. Esa forma arranca un subshell
# por linea y por si sola costaba 14 s, asi que reintroducirla hace fallar
# esta comprobacion aunque el resultado del troceo siga siendo correcto.
inicio=$(date +%s)
tg_trocear "$CABECERA" "$(rafaga 3000)"
tardado=$(( $(date +%s) - inicio ))
comprueba "3000 IPs no pasan de $TG_MAX_TROZOS mensajes" "si" \
    "$( [ "${#TG_TROZOS[@]}" -le "$TG_MAX_TROZOS" ] && echo si || echo no )"
comprueba "3000 IPs se trocean en menos de 10 s (sin forks por linea)" "si" \
    "$( [ "$tardado" -lt 10 ] && echo si || echo no )"
printf '        (tardo %d s)\n' "$tardado"

# --- Que el formato de arriba siga siendo el de verdad ---------------------
echo
echo "El formato probado es el que emite dionaea-watch.sh"

# Aqui arriba hay una COPIA del formato de la linea "Source:", y una copia es
# algo que algun dia dice otra cosa que el original --- en este proyecto ya ha
# pasado bastantes veces. Estas tres comprobaciones leen el script de verdad,
# asi que si alguien cambia el formato y no toca esta prueba, la prueba se
# entera. Son sobre el presupuesto de entities, que es lo unico que importa.
FUENTE="$AQUI/../DIONAEA/dionaea-watch.sh"
linea_real=$(grep -m1 '^Source: ' "$FUENTE" || true)

comprueba "la IP sigue dentro de <code> (si no, Telegram la enlaza sola)" "si" \
    "$( case "$linea_real" in *'<code>${ip}</code>'*) echo si;; *) echo no;; esac )"
comprueba "la hora sigue SIN <code> (costaba una entity por linea)" "no" \
    "$( case "$linea_real" in *'<code>${last_ts}'*) echo si;; *) echo no;; esac )"
comprueba "la linea gasta 2 entities, como asume esta prueba" "2" \
    "$(tg_entidades "$linea_real")"
# Sin las lineas de comentario: ahi "en AbuseIPDB" aparece contando por que se
# quito, y contarlo como si fuera codigo haria fallar la prueba por leer su
# propia explicacion.
comprueba "ya no hay lista aparte de enlaces a AbuseIPDB" "0" \
    "$(grep -v '^[[:space:]]*#' "$FUENTE" | grep -c 'en AbuseIPDB' | tr -d '[:space:]')"

# El bloque de descargas: agrupado, con la URL la ultima y escapada. Las tres
# cosas se rompen por separado, y las tres dejan de verse en cuanto el mensaje
# "parece" correcto, asi que se comprueban leyendo el script.
comprueba "las descargas se agrupan en el SQL" "si" \
    "$( grep -q 'GROUP BY d.download_md5_hash' "$FUENTE" && echo si || echo no )"
comprueba "y cuentan conexiones distintas, no filas" "si" \
    "$( grep -q 'COUNT(DISTINCT d.connection)' "$FUENTE" && echo si || echo no )"
comprueba "la URL es el ultimo campo del read (absorbe los | del atacante)" "si" \
    "$( grep -q "read -r md5 rip veces url" "$FUENTE" && echo si || echo no )"
comprueba "la URL se escapa antes de meterla en el mensaje" "si" \
    "$( grep -q 'Origin: <code>\$(tg_escapar' "$FUENTE" && echo si || echo no )"
comprueba "el enlace de VirusTotal exige un hash hexadecimal" "si" \
    "$( grep -q '\*\[!0-9a-fA-F\]\*' "$FUENTE" && echo si || echo no )"

# --- El envio --------------------------------------------------------------
echo
echo "Envio troceado"

# Sin esperas reales entre trozos.
sleep() { :; }
ENVIADOS=()
finge_envio() { ENVIADOS+=("$1"); }

tg_enviar_troceado finge_envio "$CABECERA" "$viejo"
comprueba "se envian tantos mensajes como trozos" "si" \
    "$( [ "${#ENVIADOS[@]}" -ge 2 ] && echo si || echo no )"

con_cabecera=0
con_marca=0
for m in "${ENVIADOS[@]}"; do
    case "$m" in "<strong>[Dionaea]</strong>"*) con_cabecera=$((con_cabecera + 1));; esac
    case "$m" in *"(1/${#ENVIADOS[@]})"*|*"(2/${#ENVIADOS[@]})"*|*"(3/${#ENVIADOS[@]})"*|*"(4/${#ENVIADOS[@]})"*) con_marca=$((con_marca + 1));; esac
done
comprueba "la cabecera se repite en todos los trozos" "${#ENVIADOS[@]}" "$con_cabecera"
comprueba "todos llevan su (n/total)" "${#ENVIADOS[@]}" "$con_marca"

# Un mensaje de una sola pieza no lleva "(1/1)": seria ruido.
ENVIADOS=()
tg_enviar_troceado finge_envio "$CABECERA" "una linea"
comprueba "un mensaje unico no lleva contador" "no" \
    "$( case "${ENVIADOS[0]}" in *"(1/1)"*) echo si;; *) echo no;; esac )"

echo
echo "-------------------------------------"
printf 'ok: %d   fallos: %d\n' "$OK" "$MAL"
[ "$MAL" -eq 0 ] || exit 1
