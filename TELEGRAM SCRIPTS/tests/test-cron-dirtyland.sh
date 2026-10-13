#!/usr/bin/env bash
# test-cron-dirtyland.sh — poner las tareas periodicas sin nano y sin duplicar.
#
#   bash "TELEGRAM SCRIPTS/tests/test-cron-dirtyland.sh"
#
# Este paso era un `nano` en el README, o sea lo unico del despliegue que no
# era copiar y pegar. El 2026-08-29 se anadio una tarea nueva y hubo que
# meterla a mano: si un paso se puede olvidar, hay que quitarlo, no
# advertirlo.
#
# El `crontab` de estas pruebas es de mentira y guarda en un fichero. Todo lo
# demas es el guion de verdad.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUION="$AQUI/../cron-dirtyland.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/crontab" <<'EOF'
#!/bin/bash
F="$CRONTAB_FICHERO"
if [ "${1:-}" = "-l" ]; then [ -s "$F" ] && cat "$F" || exit 1; exit 0; fi
cat "$1" > "$F"
EOF
chmod +x "$TMP/crontab"

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

correr() {
    ( CRONTAB_CMD="$TMP/crontab"; CRONTAB_FICHERO="$TMP/tab"
      CRON_BACKUP_DIR="$TMP"; export CRONTAB_CMD CRONTAB_FICHERO CRON_BACKUP_DIR
      bash "$GUION" "$@" 2>&1 )
}

echo
echo "Un crontab vacio: se ponen las cinco"
: > "$TMP/tab"
salida=$(correr --apply); rc=$?
comprueba "sale bien" "0" "$rc"
comprueba "y quedan las cinco" "5" \
    "$(grep -cE 'daily-digest|baneadas-diario|dionaea-watch|proxy-watch|generar-tabla-paises' "$TMP/tab")"

echo
echo "Y no se duplican al repetir"
# El README se copia y se pega, y tras una reinstalacion no se sabe si ya
# estaban. Ejecutarlo dos veces no puede dejar ocho lineas.
antes=$(md5sum < "$TMP/tab")
salida=$(correr --apply); rc=$?
comprueba "la segunda vez no hace nada" "0" "$rc"
comprueba "y lo dice" "1" "$(printf '%s' "$salida" | grep -c 'no hay nada que hacer')"
comprueba "sin tocar el crontab" "$antes" "$(md5sum < "$TMP/tab")"

echo
echo "Lo que NO es nuestro se respeta"
# El crontab de root es de la maquina, no nuestro: puede tener cosas de otros.
printf '0 3 * * * /usr/local/bin/algo-mio.sh\n' > "$TMP/tab"
correr --apply >/dev/null
comprueba "la linea ajena sigue ahi" "1" \
    "$(grep -c 'algo-mio.sh' "$TMP/tab")"
comprueba "y se anaden las nuestras" "5" \
    "$(grep -cE 'daily-digest|baneadas-diario|dionaea-watch|proxy-watch|generar-tabla-paises' "$TMP/tab")"

echo
echo "Una hora cambiada a mano no cuenta como que falta"
# Se reconoce por el guion, no por la linea entera: si no, cambiar la hora
# haria que esto la diera por ausente y la pusiera otra vez, dejando la tarea
# dos veces y a dos horas distintas.
sed -i 's#^0 6 \* \* \* /opt/dirtyland/monitor/daily-digest.sh#30 7 * * * /opt/dirtyland/monitor/daily-digest.sh#' "$TMP/tab"
salida=$(correr); rc=$?
comprueba "se da por puesta" "0" "$rc"
comprueba "y no se duplica" "1" "$(grep -c 'daily-digest.sh' "$TMP/tab")"

echo
echo "Sin --apply no toca nada"
printf '0 3 * * * /usr/local/bin/algo-mio.sh\n' > "$TMP/tab"
antes=$(md5sum < "$TMP/tab")
salida=$(correr); rc=$?
comprueba "dice que faltan cinco" "5" "$(printf '%s' "$salida" | grep -c 'FALTA')"
comprueba "sale con error, para que se note en un guion" "1" "$rc"
comprueba "y no ha tocado el crontab" "$antes" "$(md5sum < "$TMP/tab")"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
