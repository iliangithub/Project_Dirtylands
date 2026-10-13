#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# cron-dirtyland.sh --- pone las tareas periodicas del proyecto en el crontab.
#
#   sudo ./cron-dirtyland.sh            dice cuales faltan, no toca nada
#   sudo ./cron-dirtyland.sh --apply    anade las que falten
#
# EXISTE PORQUE ESTE PASO ERA UN `nano`, y es lo unico que quedaba del
# despliegue que no era copiar y pegar. El 2026-08-29 se anadio una tarea
# nueva y el usuario tuvo que meterla a mano; si un paso se puede olvidar, hay
# que quitarlo, no advertirlo.
#
# NO BORRA NADA. Solo anade lo que falta, y respeta cualquier otra linea que
# haya en el crontab. El crontab de root es de la maquina, no nuestro: puede
# tener cosas que no son de este proyecto.
#
# Se guarda copia del anterior antes de tocarlo, por lo mismo que en
# montajes-dionaea.sh: mas vale no cambiar nada que dejarlo a medias.
# ---------------------------------------------------------------------------
set -uo pipefail

# LAS TAREAS. Esta lista si se puede escribir aqui: cambia de año en año, no
# cada vez que se anade un fichero, que es lo que hacia insostenible el mapa
# de piezas que llevaba voy_al_dia.
TAREAS=(
    "0 6 * * * /opt/dirtyland/monitor/daily-digest.sh"
    "0 6 * * * /opt/dirtyland/monitor/baneadas-diario.sh"
    "*/5 * * * * /opt/dirtyland/monitor/dionaea-watch.sh"
    "*/30 * * * * /opt/dirtyland/monitor/proxy-watch.sh"
    "0 4 1,16 * * /opt/dirtyland/geoip/generar-tabla-paises.py --avisar >/dev/null"
)

CRONTAB="${CRONTAB_CMD:-crontab}"

actual=$("$CRONTAB" -l 2>/dev/null || true)

# Se reconoce por el GUION, no por la linea entera: asi cambiar la hora a mano
# no hace que esto crea que falta y la duplique. Lo que se quiere garantizar
# es que la tarea esta puesta, no que este puesta exactamente como aqui.
guion_de() { printf '%s' "$1" | awk '{for (i=6; i<=NF; i++) if ($i ~ /^\//) {print $i; exit}}'; }

FALTAN=()
for t in "${TAREAS[@]}"; do
    g=$(guion_de "$t")
    if printf '%s\n' "$actual" | grep -qF "$g"; then
        echo "  ok     $g"
    else
        echo "  FALTA  $g"
        FALTAN+=("$t")
    fi
done

if [ "${#FALTAN[@]}" -eq 0 ]; then
    echo
    echo "Las ${#TAREAS[@]} estan puestas; no hay nada que hacer."
    exit 0
fi

if [ "${1:-}" != "--apply" ]; then
    echo
    echo "Faltan ${#FALTAN[@]}. Para ponerlas:  sudo $0 --apply"
    exit 1
fi

BACKUP="${CRON_BACKUP_DIR:-/root}/crontab.bak-$(date +%Y-%m-%d_%H%M%S)"
if ! printf '%s\n' "$actual" > "$BACKUP" 2>/dev/null; then
    # Sin copia se sigue igual: esto solo ANADE lineas, nunca borra, asi que
    # lo peor que puede pasar es una linea de mas. Pararse aqui seria dejar
    # sin poner una tarea por no poder guardar un fichero que casi nunca se
    # usa.
    BACKUP="(no se pudo guardar, pero esto solo anade)"
fi

nuevo=$(mktemp)
# Lo que ya hubiera va primero y sin tocar; lo nuestro se anade detras.
[ -n "$actual" ] && printf '%s\n' "$actual" > "$nuevo"
for t in "${FALTAN[@]}"; do
    printf '%s\n' "$t" >> "$nuevo"
done

if "$CRONTAB" "$nuevo"; then
    rm -f "$nuevo"
    echo
    echo "Anadidas ${#FALTAN[@]}. Copia del crontab anterior en $BACKUP"
    exit 0
fi

rm -f "$nuevo"
echo "No se pudo instalar el crontab. No se ha cambiado nada." >&2
exit 1
