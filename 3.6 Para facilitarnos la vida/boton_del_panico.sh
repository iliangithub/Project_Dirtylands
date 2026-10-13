#!/usr/bin/env bash
#
# boton_del_panico.sh
#
# Corta el senuelo en seco: para los dos contenedores y con ellos toda la
# actividad entrante. Para cuando algo se tuerce y no es momento de buscar el
# comando exacto en el README.
#
#   sudo ~/boton_del_panico.sh              para Cowrie y Dionaea
#   sudo ~/boton_del_panico.sh --reanudar   los vuelve a levantar
#   sudo ~/boton_del_panico.sh --estado     solo mira como estan
#
# QUE HACE Y QUE NO HACE, que en un boton de panico importa mas que en
# ninguna otra parte:
#
#   SI  para los contenedores dirtyland_cowrie y dirtyland_dionaea. Con ellos
#       muertos, el DNAT de los puertos publicos lleva a un sitio donde no
#       escucha nadie y las conexiones se rechazan al instante. No entra ni
#       una sesion mas.
#
#   NO  toca el cortafuegos. Deliberadamente. Un script que reescribe nftables
#       con prisas y a las tantas es la mejor forma de quedarse fuera de la
#       propia maquina, y eso convierte un incidente pequeno en uno grave. Si
#       hace falta cerrar a nivel de red, se hace a mano y mirando.
#
#   NO  borra nada. Ni logs, ni muestras capturadas, ni la base de estado. Los
#       contenedores se paran, no se destruyen: lo capturado sigue en su sitio
#       y --reanudar lo deja todo como estaba.
#
#   NO  para el reporter. Sigue procesando lo ya recogido, que es lo correcto:
#       apagar el senuelo no invalida las capturas de antes. Si tambien
#       quieres cortar los envios, esta escrito al final de la salida.
set -euo pipefail

CONTENEDORES=(dirtyland_cowrie dirtyland_dionaea)

if [ "$(id -u)" -ne 0 ]; then
    echo "Esto necesita root, que es quien manda sobre Docker." >&2
    echo "  sudo $0 ${*:-}" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "No encuentro docker en el PATH." >&2
    exit 1
fi

estado() {
    local c
    for c in "${CONTENEDORES[@]}"; do
        printf '  %-20s %s\n' "$c" \
            "$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo 'no existe')"
    done
}

case "${1:-}" in
    --estado)
        echo "Estado actual:"
        estado
        exit 0
        ;;

    --reanudar)
        echo "Levantando el senuelo..."
        for c in "${CONTENEDORES[@]}"; do
            docker start "$c" >/dev/null 2>&1 \
                && echo "  $c: arrancado" \
                || echo "  $c: NO se pudo arrancar (mira 'docker logs $c')"
        done
        echo
        estado
        echo
        echo "Comprueba que vuelve a escuchar:  ~/acceder_ssh_para_vagos.sh"
        exit 0
        ;;

    "")
        : # el caso normal, sigue abajo
        ;;

    *)
        echo "Uso: sudo $0 [--reanudar | --estado]" >&2
        exit 2
        ;;
esac

echo "Se van a PARAR los contenedores del senuelo:"
estado
echo
echo "No se borra nada y se puede deshacer con --reanudar."
printf 'Escribe PARAR para confirmar: '
read -r respuesta
if [ "$respuesta" != "PARAR" ]; then
    echo "Cancelado. No se ha tocado nada."
    exit 0
fi

echo
for c in "${CONTENEDORES[@]}"; do
    # -t 10: se les da diez segundos para cerrar bien. Cowrie guarda ahi la
    # memoria del plugin de Telegram y cierra sus sesiones; matarlo a lo bruto
    # perderia el ultimo trozo de estado sin ganar nada.
    docker stop -t 10 "$c" >/dev/null 2>&1 \
        && echo "  $c: parado" \
        || echo "  $c: no se pudo parar (o ya estaba parado)"
done

echo
estado
echo
echo "Senuelo detenido. Los puertos publicos ya rechazan cualquier conexion."
echo
echo "Para volver:            sudo $0 --reanudar"
echo "Si ademas quieres cortar los envios a las plataformas:"
echo "  sudo ~/cortar_el_grifo.py        (opcion 0: el modo del cron)"
