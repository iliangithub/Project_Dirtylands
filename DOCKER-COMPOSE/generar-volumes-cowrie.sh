#!/bin/bash
# ---------------------------------------------------------------------------
# Genera el bloque `volumes:` del servicio cowrie del docker-compose.
#
# Existe porque una parte de ese bloque CRECE. Los montajes fijos (config,
# sistema de ficheros falso, Telegram) son siempre los mismos, pero los de los
# comandos emulados salen de lo que haya en cmdpatch/, y cada comando nuevo es
# una linea mas. Mantener esas lineas a mano significa que, tarde o temprano,
# se anade un comando y se olvida el montaje: el comando existe en el host y el
# contenedor sigue ejecutando el de fabrica, sin ningun error que lo delate.
#
#   ./generar-volumes-cowrie.sh              imprime el bloque, no toca nada
#   ./generar-volumes-cowrie.sh --apply      lo sustituye en el docker-compose
#
# Con --apply hace copia de seguridad, sustituye, y valida con `docker compose
# config`. Si el resultado no fuera valido, deja el fichero como estaba: mas
# vale no cambiar nada que dejar un compose roto.
#
# Ademas, si encuentra en el compose un montaje que no esta en la lista fija de
# abajo, se para y lo nombra en vez de borrarlo en silencio. Lo correcto casi
# siempre es anadirlo a esa lista, para que se genere tambien en la proxima
# instalacion y no se pierda otra vez.
#
#   ./generar-volumes-cowrie.sh --apply --force
#
# ...descarta esos montajes en lugar de pararse. Es una valvula de escape para
# limpiar restos, no un paso del procedimiento: si hace falta usarla de forma
# habitual, es que falta algo en la lista fija.
# ---------------------------------------------------------------------------
set -uo pipefail

CMDPATCH=${CMDPATCH:-/opt/dirtyland/cowrie/cmdpatch}
COMPOSE=${COMPOSE:-/opt/dirtyland/docker-compose.yml}
# Ficheros que NO son nuestros: se sacan de la imagen y se parchean. Hoy solo
# el protocol.py de Cowrie (ver COWRIE FAKE ENVIRONMENT/parche-protocol.py).
PARCHES=${PARCHES:-/opt/dirtyland/cowrie/parches}

if [ ! -d "$CMDPATCH" ]; then
    echo "No existe $CMDPATCH" >&2
    exit 1
fi

# SE PARA SI FALTA, no lo omite. Un compose generado sin esta linea arranca
# perfectamente y deja el prompt de contrasena comiendose a si mismo, sin dar
# ningun error: es justo el fallo silencioso que este generador viene a
# evitar con los comandos.
if [ ! -f "$PARCHES/protocol.py" ]; then
    echo "Falta $PARCHES/protocol.py" >&2
    echo "Se saca de la imagen y se parchea; ver el apartado 3.4.2.8 del README." >&2
    exit 1
fi

# --- El bloque, tal cual va en el fichero -----------------------------------
generar() {
    cat <<'FIJOS'
    volumes:
      - cowrie-var:/cowrie/cowrie-git/var
      - /etc/localtime:/etc/localtime:ro

      # --- Configuracion y sistema de ficheros falso -------------------
      - /opt/dirtyland/cowrie/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
      - /opt/dirtyland/cowrie/etc/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
      - /opt/dirtyland/cowrie/fs/fs.pickle:/cowrie/cowrie-git/src/cowrie/data/custom-fs.pickle:ro
      - /opt/dirtyland/cowrie/honeyfs:/opt/honeyfs:ro
      - /opt/dirtyland/cowrie/etc/ps_command_output.json:/opt/ps_command_output.json:ro
      # Los textos de "--help" de los 46 comandos, medidos de sus
      # binarios reales. Son DATOS, como la salida de ps y la lista de
      # dpkg, y por eso van en un fichero aparte y no dentro del codigo.
      - /opt/dirtyland/cowrie/etc/ayudas-comandos.json:/opt/ayudas-comandos.json:ro
      # La lista de "dpkg -l", exportada por build-dirtyland-fs.sh del mismo
      # contenedor del que sale el pickle (3.4.2.3). Se monta desde fs/, que es
      # donde el generador la deja, y NO desde etc/: copiarla seria un paso
      # manual mas, y un paso manual es un paso que algun dia se olvida. Aqui
      # ademas se olvidaria en silencio, porque el pickle nuevo si estaria y la
      # lista vieja tambien: el senuelo seguiria en pie contando dos versiones
      # distintas de si mismo. Igual que fs.pickle, esto vive en fs/.
      - /opt/dirtyland/cowrie/fs/dpkg-packages.tsv:/opt/dpkg-packages.tsv:ro

      # --- Claves de host SSH (3.4.2.10) -------------------------------
      # Generadas con ssh-keygen de verdad. Sin esto Cowrie se las fabrica el
      # solo con RSA_KEY_SIZE = 2048, y un Debian 13 con OpenSSH 10 tiene la
      # RSA de 3072: lo canta un "nmap --script ssh-hostkey" sin entrar.
      - /opt/dirtyland/cowrie/keys:/opt/cowrie-keys:ro

      # --- Salidas enlatadas que sustituyen a las de fabrica (3.4.2.8) --
      # Se monta el DIRECTORIO y no cada fichero, y aqui no tapa nada:
      # [honeypot] txtcmds_path es una ruta de anulacion, asi que lo que no
      # este aqui Cowrie lo sigue cogiendo de la suya.
      - /opt/dirtyland/cowrie/txtcmds:/opt/txtcmds:ro

      # --- Alertas de Telegram (3.4.2.7) -------------------------------
      # El plugin, dentro del paquete de outputs de Cowrie.
      # Ojo al destino: se monta ENCIMA del telegram.py de fabrica, porque el
      # cargador de Cowrie solo admite nombres de una palabra (ver 3.4.2.7).
      - "/opt/dirtyland/Telegram Reports/telegram_alert_cowrie.py:/cowrie/cowrie-git/src/cowrie/output/telegram.py:ro"
      # Los tokens, en la MISMA ruta que en el host, para que la constante
      # del plugin sea valida dentro y fuera del contenedor.
      - "/opt/dirtyland/Telegram Reports/telegram.cfg:/opt/dirtyland/Telegram Reports/telegram.cfg:ro"
      # Lo unico con escritura: el buzon de peticiones de baneo. El
      # contenedor escribe aqui; quien toca nftables es el servicio
      # telegram-ban-watcher del host.
      - "/opt/dirtyland/Telegram Reports/state:/opt/dirtyland/Telegram Reports/state:rw"

      # --- Pais de cada IP, para la bandera de las alertas -------------
      # Se monta LA CARPETA, no los ficheros de dentro, y eso no es un
      # detalle de estilo. Un bind mount de un fichero se queda pegado a su
      # inodo: cuando el cron regenera la tabla ---que la escribe al lado y
      # la renombra encima, para no dejarla nunca a medias--- el contenedor
      # seguiria viendo la vieja hasta que alguien lo recreara, y nada lo
      # diria. Montando la carpeta, el reemplazo se ve al instante.
      #
      # En la misma ruta que en el host, como el telegram.cfg, para que el
      # import del plugin valga dentro y fuera. Solo lectura: quien la
      # genera es el cron del anfitrion.
      - "/opt/dirtyland/geoip:/opt/dirtyland/geoip:ro"
FIJOS

    local n=0
    for f in "$CMDPATCH"/*.py; do
        [ -e "$f" ] || continue
        n=$((n + 1))
    done
    echo
    echo "      # --- Comandos emulados (3.4.2.8): $n lineas generadas ------------"

    # Dos ficheros no son comandos y no van a commands/: honeypot.py es la
    # shell y userauth.py es la autenticacion de telnet.
    for f in "$CMDPATCH"/*.py; do
        [ -e "$f" ] || continue
        local base dst
        base=$(basename "$f")
        case "$base" in
            # Un test que se hubiera colado en cmdpatch NO es un comando: se
            # montaria dentro de Cowrie y se cargaria al arrancar.
            test_*.py)   continue ;;
            honeypot.py) dst="shell/$base" ;;
            userauth.py) dst="telnet/$base" ;;
            *)           dst="commands/$base" ;;
        esac
        printf '      - /opt/dirtyland/cowrie/cmdpatch/%s:/cowrie/cowrie-git/src/cowrie/%s:ro\n' \
               "$base" "$dst"
    done

    echo
    echo "      # --- De la imagen, parcheados (3.4.2.8) --------------------------"
    printf '      - %s/protocol.py:/cowrie/cowrie-git/src/cowrie/shell/protocol.py:ro\n' \
           "$PARCHES"
}

# --- Sin --apply: solo imprimir ---------------------------------------------
if [ "${1:-}" != "--apply" ]; then
    generar
    exit 0
fi

# --- Con --apply: sustituir, validar y revertir si algo sale mal ------------
if [ ! -f "$COMPOSE" ]; then
    echo "No existe $COMPOSE" >&2
    exit 1
fi

NUEVO=$(mktemp)
generar > "$NUEVO"

# --- Nada se pierde por el camino -------------------------------------------
# El bloque se sustituye entero, asi que un montaje anadido a mano que no este
# en la lista fija desapareceria en silencio. Antes de tocar nada se comprueba
# que todo lo que ya habia sigue estando, y si no, se para: el usuario decide.
entradas() {
    awk '
        /^  cowrie:[[:space:]]*$/ { en_cowrie = 1 }
        /^  [a-zA-Z_][a-zA-Z0-9_-]*:[[:space:]]*$/ && !/^  cowrie:/ { en_cowrie = 0 }
        en_cowrie && /^    volumes:[[:space:]]*$/ { en_vol = 1; next }
        en_vol && /^      *- / {
            linea = $0
            sub(/^[[:space:]]*- [[:space:]]*/, "", linea)
            gsub(/^"|"$/, "", linea)
            print linea
            next
        }
        en_vol && !/^      / && !/^[[:space:]]*$/ { en_vol = 0 }
    ' "$1" | sort -u
}

PERDIDAS=$(comm -23 <(entradas "$COMPOSE") <(entradas <(cat "$NUEVO" | sed '1i\  cowrie:')))
if [ -n "$PERDIDAS" ] && [ "${2:-}" != "--force" ]; then
    echo "AVISO: estos montajes existen ahora y NO los genera el guion:" >&2
    echo "$PERDIDAS" | sed 's/^/  - /' >&2
    echo >&2
    echo "Sustituir el bloque los eliminaria. Si son tuyos y los quieres" >&2
    echo "conservar, anadelos a la parte fija de este guion. Si sobran," >&2
    echo "vuelve a lanzarlo con:  $0 --apply --force" >&2
    rm -f "$NUEVO"
    exit 1
fi

BACKUP="${COMPOSE}.bak-$(date +%Y-%m-%d_%H%M%S)"
cp -a "$COMPOSE" "$BACKUP"
echo "Copia de seguridad: $BACKUP"

SALIDA=$(mktemp)
# Sustituye el bloque volumes: del servicio cowrie. Empieza en su linea
# "    volumes:" y termina en la siguiente clave con sangria de 4 o menos, que
# es donde acaba la lista.
awk -v bloque="$NUEVO" '
    /^  cowrie:[[:space:]]*$/ { en_cowrie = 1 }
    /^  [a-zA-Z_][a-zA-Z0-9_-]*:[[:space:]]*$/ && !/^  cowrie:/ { en_cowrie = 0 }

    en_cowrie && /^    volumes:[[:space:]]*$/ {
        while ((getline linea < bloque) > 0) print linea
        close(bloque)
        saltando = 1
        next
    }
    saltando {
        # La lista sigue mientras haya elementos, comentarios o lineas vacias
        # con al menos 6 espacios de sangria.
        if ($0 ~ /^      / || $0 ~ /^[[:space:]]*$/) next
        saltando = 0
    }
    { print }
' "$COMPOSE" > "$SALIDA"

if [ ! -s "$SALIDA" ]; then
    echo "El resultado salio vacio; no se toca nada." >&2
    rm -f "$NUEVO" "$SALIDA"
    exit 1
fi

cp -a "$SALIDA" "$COMPOSE"
rm -f "$NUEVO" "$SALIDA"

if docker compose -f "$COMPOSE" config >/dev/null 2>&1; then
    echo "Bloque actualizado y compose valido."
    # El comando para aplicar esta en el README y no aqui, por lo mismo que
    # en build-dirtyland-fs.sh: un comando en dos sitios acaba divergiendo.
    echo "Aplicalo siguiendo el apartado 3.4.2.9 del README."
    exit 0
fi

echo "El compose resultante NO es valido. Se restaura la copia de seguridad." >&2
cp -a "$BACKUP" "$COMPOSE"
docker compose -f "$COMPOSE" config >/dev/null
exit 1
