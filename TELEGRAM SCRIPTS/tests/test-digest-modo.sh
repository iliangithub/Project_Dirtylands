#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test-digest-modo.sh --- el apartado de reporters del resumen diario:
# el color, el MOTIVO y las CUENTAS de 24 horas.
#
#     bash "TELEGRAM SCRIPTS/tests/test-digest-modo.sh"
#
# Existe por dos fallos, y los dos consistian en que el parte decia algo que
# no era verdad:
#
#   1. El cron volvio a modo simulacion y el parte seguia ensenando puntos
#      VERDES con ceros al lado. Todo apagado, pintado de encendido. Costo
#      mas de un dia de reportes.
#
#   2. Las cuentas de la seccion "(24h)" salian del ultimo "--- resumen ---"
#      del log, que es de UNA PASADA de 15 minutos. Con 400 IP denunciadas en
#      el dia, el parte decia "1 enviados" ---la que se hubiera publicado
#      desde y cuarto--- mientras AbuseIPDB ensenaba los cientos de verdad.
#
# Las funciones se EXTRAEN del daily-digest.sh que se despliega, no se copian
# aqui: una copia se queda vieja sin avisar, que es el mismo error que se esta
# intentando cazar. Por lo mismo, el esquema de la base sale de
# common/state.py y el reparto de motivos se compara con reporters/base.py.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FUENTE="$AQUI/../daily-digest.sh"
PLANTILLA="$AQUI/../../REPORTING PLATFORM SCRIPTS/cron.d/dirtyland-reporter"
ESTADO_PY="$AQUI/../../REPORTING PLATFORM SCRIPTS/common/state.py"
BASE_PY="$AQUI/../../REPORTING PLATFORM SCRIPTS/reporters/base.py"

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

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Se sacan las cuatro funciones del fichero de verdad.
extraer() {
    awk -v n="$1" '
        $0 ~ "^"n"\\(\\) \\{" {dentro=1}
        dentro {print}
        dentro && /^}$/ {exit}
    ' "$FUENTE"
}
{
    printf 'NL=$%s\n' "'\n'"
    printf 'since="24 hours ago"\nDIONAEA_MUDO_HORAS="${DIONAEA_MUDO_HORAS:-6}"\n'
    for f in cron_en_live plataforma_encendida punto_plataforma motivo_apagado \
             cuentas_24h aviso_parcial reporters_health dionaea_resumen \
             registro_incompleto; do
        extraer "$f"
    done
} > "$TMP/fn.sh"

VERDE=$(printf '\360\237\237\242')
ROJO=$(printf '\360\237\224\264')

cfg() {   # $1 = fichero, resto = secciones encendidas
    local f="$TMP/$1"; shift
    : > "$f"
    local s
    for s in virustotal malwarebazaar threatfox urlhaus abuseipdb; do
        printf '[%s]\nenabled = %s\n' "$s" \
            "$(printf '%s\n' "$@" | grep -qx "$s" && echo true || echo false)" >> "$f"
    done
}
cfg todo.ini   virustotal malwarebazaar threatfox urlhaus abuseipdb
cfg nada.ini
cfg parcial.ini virustotal abuseipdb

cp "$PLANTILLA" "$TMP/cron-sim"
sed -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' \
    "$TMP/cron-sim" > "$TMP/cron-live"

evaluar() {   # $1 = cfg  $2 = cron  $3 = que funcion  $4 = argumento
    ( CFG_REPORTER="$TMP/$1"; CRON_REPORTER="$TMP/$2"
      # shellcheck source=/dev/null
      . "$TMP/fn.sh"; "$3" "${4:-}" )
}

echo
echo "El cron manda sobre el config"
comprueba "con el cron en simulacion, una plataforma encendida sale ROJA" \
    "$ROJO" "$(evaluar todo.ini cron-sim punto_plataforma virustotal)"
comprueba "con el cron publicando, esa misma sale VERDE" \
    "$VERDE" "$(evaluar todo.ini cron-live punto_plataforma virustotal)"
comprueba "y una apagada sigue roja aunque el cron publique" \
    "$ROJO" "$(evaluar parcial.ini cron-live punto_plataforma threatfox)"

echo
echo "La linea de MOTIVO distingue las cuatro situaciones"
comprueba "cron en simulacion" \
    "1" "$(evaluar todo.ini cron-sim motivo_apagado | grep -c 'modo simulacion')"
comprueba "cron bien y todo apagado" \
    "1" "$(evaluar nada.ini cron-live motivo_apagado | grep -c 'simplemente todo apagado')"
comprueba "cron bien y algunos apagados" \
    "1" "$(evaluar parcial.ini cron-live motivo_apagado | grep -c 'ciertos servicios')"
comprueba "todo encendido: NO se escribe motivo, que una linea que sale siempre no se lee" \
    "" "$(evaluar todo.ini cron-live motivo_apagado)"

echo
echo "El cron que falta no se confunde con el cron apagado"
comprueba "sin fichero de cron, nada esta publicando" \
    "$ROJO" "$(evaluar todo.ini cron-que-no-existe punto_plataforma virustotal)"

echo
echo "Las cuentas son de 24 HORAS, no de la ultima pasada"

# La base se monta con el esquema DE VERDAD, sacado de common/state.py: si
# alguna vez cambian esas tablas, esta prueba se entera en vez de seguir
# midiendo sobre una copia inventada.
python3 - "$TMP/state.sqlite3" "$ESTADO_PY" <<'FIN_PY'
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

esquema = re.search(r'SCHEMA = """(.*?)"""',
                    open(sys.argv[2], encoding="utf-8").read(), re.S).group(1)
db = sqlite3.connect(sys.argv[1])
db.executescript(esquema)

ahora = datetime.now(timezone.utc)


def marca(horas):
    return (ahora - timedelta(hours=horas)).replace(microsecond=0).isoformat()


# 412 denuncias repartidas por el dia: son 27 pasadas del cron, no una. Es el
# caso que el parte contaba mal.
for i in range(412):
    db.execute("INSERT INTO sent VALUES (?,?,?,?,?)",
               ("abuseipdb", "10.0.%d.%d@hoy" % (i // 256, i % 256), "ok",
                marca(1 + (i % 22)), ""))
# Y 50 de anteayer, que NO son de las ultimas 24 h.
for i in range(50):
    db.execute("INSERT INTO sent VALUES (?,?,?,?,?)",
               ("abuseipdb", "10.9.0.%d@ayer" % i, "ok", marca(30), ""))

# VirusTotal: 7 publicadas de verdad y 3 solo simuladas.
for i in range(7):
    db.execute("INSERT INTO sent VALUES (?,?,?,?,?)",
               ("virustotal", "upload:%d" % i, "ok", marca(3), ""))
for i in range(3):
    db.execute("INSERT INTO sent VALUES (?,?,?,?,?)",
               ("virustotal", "sim:%d" % i, "simulado", marca(3), ""))

# ThreatFox: lo que dijo la verificacion de despues de publicar. Uno nuevo,
# uno que ya era de otra persona y uno que no se pudo comprobar.
for clave, detalle in (("ip:port:1.1.1.1:80", "elf.mirai | nuevo, id=99"),
                       ("ip:port:2.2.2.2:80", "elf.mirai | refresco de otro, id=98"),
                       ("ip:port:3.3.3.3:80", "elf.mirai | sin-verificar (HTTP 503)")):
    db.execute("INSERT INTO sent VALUES (?,?,?,?,?)",
               ("threatfox", clave, "ok", marca(2), detalle))

for gate, n, horas in (("enfriamiento", 291, 2), ("antiguedad", 4, 2),
                       ("rechazo-plataforma", 2, 2), ("enfriamiento", 99, 40)):
    for i in range(n):
        db.execute("INSERT INTO rejections VALUES (?,?,?,?,?)",
                   (marca(horas), "abuseipdb", "k%s%d%d" % (gate, horas, i),
                    gate, "de prueba"))
db.commit()
FIN_PY

cuentas() {   # $1 = plataforma, $2 = numero de campo (1..4)
    ( BASE_REPORTER="$TMP/state.sqlite3"
      # shellcheck source=/dev/null
      . "$TMP/fn.sh"; cuentas_24h ) | awk -F'\t' -v p="$1" -v c="$2" \
        '$1==p {print $c}'
}

# Cuantas filas hay REALMENTE en la tabla, sin ventana. Sirve para que las
# dos comprobaciones de abajo digan cosas distintas: que 412 no es "todo lo
# que hay" ni "lo de la ultima pasada", sino justo lo de las ultimas 24 h.
en_tabla() {   # $1 = tabla, $2 = columna de fecha
    python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute(
        'SELECT COUNT(*) FROM %s WHERE platform=\'abuseipdb\'' % sys.argv[2]
        ).fetchone()[0])" "$TMP/state.sqlite3" "$1"
}

comprueba "en la tabla hay 462 denuncias en total" "462" "$(en_tabla sent)"
comprueba "pero solo las 412 de las ultimas 24 h entran en el parte" \
    "412" "$(cuentas abuseipdb 2)"
comprueba "una plataforma sin nada dice 0, y sale igual" \
    "0" "$(cuentas malwarebazaar 2)"

comprueba "lo SIMULADO no se cuenta como publicado" \
    "7" "$(cuentas virustotal 2)"
comprueba "pero se dice aparte, que si no es pintar de verde lo muerto" \
    "3" "$(cuentas virustotal 4)"

comprueba "en la tabla hay 396 rechazos en total" "396" "$(en_tabla rejections)"
comprueba "y solo los 297 de las ultimas 24 h se agrupan, en el orden del reporter" \
    "291 ya cubiertas, 4 descartadas, 2 RECHAZADAS POR LA PLATAFORMA" \
    "$(cuentas abuseipdb 5)"
# --- Lo que ThreatFox dice DESPUES de publicar --------------------------
#
# "1 publicadas" se lee como "una contribucion mas", y no tiene por que
# serlo: abuse.ch responde ok igual cuando funde el indicador con uno que ya
# tenia de otra persona. Sin este desglose, el parte y el perfil se
# contradicen y no hay forma de saber cual de los dos miente.
comprueba "el parte separa los IOC nuevos de los que ya eran de otro" \
    " (1 nuevo, 1 ya era de otro, 1 sin verificar)" "$(cuentas threatfox 3)"

# EL CAMPO VACIO NO PUEDE DESAPARECER. El tabulador es separador BLANCO para
# `read`, asi que dos seguidos cuentan como uno: el matiz vacio se esfumaba y
# todo lo de detras se corria un puesto, sacando "0 publicadas0" en el parte.
# Por eso va un guion en vez de nada.
comprueba "una plataforma sin matiz manda un guion, no un hueco" \
    "-" "$(cuentas abuseipdb 3)"
comprueba "y el guion no llega a verse en el parte" \
    "0" "$( ( REPORTER_LOG="$TMP/reporter.log"; CFG_REPORTER="$TMP/todo.ini"
              CRON_REPORTER="$TMP/cron-live"; BASE_REPORTER="$TMP/state.sqlite3"
              # shellcheck source=/dev/null
              . "$TMP/fn.sh"; reporters_health ) | grep -c 'publicadas-')"

comprueba "salen las cinco plataformas, tengan o no algo que contar" \
    "5" "$( ( BASE_REPORTER="$TMP/state.sqlite3"
              # shellcheck source=/dev/null
              . "$TMP/fn.sh"; cuentas_24h ) | grep -c . )"

echo
echo "Sin base no se inventa un cero"
sin_base=$( ( BASE_REPORTER="$TMP/no-existe.sqlite3"
              # shellcheck source=/dev/null
              . "$TMP/fn.sh"; cuentas_24h ) ; echo "rc=$?" )
comprueba "falla en vez de devolver lineas a cero" \
    "rc=1" "$sin_base"
comprueba "y NO crea la base al mirarla: se abre en solo lectura" \
    "no" "$( [ -e "$TMP/no-existe.sqlite3" ] && echo si || echo no )"

echo
echo "La seccion entera no se contradice a si misma"

# La linea del modo y los puntos de color responden a la MISMA pregunta: si se
# esta publicando. Salian de dos sitios distintos ---la primera con la ruta del
# cron escrita a mano dentro de reporters_health, los segundos con
# $CRON_REPORTER---, y dos fuentes para un mismo dato acaban discrepando. Un
# parte que diga "publicando" con los puntos en rojo es exactamente el fallo
# que este apartado existe para evitar.
date '+%Y-%m-%d %H:%M:%S,000 INFO     dirtyland: fin' > "$TMP/reporter.log"

seccion() {   # $1 = fichero de cron
    ( REPORTER_LOG="$TMP/reporter.log"; CFG_REPORTER="$TMP/todo.ini"
      CRON_REPORTER="$TMP/$1"; BASE_REPORTER="$TMP/state.sqlite3"
      # shellcheck source=/dev/null
      . "$TMP/fn.sh"; reporters_health )
}

comprueba "con el cron publicando no se dice el modo: ya lo dicen los puntos" \
    "0" "$(seccion cron-live | grep -c 'modo:')"
comprueba "y la ultima pasada va en la misma linea del OK, no en una suelta" \
    "1" "$(seccion cron-live | grep -c 'OK --- ultima pasada')"

# La leyenda solo nombra los grupos que han salido hoy: explicarlos los
# cuatro siempre seria media pantalla fija que se deja de leer.
comprueba "la leyenda explica los grupos que han salido" \
    "1" "$(seccion cron-live | grep -c 'ya cubiertas = ')"
comprueba "y no explica los que no han salido" \
    "0" "$(seccion cron-live | grep -c 'aplazadas = ')"
comprueba "y entonces no queda ni un punto rojo" \
    "0" "$(seccion cron-live | grep -c "$ROJO")"
comprueba "con el cron en simulacion, la linea del modo lo dice" \
    "1" "$(seccion cron-sim | grep -c 'modo: SIMULACION')"
comprueba "y entonces no queda ni un punto verde" \
    "0" "$(seccion cron-sim | grep -c "$VERDE")"
comprueba "las cuentas de 24 h llegan hasta el parte, no solo hasta la funcion" \
    "1" "$(seccion cron-live | grep -c '412 publicadas')"

# ESTA SECCION NECESITA EL sqlite3 DE VERDAD, y si no esta se PARA en vez de
# seguir. Las comprobaciones de abajo son casi todas "no debe aparecer tal
# aviso": sin base que leer, la funcion no escribe nada y todas saldrian en
# verde sin haber probado nada. Una suite que se pone verde por no poder
# mirar es peor que una que falla, porque nadie la vuelve a mirar --- que es
# exactamente como Dionaea estuvo cinco dias caido.
if ! command -v sqlite3 >/dev/null; then
    echo
    echo "NO SE PUEDE PROBAR: falta el binario sqlite3 (apt install sqlite3)."
    echo "El resumen diario lo usa, asi que sin el no se puede comprobar."
    exit 1
fi

echo
echo "Dionaea mudo: el fallo que estuvo cinco dias sin que nada lo dijera"
#
# El 2026-08-23 a las 17:11 Dionaea se quedo en bucle y no volvio a anotar
# nada hasta el 28. Todo lo que se miraba decia que estaba bien: el contenedor
# "Up 6 days", el proceso vivo, el DNAT contando paquetes que entraban. Y el
# apartado escribia "(sin conexiones)", que se lee como "hoy no ha atacado
# nadie". Lo unico que separa las dos cosas es CUANDO fue la ultima conexion.

base_dionaea() {   # $1 = fichero; $2... = horas de antiguedad de cada conexion
    local f="$1"; shift
    rm -f "$f"
    python3 - "$f" "$@" <<'FIN_PY'
import sqlite3
import sys
import time

db = sqlite3.connect(sys.argv[1])
db.execute("CREATE TABLE connections (connection INTEGER PRIMARY KEY,"
           " connection_type TEXT, connection_protocol TEXT,"
           " connection_timestamp INTEGER, local_port INTEGER, remote_host TEXT)")
ahora = int(time.time())
for i, horas in enumerate(sys.argv[2:], 1):
    db.execute("INSERT INTO connections VALUES (?,?,?,?,?,?)",
               (i, "accept", "smbd", ahora - int(horas) * 3600, 445, "1.2.3.%d" % i))
db.commit()
FIN_PY
}

dionaea() {   # $1 = fichero de base
    ( DIONAEA_DB="$1"
      # shellcheck source=/dev/null
      . "$TMP/fn.sh"; dionaea_resumen )
}

base_dionaea "$TMP/dio-sano.sqlite" 1 2
base_dionaea "$TMP/dio-mudo.sqlite" 120 121
base_dionaea "$TMP/dio-justo.sqlite" 5
base_dionaea "$TMP/dio-vacia.sqlite"

comprueba "con actividad reciente no se avisa de nada" \
    "0" "$(dionaea "$TMP/dio-sano.sqlite" | grep -c 'SIN ANOTAR')"
comprueba "y se siguen viendo las conexiones por servicio" \
    "1" "$(dionaea "$TMP/dio-sano.sqlite" | grep -c 'smbd: 2 conexiones')"

# EL CASO DEL INCIDENTE, tal cual paso: cinco dias.
comprueba "cinco dias sin anotar nada se cantan" \
    "1" "$(dionaea "$TMP/dio-mudo.sqlite" | grep -c 'SIN ANOTAR NADA DESDE HACE 120 h')"
comprueba "y se dice cuando fue la ultima, no solo que no hay" \
    "1" "$(dionaea "$TMP/dio-mudo.sqlite" | grep -c 'ultima: 20')"
# El sintoma no se parece a la causa: el proceso esta VIVO. Sin la orden
# escrita, a las 6 de la manana se mira "docker ps", sale "Up", y se cierra.
comprueba "y la orden que lo diagnostica va escrita en el aviso" \
    "1" "$(dionaea "$TMP/dio-mudo.sqlite" | grep -c 'docker top dirtyland_dionaea')"

comprueba "por debajo del umbral no se avisa" \
    "0" "$(dionaea "$TMP/dio-justo.sqlite" | grep -c 'SIN ANOTAR')"
comprueba "el umbral se puede mover" \
    "1" "$( ( export DIONAEA_MUDO_HORAS=4
              dionaea "$TMP/dio-justo.sqlite" ) | grep -c 'SIN ANOTAR')"

# Una base recien creada NO puede dar la alarma: el dia de la instalacion
# diria "hace 500000 horas" y se aprenderia a ignorar el aviso.
comprueba "una base sin conexiones no da una alarma falsa" \
    "0" "$(dionaea "$TMP/dio-vacia.sqlite" | grep -c 'SIN ANOTAR')"
comprueba "pero lo dice, en vez de callarse" \
    "1" "$(dionaea "$TMP/dio-vacia.sqlite" | grep -c 'aun no hay ninguna conexion')"

comprueba "sin fichero de base no revienta" \
    "1" "$(dionaea "$TMP/no-esta.sqlite" | grep -c 'sin datos')"

echo
echo "El registro de ordenes tiene que estar cargado en los DOS sitios"
#
# En este apartado "(ninguna)" es la respuesta BUENA ---a esa maquina no se
# entra--- y por eso mismo es indistinguible de "el registro no esta puesto".
# Sin esta comprobacion, perder el gancho se leeria durante meses como
# tranquilidad.
#
# Y hacen falta los dos: /etc/profile.d solo lo leen los shells de LOGIN, asi
# que sin la linea de /etc/bash.bashrc un shell de root abierto con "sudo su"
# no anota NADA. Es el punto ciego que se encontro el 2026-08-29.
registro() {   # $1 = fichero de perfil, $2 = fichero bashrc
    ( REGISTRO_PERFIL="$1"; REGISTRO_BASHRC="$2"
      # shellcheck source=/dev/null
      . "$TMP/fn.sh"; registro_incompleto )
}

: > "$TMP/perfil-ok.sh"
printf '[ -r /etc/profile.d/dirtyland-registro.sh ] && . /etc/profile.d/dirtyland-registro.sh\n' \
    > "$TMP/bashrc-ok"
printf '# un bash.bashrc cualquiera, sin nuestra linea\n' > "$TMP/bashrc-sin"

comprueba "con los dos puestos, no dice nada" "" \
    "$(registro "$TMP/perfil-ok.sh" "$TMP/bashrc-ok")"
comprueba "si falta el de profile.d, avisa" "1" \
    "$(registro "$TMP/no-existe.sh" "$TMP/bashrc-ok" | grep -c 'NO ESTA COMPLETO')"
comprueba "y dice cual falta" "1" \
    "$(registro "$TMP/no-existe.sh" "$TMP/bashrc-ok" | grep -c 'no-existe.sh')"

# EL CASO DEL PUNTO CIEGO: el de profile.d esta, todo parece bien, y sin
# embargo un shell de root con "sudo su" no registra nada.
comprueba "si bash.bashrc no lo carga, avisa igual" "1" \
    "$(registro "$TMP/perfil-ok.sh" "$TMP/bashrc-sin" | grep -c 'NO ESTA COMPLETO')"
comprueba "y explica QUE se pierde, no solo que falta" "1" \
    "$(registro "$TMP/perfil-ok.sh" "$TMP/bashrc-sin" | grep -c 'sudo su')"

comprueba "si faltan los dos, los nombra a los dos" "1" \
    "$(registro "$TMP/no-existe.sh" "$TMP/bashrc-sin" | grep -c 'no-existe.sh.*bash.*sudo su')"
# Un bash.bashrc que no se puede leer cuenta como que no lo carga: mas vale
# avisar de mas que dar por bueno lo que no se ha podido mirar.
comprueba "un bashrc ilegible cuenta como que falta" "1" \
    "$(registro "$TMP/perfil-ok.sh" "$TMP/ni-existe" | grep -c 'NO ESTA COMPLETO')"

echo
echo "El reparto de motivos no se puede quedar viejo"
comprueba "los grupos del parte son los mismos que los del reporter" \
    "iguales" "$(python3 - "$FUENTE" "$BASE_PY" <<'FIN_PY'
import re
import sys


def pares(texto, nombre):
    bloque = re.search(nombre + r" = \{(.*?)\n *\}", texto, re.S)
    return dict(re.findall(r'"([^"]+)": "([^"]+)"', bloque.group(1)))


a = pares(open(sys.argv[1], encoding="utf-8").read(), "GRUPOS")
b = pares(open(sys.argv[2], encoding="utf-8").read(), "GRUPOS_MOTIVO")
print("iguales" if a == b else "distintos: %s" % sorted(set(a.items()) ^ set(b.items())))
FIN_PY
)"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
