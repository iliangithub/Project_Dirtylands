#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_que_pasa_con_las_plataformas.py --- los dos contadores del dia, y que un
cambio de esquema vuelva a caer aqui en vez de quedarse en silencio.

    python3 "3.6 Para facilitarnos la vida/tests/test_que_pasa_con_las_plataformas.py"

Existe por un fallo que no se veia. El bloque de cada plataforma pedia la
columna `used` a las DOS tablas de contadores, y `api_calls` no la tiene: la
suya es `calls`, y quien lo fija es el esquema de
"REPORTING PLATFORM SCRIPTS/common/state.py". Asi que el SELECT de api_calls
lanzaba OperationalError, un `except sqlite3.Error: continue` se lo tragaba y
la linea de las llamadas de hoy NO SE IMPRIMIA NUNCA. Nada avisaba: el bloque
de la plataforma salia entero y con pinta de correcto, solo que sin ese dato.

Y es el dato que mas importa de los dos: el tope de VirusTotal son 500
peticiones al dia e incluye las consultas de hash, que son lo mas frecuente
con diferencia y lo que cuenta `api_calls`. Mirando solo `quota` ---que cuenta
lo PUBLICADO--- se puede agotar la cuota real con el contador marcando tres.
Es la misma distincion que vigila test-cuota-watch.sh en el vigilante de la
cuota, y por eso tambien tenia que estar vigilada aqui.

Lo que se comprueba:

  - que salgan LAS DOS lineas, y que cada numero venga de su tabla: con los
    dos numeros distintos a proposito, un SELECT que fuera a la tabla
    equivocada o que copiara el otro valor se ve;
  - que el esquema que manda es el DE VERDAD: la base sintetica se crea con el
    SCHEMA de state.py tal cual, asi que renombrar una de esas dos columnas
    alli rompe esta prueba en lugar de apagar la linea en produccion;
  - que si la tabla esta pero la columna no, la consulta REVIENTA. Es lo que
    antes se tragaba el except, y es el fallo nuestro que hay que ver;
  - que una base vieja SIN la tabla si se calla, porque ese es el unico caso
    en que callar estaba bien, y que el resto del bloque sale igual;
  - y que el contador es el de HOY y no el de cualquier dia.

No toca nada: monta una base de estado sintetica en un directorio temporal.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

AQUI = Path(__file__).resolve().parent
FUENTE = AQUI.parent / "que_pasa_con_las_plataformas.py"
ESQUEMA = (AQUI.parent.parent / "REPORTING PLATFORM SCRIPTS"
           / "common" / "state.py")

OK = 0
MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba %r\n          obtuvo   %r"
              % (que, esperado, obtenido))


spec = importlib.util.spec_from_file_location("plataformas", FUENTE)
plataformas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plataformas)

# El esquema NO se copia aqui: se saca del fichero que lo define. Una copia
# envejece sin avisar, y envejecer en silencio es justo el fallo que se esta
# probando.
texto = ESQUEMA.read_text(encoding="utf-8")
casa = re.search(r'SCHEMA = """(.*?)"""', texto, re.S)
if not casa:
    print("  FALLO no se encuentra el SCHEMA en %s" % ESQUEMA)
    sys.exit(1)
SCHEMA = casa.group(1)

tmp = Path(tempfile.mkdtemp())
HOY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
AYER = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def base_sintetica(nombre):
    """Una base de estado con las dos tablas y sus columnas de verdad."""
    ruta = tmp / nombre
    db = sqlite3.connect(ruta)
    db.executescript(SCHEMA)
    # Dos publicaciones y una simulada, que no cuenta como publicada.
    db.executemany(
        "INSERT INTO sent (platform, key, status, sent_at, detail)"
        " VALUES (?,?,?,?,?)",
        [("virustotal", "upload:aa", "ok", HOY + "T08:00:00+00:00", "subida"),
         ("virustotal", "vote:aa", "ok", HOY + "T08:01:00+00:00", "voto"),
         ("virustotal", "upload:bb", "simulado", HOY + "T08:02:00+00:00", None)])
    db.execute(
        "INSERT INTO rejections (ts, platform, key, gate, reason)"
        " VALUES (?,?,?,?,?)",
        (HOY + "T08:03:00+00:00", "virustotal", "cc", "veredicto",
         "VirusTotal todavia no la conoce"))
    # Los dos contadores, con numeros DISTINTOS a proposito: con el mismo
    # valor en las dos tablas no habria forma de ver que cada linea sale de
    # la suya.
    db.execute("INSERT INTO quota (platform, day, used) VALUES (?,?,?)",
               ("virustotal", HOY, 2))
    db.execute("INSERT INTO api_calls (platform, day, calls) VALUES (?,?,?)",
               ("virustotal", HOY, 417))
    # Y lo de ayer, para ver que no se cuela en el contador de hoy.
    db.execute("INSERT INTO api_calls (platform, day, calls) VALUES (?,?,?)",
               ("virustotal", AYER, 99))
    db.commit()
    db.close()
    return ruta


def salida_de(ruta, plataforma="virustotal"):
    """El bloque de una plataforma, tal cual lo imprime, contra esa base."""
    db = sqlite3.connect(ruta)
    db.row_factory = sqlite3.Row
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            plataformas.bloque(db, plataforma, None, True, None)
    finally:
        db.close()
    return buf.getvalue()


print()
print("Las dos lineas salen, y cada numero de SU tabla")
completa = base_sintetica("completa.sqlite3")
try:
    vista = salida_de(completa)
except sqlite3.Error as exc:
    vista = ""
    comprueba("el bloque no revienta con el esquema de state.py "
              "(si falla aqui, una de las dos columnas cambio de nombre): %s"
              % exc, True, False)
comprueba("sale la linea de las publicaciones (quota.used)",
          True, "publicaciones hoy: 2" in vista)
comprueba("y sale la de las llamadas (api_calls.calls), que no salia nunca",
          True, "llamadas hoy: 417" in vista)
comprueba("las llamadas no traen el numero de las publicaciones",
          False, "llamadas hoy: 2" in vista)
comprueba("ni las publicaciones el de las llamadas",
          False, "publicaciones hoy: 417" in vista)
comprueba("el contador es el de hoy, no el de ayer",
          False, "llamadas hoy: 99" in vista)
comprueba("y el bloque sigue trayendo lo suyo",
          True, "PUBLICADO: 2" in vista and "DESCARTADO: 1" in vista)

print()
print("Cada tabla con la columna que le da state.py, no una escrita a mano")
fuente = FUENTE.read_text(encoding="utf-8")


def contador_de(tabla):
    """La columna INTEGER de esa tabla, segun el esquema de state.py."""
    trozo = re.search(
        r"CREATE TABLE IF NOT EXISTS " + tabla + r" \((.*?)\);", SCHEMA, re.S)
    for linea in trozo.group(1).splitlines():
        campo = linea.strip().split()
        if len(campo) >= 2 and campo[1].upper() == "INTEGER":
            return campo[0]
    return None


for tabla, esperada in (("quota", "used"), ("api_calls", "calls")):
    comprueba("state.py sigue contando en %s.%s" % (tabla, esperada),
              esperada, contador_de(tabla))
    comprueba('y el script le pide "%s" a %s' % (esperada, tabla),
              True, '("%s", "%s"' % (tabla, esperada) in fuente)

# El que se tragaba el error estaba DENTRO de bloque(), envolviendo el SELECT,
# asi que se mira ahi y no en todo el fichero. Y se busca el "try:" y no la
# palabra del except: la explicacion de por que se quito lo cita, y entonces
# la prueba pasaria por la explicacion en vez de por el codigo.
cuerpo = fuente.split("def bloque(")[1].split("\ndef ")[0]
comprueba("y en bloque() no queda ningun try envolviendo la consulta, que es "
          "lo que se tragaba el error de esquema", False, "try:" in cuerpo)

print()
print("Un cambio de esquema tiene que verse")
# Se simula lo que pasaria manana si a api_calls le renombran la columna: la
# tabla esta, la consulta ya no vale. Eso es un fallo NUESTRO y tiene que
# reventar, porque callarlo es volver a la linea que no se imprimia.
renombrada = base_sintetica("columna_renombrada.sqlite3")
db = sqlite3.connect(renombrada)
db.executescript("DROP TABLE api_calls;"
                 "CREATE TABLE api_calls (platform TEXT NOT NULL,"
                 " day TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0);")
db.execute("INSERT INTO api_calls (platform, day, hits) VALUES (?,?,?)",
           ("virustotal", HOY, 417))
db.commit()
db.close()
revienta = False
try:
    salida_de(renombrada)
except sqlite3.OperationalError:
    revienta = True
comprueba("con la columna renombrada la consulta revienta, no se calla",
          True, revienta)

print()
print("Y una base vieja SIN la tabla si se calla, que es el caso legitimo")
vieja = base_sintetica("sin_api_calls.sqlite3")
db = sqlite3.connect(vieja)
db.executescript("DROP TABLE api_calls;")
db.commit()
db.close()
try:
    vista = salida_de(vieja)
except sqlite3.Error as exc:
    vista = ""
    comprueba("una tabla que no existe no puede tumbar el bloque: %s" % exc,
              True, False)
comprueba("no sale la linea de llamadas", False, "llamadas hoy" in vista)
comprueba("pero la de publicaciones si", True, "publicaciones hoy: 2" in vista)
comprueba("y el resto del bloque sale igual", True, "PUBLICADO: 2" in vista)

shutil.rmtree(tmp, ignore_errors=True)

print()
print("-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
