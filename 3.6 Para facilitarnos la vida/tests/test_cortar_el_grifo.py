#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_cortar_el_grifo.py --- el modo del cron y la conmutacion.

    python3 "3.6 Para facilitarnos la vida/tests/test_cortar_el_grifo.py"

Existe por un fallo que costo mas de un dia de reportes: el cron volvio a
simulacion al reinstalarlo y NADA lo dijo. Las pasadas seguian corriendo, el
log crecia y el parte diario ensenaba puntos verdes.

Lo que se comprueba:

  - que se distingue LIVE de SIMULACION y de "no hay fichero";
  - que conmutar deja SIEMPRE una sola linea activa, en los dos sentidos y
    repitiendolo (si dejara dos, se publicaria dos veces);
  - que los comentarios del fichero sobreviven, porque son la unica
    documentacion de para que es cada linea.

No toca el sistema: trabaja sobre copias en un directorio temporal.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

AQUI = Path(__file__).resolve().parent
FUENTE = AQUI.parent / "cortar_el_grifo.py"
PLANTILLA = (AQUI.parent.parent / "REPORTING PLATFORM SCRIPTS"
             / "cron.d" / "dirtyland-reporter")

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


spec = importlib.util.spec_from_file_location("grifo", FUENTE)
grifo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grifo)

tmp = Path(tempfile.mkdtemp())
cron = tmp / "dirtyland-reporter"
grifo.CRON = str(cron)


def activas() -> list[str]:
    """Las lineas de malware-watch que NO estan comentadas."""
    return [l.strip() for l in cron.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.lstrip().startswith("#")
            and "malware-watch.sh" in l]


print("\nLeer el modo")
comprueba("sin fichero devuelve None, que no es lo mismo que simulacion",
          None, grifo.cron_en_live())

shutil.copy2(PLANTILLA, cron)
comprueba("la plantilla del repositorio viene en SIMULACION",
          False, grifo.cron_en_live())

print("\nConmutar")
grifo.cambiar_cron(True)
comprueba("pasa a publicar", True, grifo.cron_en_live())
comprueba("y queda UNA sola linea activa", 1, len(activas()))
comprueba("que es la de --live", True, activas()[0].endswith("--live"))

grifo.cambiar_cron(True)
comprueba("repetirlo no acumula ni duplica", 1, len(activas()))

grifo.cambiar_cron(False)
comprueba("vuelve a simulacion", False, grifo.cron_en_live())
comprueba("y sigue habiendo una sola activa", 1, len(activas()))
comprueba("que ya no es la de --live",
          False, activas()[0].endswith("--live"))

print("\nLo que no se puede perder por el camino")
texto = cron.read_text(encoding="utf-8")
comprueba("la comprobacion diaria del self-test sigue ahi",
          True, "--self-test" in texto)
comprueba("y el vigilante del cortacircuitos tambien",
          True, "breaker-watch.sh" in texto)
comprueba("los comentarios del fichero sobreviven",
          True, texto.lstrip().startswith("#"))

shutil.rmtree(tmp, ignore_errors=True)

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
