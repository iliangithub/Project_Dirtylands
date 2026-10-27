#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_telnet_opciones.py — la negociacion de opciones de telnet de Cowrie.

    python3 "TELEGRAM SCRIPTS/tests/test_telnet_opciones.py"

Comprueba UNA invariante, y es la que tumbaba telnet entero:

    toda opcion que PEDIMOS tiene que aceptarse cuando nos la conceden.

Twisted lo exige por escrito. En twisted/conch/telnet.py, la rama que se
ejecuta cuando el cliente acepta algo que hemos pedido nosotros:

    def will_no_true(self, state, option):
        # Peer agreed to enable an option in response to our request.
        ...
        assert self.enableRemote(
            option
        ), "enableRemote must return True in this context (for option {!r})"

connectionMade pedia DO TERMINAL-TYPE, TSPEED, XDISPLOC y NEW-ENVIRON, pero
enableRemote solo decia que si a NEW-ENVIRON: las otras tres caian en el
"else: return False". Cliente acepta, salta el assert, se rompe la conexion, y
NINGUNA sesion de telnet llegaba al login.

No se importa el modulo --- depende de Twisted y de cowrie.core, que solo
existen dentro del contenedor. Se extraen las piezas del fichero real, para
que esto pruebe lo que se despliega y no una copia.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FUENTE = (Path(__file__).resolve().parent.parent.parent
          / "COWRIE FAKE ENVIRONMENT" / "COMANDOS COWRIE"
          / "telnet" / "userauth.py")

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


TEXTO = FUENTE.read_text(encoding="utf-8")

# Las constantes de opcion y el conjunto solicitado, tal cual estan escritos.
ns: dict = {}
for linea in TEXTO.split("\n"):
    if re.match(r"^(TTYPE|TSPEED|XDISPLOC|NEW_ENVIRON|ECHO|SGA|NAWS|LINEMODE)"
                r"\s*=\s*bytes\(\[\d+\]\)", linea):
        exec(linea.split("#")[0].strip(), ns)
# Las que vienen de twisted no estan definidas en el fichero.
for nombre, codigo in (("ECHO", 1), ("SGA", 3), ("TTYPE", 24),
                       ("NAWS", 31), ("LINEMODE", 34)):
    ns.setdefault(nombre, bytes([codigo]))

m = re.search(r"^OPCIONES_SOLICITADAS\s*=\s*\(([^)]*)\)", TEXTO, re.M)
if not m:
    sys.exit("no existe OPCIONES_SOLICITADAS en %s: las dos listas han vuelto "
             "a escribirse por separado" % FUENTE)
exec("OPCIONES_SOLICITADAS = (%s)" % m.group(1), ns)

# Y los dos metodos, colgados de un objeto minimo.
def extraer(nombre: str) -> str:
    patron = re.compile(r"^    def %s\(.*?(?=^    def |\Z)" % re.escape(nombre),
                        re.S | re.M)
    mm = patron.search(TEXTO)
    if not mm:
        sys.exit("no se encontro %s en %s" % (nombre, FUENTE))
    return mm.group(0)


exec("class Falso:\n" + extraer("enableRemote") + "\n" + extraer("enableLocal"),
     ns)
bot = ns["Falso"]()
SOLICITADAS = ns["OPCIONES_SOLICITADAS"]

NOMBRES = {ns["TTYPE"]: "TERMINAL-TYPE", ns["TSPEED"]: "TSPEED",
           ns["XDISPLOC"]: "XDISPLOC", ns["NEW_ENVIRON"]: "NEW-ENVIRON",
           ns["NAWS"]: "NAWS", ns["SGA"]: "SGA", ns["ECHO"]: "ECHO",
           ns["LINEMODE"]: "LINEMODE"}


def nombre(op):
    return NOMBRES.get(op, repr(op))


print("\nLa invariante que exige Twisted")
print("        opciones que pedimos: %s"
      % ", ".join(nombre(o) for o in SOLICITADAS))
for op in SOLICITADAS:
    comprueba("pedimos %s, luego lo aceptamos" % nombre(op),
              True, bot.enableRemote(op))

comprueba("y TERMINAL-TYPE esta entre las pedidas (era la que reventaba)",
          True, ns["TTYPE"] in SOLICITADAS)

print("\nLas dos listas son la misma, por construccion")
# Si alguien vuelve a escribir la lista a mano en connectionMade, esto falla.
cuerpo_cm = extraer("connectionMade")
comprueba("connectionMade recorre OPCIONES_SOLICITADAS, no una lista suya",
          True, "OPCIONES_SOLICITADAS" in cuerpo_cm)
comprueba("y no queda ninguna tupla de opciones escrita a mano ahi",
          False, bool(re.search(r"for opt in \(", cuerpo_cm)))

print("\nLo que NO pedimos")
comprueba("NAWS se acepta si el cliente lo ofrece", True,
          bot.enableRemote(ns["NAWS"]))
comprueba("SGA tambien", True, bot.enableRemote(ns["SGA"]))
comprueba("LINEMODE se rechaza (twisted no lo soporta)", False,
          bot.enableRemote(ns["LINEMODE"]))
comprueba("una opcion desconocida se rechaza", False,
          bot.enableRemote(bytes([99])))

print("\nEl lado local")
# telnet_User hace willChain(ECHO): mismo razonamiento, pero con enableLocal.
comprueba("ofrecemos ECHO, luego lo habilitamos", True,
          bot.enableLocal(ns["ECHO"]))
comprueba("SGA local se rechaza", False, bot.enableLocal(ns["SGA"]))
comprueba("willChain(ECHO) sigue en telnet_User", True,
          "willChain(ECHO)" in extraer("telnet_User"))

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
