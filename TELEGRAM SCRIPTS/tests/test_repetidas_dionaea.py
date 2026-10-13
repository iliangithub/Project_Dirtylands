#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_repetidas_dionaea.py --- la memoria que impide que Dionaea repita el
mismo aviso cada cinco minutos.

    python3 "TELEGRAM SCRIPTS/tests/test_repetidas_dionaea.py"

Existe por una captura de pantalla: la misma IP, el mismo puerto y el mismo
enlace en CADA mensaje de las 10:30, 10:35 y 10:40. Un escaner insistente
dejaba 288 avisos al dia el solo, y un aviso que llega 288 veces se aprende a
ignorar --- que es la unica forma de que la vigilancia falle del todo.

Las funciones se EXTRAEN del script que se despliega y se ejecutan con bash de
verdad: copiarlas aqui seria probar una copia que se queda vieja sin avisar.

EL FALLO QUE CAZA, y que la primera version tenia: la clave de la memoria es
"ip|servicio|puerto" y el fichero separa por "|", asi que con la clave DELANTE
el `read` la partia en tres y los numeros se leian corridos. La memoria
cargaba siempre "0 veces" y no callaba a nadie: todo parecia funcionar y el
spam seguia igual. Por eso la clave va la ULTIMA, que es donde la ultima
variable de un `read` se queda con el resto de la linea entera.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(AQUI), "DIONAEA", "dionaea-watch.sh")

OK = MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print(f"  ok    {que}")
    else:
        MAL += 1
        print(f"  FALLO {que}\n          esperaba {esperado!r}\n"
              f"          obtuvo   {obtenido!r}")


def trozo(nombre: str) -> str:
    """El cuerpo de una funcion del script, tal cual se despliega."""
    texto = open(SCRIPT, encoding="utf-8").read()
    m = re.search(r"^%s\(\) \{.*?^\}" % re.escape(nombre), texto,
                  re.S | re.M)
    if not m:
        raise SystemExit("no encuentro la funcion %s en %s" % (nombre, SCRIPT))
    return m.group(0)


def corre(guion: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(guion)
        ruta = f.name
    try:
        r = subprocess.run(["bash", ruta], capture_output=True, text=True)
        return r.stdout + r.stderr
    finally:
        os.unlink(ruta)


CABECERA = """set -u
MEMORIA="$1"
MEMORIA_DIAS=30
declare -A MEM_VECES MEM_ULTIMO MEM_ACUM
%s

%s
""" % (trozo("memoria_cargar"), trozo("memoria_guardar"))

print("== la memoria de Dionaea ==")

with tempfile.TemporaryDirectory() as tmp:
    fichero = os.path.join(tmp, "mem.state")
    ahora = 1788530000

    # Una clave con DOS separadores dentro, que es como son todas.
    guion = CABECERA + '''
MEM_VECES["1.2.3.4|SMB|445"]=2
MEM_ULTIMO["1.2.3.4|SMB|445"]=%d
MEM_ACUM["1.2.3.4|SMB|445"]=17
memoria_guardar
unset MEM_VECES MEM_ULTIMO MEM_ACUM
declare -A MEM_VECES MEM_ULTIMO MEM_ACUM
memoria_cargar
echo "veces=${MEM_VECES[1.2.3.4|SMB|445]:-AUSENTE}"
echo "ultimo=${MEM_ULTIMO[1.2.3.4|SMB|445]:-AUSENTE}"
echo "acum=${MEM_ACUM[1.2.3.4|SMB|445]:-AUSENTE}"
''' % ahora
    salida = corre(guion.replace('MEMORIA="$1"', 'MEMORIA="%s"' % fichero))
    comprueba("una clave con '|' dentro sobrevive al guardar y cargar",
              ["veces=2", "ultimo=%d" % ahora, "acum=17"],
              [l for l in salida.split("\n") if "=" in l][:3])

    # Y lo que caduca se va, que si no el fichero crece sin freno.
    guion = CABECERA + '''
MEM_VECES["nueva|SMB|445"]=1
MEM_ULTIMO["nueva|SMB|445"]=$(date -u +%s)
MEM_ACUM["nueva|SMB|445"]=0
MEM_VECES["vieja|SMB|445"]=9
MEM_ULTIMO["vieja|SMB|445"]=1
MEM_ACUM["vieja|SMB|445"]=0
memoria_guardar
cat "$MEMORIA"
'''
    salida = corre(guion.replace('MEMORIA="$1"', 'MEMORIA="%s"' % fichero))
    comprueba("una entrada vieja se olvida al guardar", False,
              "vieja|SMB|445" in salida)
    comprueba("   y la reciente se queda", True, "nueva|SMB|445" in salida)

# --- La forma del fichero, que es donde estaba el fallo --------------------
_texto = open(SCRIPT, encoding="utf-8").read()
_lectura = re.search(r"while IFS='\|' read -r ([^;]+); do", _texto)
comprueba("la clave se lee la ULTIMA, o el '|' que lleva dentro la parte",
          "clave", (_lectura.group(1).split()[-1] if _lectura else "?"))
_escritura = re.search(r"printf '%s\|%s\|%s\|%s\\n'(.*?)>> ", _texto, re.S)
# La continuacion de linea deja una barra al final, asi que se quita antes de
# mirar cual es el ultimo argumento.
_cola = re.sub(r"[\s\\]+$", "", _escritura.group(1)) if _escritura else ""
comprueba("   y se escribe tambien la ultima", True,
          _cola.endswith('"$clave"'))

# --- Y que las tres constantes existan y sean configurables ---------------
for _nombre in ("DIONAEA_AVISOS_POR_IP", "DIONAEA_REAVISO_HORAS",
                "DIONAEA_RESUMEN_HORAS"):
    comprueba("%s se puede cambiar sin tocar el codigo" % _nombre, True,
              "${%s:-" % _nombre in _texto)

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
