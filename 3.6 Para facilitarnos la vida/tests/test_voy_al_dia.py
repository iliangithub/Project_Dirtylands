#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_voy_al_dia.py --- el sello de version, y que el README no se quede viejo.

    python3 "3.6 Para facilitarnos la vida/tests/test_voy_al_dia.py"

La herramienta se simplifico a proposito el 2026-08-29. Antes llevaba dentro
un mapa de las nueve piezas, fichero a fichero, y comparaba cada uno con su
copia desplegada: cazaba mas ---un despliegue a medias, por ejemplo--- pero
habia que tocarla cada vez que se anadia un fichero. Una herramienta que hay
que mantener al dia para que te diga si vas al dia acaba sobrando.

Ahora solo compara dos sellos. Las comprobaciones del README de mas abajo se
quedan, porque esas si valen y no hay que mantenerlas: salen de mirar el disco.
"""

from __future__ import annotations

import importlib.util
import io
import os
import re
import shutil
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(os.path.dirname(AQUI))

OK = 0
MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>"
              % (que, esperado, obtenido))


tmp = tempfile.mkdtemp()
carpeta = os.path.join(tmp, "repo", "3.6 Para facilitarnos la vida")
os.makedirs(carpeta)
sello_repo = os.path.join(carpeta, "VERSION")
sello_maquina = os.path.join(tmp, "opt", "VERSION")


def cargar():
    """Otra instancia del modulo, con el entorno que tenga puesto ahora."""
    os.environ["DIRTYLAND_REPO"] = os.path.join(tmp, "repo")
    os.environ["DIRTYLAND_SELLO"] = sello_maquina
    spec = importlib.util.spec_from_file_location(
        "aldia", os.path.join(AQUI, "..", "voy_al_dia.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def correr(*args):
    """Ejecuta main() y devuelve (codigo, salida)."""
    m = cargar()
    real, sys.argv = sys.argv, ["voy_al_dia.py", *args]
    buf, sys.stdout = io.StringIO(), None
    sys.stdout = buf
    try:
        codigo = m.main()
    finally:
        sys.stdout = sys.__stdout__
        sys.argv = real
    return codigo, buf.getvalue()


def pon_sello(ruta, commit):
    with io.open(ruta, "w", encoding="utf-8") as fh:
        fh.write("# de donde viene\ncommit  %s\nfecha   2026-08-29T19:40:00+02:00\n"
                 % commit)


print()
print("Los tres estados que puede haber")
pon_sello(sello_repo, "c" * 40)

codigo, salida = correr()
comprueba("sin marcar, lo dice y sale con error", 1, codigo)
comprueba("y explica como marcarlo", True, "--marcar" in salida)

codigo, salida = correr("--marcar")
comprueba("marcar sale bien", 0, codigo)
comprueba("y deja el sello puesto", True, os.path.exists(sello_maquina))

codigo, salida = correr()
comprueba("con el mismo commit, al dia", 0, codigo)
comprueba("y lo dice en una palabra", True, "AL DIA" in salida)

pon_sello(sello_repo, "7" * 40)
codigo, salida = correr()
comprueba("con otro commit, atrasado", 1, codigo)
comprueba("y se ven los dos", True,
          "ccccccc" in salida and "7777777" in salida)

print()
print("Lo que se niega a dar por bueno")
# Un sello sin sustituir significa que la carpeta se trajo a mano en vez de
# con `git archive`, que es lo que el README prohibe. Comparar dos marcadores
# daria un "al dia" que no significa nada.
with io.open(sello_repo, "w", encoding="utf-8") as fh:
    fh.write("commit  $Format:%H$\n")
codigo, salida = correr()
comprueba("un sello sin sustituir no cuenta como version", 2, codigo)
comprueba("y manda subirla como toca", True, "README" in salida)

os.remove(sello_repo)
codigo, salida = correr()
comprueba("sin copia del repositorio, tampoco", 2, codigo)

# La salida entera cabe en cuatro lineas: es lo que se mira de un vistazo
# antes de exponer, no un informe.
pon_sello(sello_repo, "c" * 40)
codigo, salida = correr()
comprueba("y toda la salida cabe en cuatro lineas", True,
          len([x for x in salida.splitlines() if x.strip()]) <= 4)

shutil.rmtree(tmp, ignore_errors=True)

# --------------------------------------------------------------------------
print()
print("El README no se puede quedar viejo")
readme = io.open(os.path.join(RAIZ, "README.md"), encoding="utf-8").read()

# 1. LA LISTA DE SUITES del apartado 3.7.10. Se desfaso varias veces en un
#    solo dia, una por cada suite nueva, y solo se veia mirandola a mano. Una
#    suite que no esta listada no la ejecuta quien reinstala: ni la corre ni
#    se entera de que existe.
# El anclaje NO es el nombre de una suite concreta. Lo fue, y se rompio en
# cuanto una nueva quedo la primera de la lista: la prueba fallaba diciendo
# que el README no traia el bloque, que era mentira. Se busca el <pre> que
# mas nombres de suite contiene, que es una propiedad del bloque y no del
# orden en que salgan.
# Y no es un <pre>: lo fue, hasta que la salida de ejemplo se recorto a cuatro
# lineas y la lista completa paso a la tabla "Suite | Vigila". Se busca la
# TABLA con mas suites en su primera columna.
bloques = re.findall(r"(?:^\|.*\n)+", readme, re.M)
suites_de = lambda b: set(re.findall(r"^\|\s*`(test[^`\s]*\.(?:py|sh))`\s*\|", b, re.M))
bloque = max(bloques, key=lambda b: len(suites_de(b)), default="")
comprueba("el README trae la lista de suites", True, len(suites_de(bloque)) > 5)
if bloque:
    listadas = suites_de(bloque)
    en_disco = set()
    for carpeta_, dirs, nombres in os.walk(RAIZ):
        # NO SE BAJA A .git NI A .claude. Dentro de ".claude/worktrees" el
        # entorno de trabajo crea OTRAS COPIAS del repositorio ---una por tarea
        # en paralelo---, y los ficheros de una copia no son ficheros nuevos:
        # contandolos, esta comprobacion pedia al README una suite que ya
        # estaba listada, o una que todavia vivia en otra rama. Salia en rojo
        # sin que hubiera nada que arreglar, que es la forma mas rapida de
        # ensenar a no mirar los rojos.
        dirs[:] = [d for d in dirs if d not in (".git", ".claude")]
        if ".git" in carpeta_:
            continue
        for n in nombres:
            if re.match(r"^test_.*\.py$|^test-.*\.sh$", n):
                en_disco.add(n)
    comprueba("y no falta ninguna de las que hay en disco",
              [], sorted(en_disco - listadas))
    comprueba("ni sobra ninguna que ya no exista",
              [], sorted(listadas - en_disco))

# 2. TODO FICHERO QUE EL README MANDA COPIAR TIENE QUE EXISTIR. Es la
#    comprobacion que sustituye a la del mapa de piezas, y esta no hay que
#    mantenerla: sale de leer el propio README. Caza lo que de verdad rompe
#    una reinstalacion ---renombrar o mover un fichero y no tocar la guia---,
#    y ahi el fallo no se ve hasta que alguien pega el comando y le dice que
#    no existe.
# Ojo con las comillas: media docena de rutas del README llevan un espacio
# dentro ("TELEGRAM SCRIPTS/..."), asi que cortar por espacios las parte y
# esta comprobacion se pone a fallar por su propia culpa.
rutas = set()
for comillas, acentos, suelta in re.findall(
        r'"/tmp/dirtyland-repo/([^"]+)"'
        r'|`/tmp/dirtyland-repo/([^`]+)`'
        r'|/tmp/dirtyland-repo/([^\s"\'`]+)', readme):
    rutas.add(comillas or acentos or suelta)
faltan = []
for rel in sorted(rutas):
    rel = rel.rstrip('".,/')
    if "*" in rel or not rel:
        continue
    if not os.path.exists(os.path.join(RAIZ, rel)):
        faltan.append(rel)
comprueba("todo lo que el README manda copiar existe en el repositorio",
          [], faltan)

# 3. EL ORDEN DE LOS PASOS, no solo que existan. Una guia se sigue de arriba
#    abajo, y un paso que depende de otro posterior no se ve leyendo: se ve
#    cuando alguien la ejecuta y algo falla. Ya paso el 2026-08-31, con el
#    generador de volumenes: se regenero el compose ANTES de instalar la
#    version nueva del generador, asi que salio un compose valido y con los
#    montajes viejos ---sin dar ningun error---.
#
#    Cada pareja es (lo que tiene que ir antes, lo que va despues).
DEPENDENCIAS = [
    ('docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/shell/protocol.py',
     'generar-volumes-cowrie.sh --apply',
     'el protocol.py hay que sacarlo del contenedor antes de generar los '
     'montajes: el generador se para si no lo encuentra'),
    ('parche-protocol.py" /opt/dirtyland/',
     'parche-protocol.py /opt/dirtyland/cowrie/parches/protocol.py',
     'el parcheador se instala antes de usarlo'),
    ('DOCKER-COMPOSE/generar-volumes-cowrie.sh"',
     'generar-volumes-cowrie.sh --apply',
     'el generador se instala antes de ejecutarlo --- si no, se regenera '
     'el compose con la lista de montajes vieja y nada avisa'),
    ('ayudas-comandos.json" /opt/dirtyland/cowrie/etc/ayudas-comandos.json',
     'generar-volumes-cowrie.sh --apply',
     'el JSON de ayudas tiene que estar antes de que se escriba su montaje'),
]
for antes, despues, por_que in DEPENDENCIAS:
    i, j = readme.find(antes), readme.find(despues)
    if i < 0 or j < 0:
        comprueba("el README trae los dos pasos de: %s" % por_que, True, False)
        continue
    comprueba("va antes: %s" % por_que, True, i < j)

# 4. Y UN PASO QUE NO ES UN FICHERO, asi que no lo cubre lo anterior, y que
#    no puede perderse: sin la segunda carga del registro de ordenes,
#    /etc/profile.d cubre solo los shells de login y un "sudo su" no anota
#    NADA de lo que se teclee dentro.
comprueba("el README manda cargar el registro tambien desde bash.bashrc",
          True, "/etc/bash.bashrc" in readme and "dirtyland-registro" in readme)

print()
print("-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
