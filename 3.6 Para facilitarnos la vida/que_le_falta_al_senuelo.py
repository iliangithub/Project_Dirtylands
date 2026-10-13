#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
que_le_falta_al_senuelo.py
Que binarios DICE tener el senuelo y no sabe ejecutar --- y cuales de esos los
han tecleado de verdad los atacantes.

    sudo ~/que_le_falta_al_senuelo.py              lo que importa, por uso
    sudo ~/que_le_falta_al_senuelo.py --todos      la lista entera
    sudo ~/que_le_falta_al_senuelo.py --dias 30    otra ventana de log
    sudo ~/que_le_falta_al_senuelo.py --tecleado   solo el ranking de comandos

EL PROBLEMA NO ES QUE FALTEN COMANDOS. Es que el senuelo se contradice a si
mismo, y eso no pasa en ningun Linux:

    $ ls -la /usr/bin/sed   ->  -rwxr-xr-x 1 root root 126424 Jan  5 2023 ...
    $ file /usr/bin/sed     ->  ELF 64-bit LSB pie executable, x86-64
    $ which sed             ->  /usr/bin/sed
    $ sed --version         ->  -bash: /usr/bin/sed: No such file or directory

Tres ordenes afirman que el fichero esta y la cuarta dice que no existe. Un
"command not found" seria mucho menos revelador: significaria que el binario
no esta instalado, cosa normal. Esto significa que la maquina miente.

POR QUE NO SE ARREGLA QUITANDO BINARIOS del sistema de ficheros. El `dpkg -l`
del senuelo sale de un Debian 13 de verdad y declara instalados coreutils,
sed, findutils y demas; commands/dpkg.py ya dice en su cabecera que el
`dpkg -l` y el sistema de ficheros tienen que contar lo mismo. Quitar
/usr/bin/sed dejaria un sed instalado segun dpkg y ausente en el disco:
cambiariamos una contradiccion por otra peor.

Y TAMPOCO SE ARREGLA EMULANDO LOS TRESCIENTOS. La mayoria no los teclea nadie,
y cada emulacion mala es un delator NUEVO: un sed que se equivoca en un caso
corriente es peor que un sed que no esta, porque para entonces el atacante ya
esta mirando la salida.

POR ESO ESTO CRUZA LAS DOS COSAS. La lista de lo que falta se ordena por lo
que los bots han tecleado DE VERDAD contra este senuelo, sacado del propio
cowrie.json. Asi la decision de que emular sale de los datos y no de lo que
uno se imagina que hace un Mirai.

NO CAMBIA NADA: solo lee.
"""
from __future__ import annotations

import argparse
import collections
import glob as _glob
import gzip
import json
import os
import pickle
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

PICKLE = "/opt/dirtyland/cowrie/fs/fs.pickle"
CONTENEDOR = "dirtyland_cowrie"
TXTCMDS = "/opt/dirtyland/cowrie/txtcmds"
LOGS = "/var/lib/docker/volumes/dirtyland_cowrie-var/_data/log/cowrie"
PATRON_LOG = "cowrie.json*"

# Donde vive un binario en un Debian. El orden es el del PATH.
DIRECTORIOS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
               "/sbin", "/bin")

# Indices del nodo del pickle de Cowrie.
A_NOMBRE, A_TIPO, A_CONTENIDO = 0, 1, 7

# Lo que separa un comando de otro en una linea. No se pretende parsear un
# shell: solo sacar el PRIMER nombre de cada tramo, que es el binario.
_CORTES = re.compile(r"[;\n]|\|\||&&|\||`|\$\(")


# Se le pregunta a Cowrie DENTRO del contenedor, que es el unico sitio donde
# esta la verdad: alli conviven los modulos de fabrica y los nuestros ---el
# cmdpatch se monta ENCIMA de la carpeta de comandos, fichero a fichero--- asi
# que listar esa carpeta da la union, que es lo que Cowrie carga de verdad.
#
# Leyendo solo el cmdpatch del anfitrion salia mal y de la forma mas
# enganosa: decia que faltaban wget, curl y uname, que llevan funcionando
# desde el primer dia porque vienen de fabrica y no los hemos parcheado.
_PREGUNTA = (
    "import pkgutil, importlib, cowrie.commands as C\n"
    "n=set()\n"
    "for _,m,_ in pkgutil.iter_modules(C.__path__):\n"
    "    try: mod=importlib.import_module('cowrie.commands.'+m)\n"
    "    except Exception: continue\n"
    "    for k in getattr(mod,'commands',{}): n.add(k.split('/')[-1])\n"
    "print('\\n'.join(sorted(n)))\n"
)


def catalogo() -> set[str]:
    """Lo que el senuelo SABE ejecutar, preguntandoselo a el."""
    sabe: set[str] = set()
    try:
        salida = subprocess.run(
            ["docker", "exec", CONTENEDOR, "/cowrie/cowrie-env/bin/python3",
             "-c", _PREGUNTA],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        sys.exit(f"no se pudo preguntar al contenedor: {exc}\n"
                 "  (esto necesita root y el senuelo levantado)")
    if salida.returncode != 0:
        sys.exit("el contenedor no contesto:\n" + (salida.stderr or "").strip()
                 + "\n  comprueba:  sudo docker ps --filter name=" + CONTENEDOR)
    sabe |= {l.strip() for l in salida.stdout.splitlines() if l.strip()}

    # Las salidas enlatadas tambien "funcionan": su ruta dentro de txtcmds ES
    # la ruta del binario en el senuelo.
    for _raiz, _dirs, ficheros in os.walk(TXTCMDS):
        for f in ficheros:
            if not f.endswith(".md"):
                sabe.add(f)
    return sabe


def _hijos(nodo):
    return nodo[A_CONTENIDO] or []


def _buscar(nodo, ruta, objetivo):
    if ruta == objetivo:
        return nodo
    for h in _hijos(nodo):
        r = ruta + "/" + h[A_NOMBRE]
        if objetivo == r or objetivo.startswith(r + "/"):
            encontrado = _buscar(h, r, objetivo)
            if encontrado is not None:
                return encontrado
    return None


def declarados() -> dict[str, str]:
    """{nombre: ruta} de lo que el sistema de ficheros dice tener."""
    try:
        with open(PICKLE, "rb") as fh:
            fs = pickle.load(fh)
    except (OSError, pickle.UnpicklingError) as exc:
        sys.exit(f"no se pudo leer {PICKLE}: {exc}")
    salida: dict[str, str] = {}
    for d in DIRECTORIOS:
        nodo = _buscar(fs, "", d)
        if nodo is None:
            continue
        for h in _hijos(nodo):
            # El primero que gane se queda, como en el PATH.
            salida.setdefault(h[A_NOMBRE], d + "/" + h[A_NOMBRE])
    return salida


# Lo que un shell ejecuta SIN que exista ningun binario. Que no aparezcan en
# /usr/bin no es una incoherencia: es lo normal. La lista sale de "compgen -b"
# en un bash 5.2 de Debian 13, mas los tres que son solo palabras del lenguaje.
BUILTINS = {
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd",
    "command", "compgen", "complete", "compopt", "continue", "declare",
    "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export",
    "false", "fc", "fg", "getopts", "hash", "help", "history", "jobs", "kill",
    "let", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd",
    "read", "readarray", "readonly", "return", "set", "shift", "shopt",
    "source", "suspend", "test", "times", "trap", "true", "type", "typeset",
    "ulimit", "umask", "unalias", "unset", "wait",
    "if", "for", "while",
}


def tecleados(dias: int) -> collections.Counter:
    """Que ha tecleado la gente, contado por binario.

    Se cuenta CADA tramo de la linea, no solo el primero: en
    `wget X || curl -O X || busybox wget X` hay tres binarios distintos y los
    tres cuentan.
    """
    corte = datetime.now(timezone.utc) - timedelta(days=dias)
    cuenta: collections.Counter = collections.Counter()
    ficheros = sorted(_glob.glob(os.path.join(LOGS, PATRON_LOG)))
    if not ficheros:
        print(f"  (aviso: no hay logs de Cowrie en {LOGS})", file=sys.stderr)
    for ruta in ficheros:
        abrir = gzip.open if ruta.endswith(".gz") else open
        try:
            with abrir(ruta, "rt", encoding="utf-8", errors="replace") as fh:
                for linea in fh:
                    if '"cowrie.command.' not in linea:
                        continue
                    try:
                        ev = json.loads(linea)
                    except ValueError:
                        continue
                    if not str(ev.get("eventid", "")).startswith("cowrie.command."):
                        continue
                    marca = ev.get("timestamp", "")
                    try:
                        if datetime.fromisoformat(
                                marca.replace("Z", "+00:00")) < corte:
                            continue
                    except ValueError:
                        pass
                    for tramo in _CORTES.split(str(ev.get("input", ""))):
                        tramo = tramo.strip().lstrip("(){}")
                        if not tramo:
                            continue
                        primero = tramo.split()[0]
                        # Una asignacion no es un binario: VAR=x cmd
                        while "=" in primero and not primero.startswith("/"):
                            partes = tramo.split(None, 1)
                            if len(partes) < 2:
                                primero = ""
                                break
                            tramo = partes[1]
                            primero = tramo.split()[0]
                        if primero:
                            cuenta[primero.split("/")[-1]] += 1
        except OSError:
            continue
    return cuenta


def main() -> int:
    p = argparse.ArgumentParser(
        description="Que dice tener el senuelo y no sabe ejecutar")
    p.add_argument("--dias", type=int, default=90)
    p.add_argument("--todos", action="store_true", help="la lista entera")
    p.add_argument("--tecleado", action="store_true",
                   help="solo el ranking de lo que se ha tecleado")
    a = p.parse_args()

    sabe = catalogo()
    dice = declarados()
    usado = tecleados(a.dias)
    faltan = {k: v for k, v in dice.items() if k not in sabe}

    print("=" * 72)
    print("  SABE EJECUTAR        : %d nombres" % len(sabe))
    print("  DICE TENER           : %d binarios" % len(dice))
    print("  DICE TENER Y NO SABE : %d   (%.0f%% de lo que anuncia)"
          % (len(faltan), 100.0 * len(faltan) / max(len(dice), 1)))
    print("=" * 72)

    if a.tecleado:
        print("\nLo mas tecleado en %d dias (los 40 primeros):" % a.dias)
        for nombre, n in usado.most_common(40):
            marca = "" if nombre in sabe else "   <-- NO SABE"
            print("  %6d  %s%s" % (n, nombre, marca))
        return 0

    # LO QUE IMPORTA: lo que falta Y ademas alguien ha tecleado.
    prioridad = [(n, usado[k], faltan[k]) for k, n in
                 ((k, k) for k in faltan) if usado[k]]
    prioridad.sort(key=lambda t: -t[1])

    print("\nQUE EMULAR PRIMERO --- lo que falta y ADEMAS se ha tecleado aqui")
    print("(%d dias de log; el numero son las veces que alguien lo escribio)\n"
          % a.dias)
    if not prioridad:
        print("  Ninguno. De todo lo que el senuelo no sabe ejecutar, no hay")
        print("  ni un caso de que un atacante lo haya tecleado en la ventana")
        print("  mirada. Emular cualquiera de ellos seria trabajo sin uso.")
    for nombre, veces, ruta in prioridad:
        print("  %6d  %-24s %s" % (veces, nombre, ruta))

    # Y LA DIRECCION CONTRARIA, que hasta ahora no miraba nadie: algo que el
    # senuelo SABE ejecutar y que la maquina NO dice tener. Es la misma
    # incoherencia del reves y se comprueba igual de facil ---"which X" no lo
    # encuentra, "dpkg -l" no lo declara, "ls /usr/bin/X" dice que no esta--- y
    # ademas es mas barata de arreglar: se anade el paquete a PACKAGES en
    # build-dirtyland-fs.sh y se regenera el pickle.
    #
    # Asi salio "file": se emula desde hace tiempo, y el Debian del que sale el
    # pickle no lo trae, porque se instala con --no-install-recommends.
    sobran = sorted(k for k in sabe
                    if k not in dice and k not in BUILTINS
                    and not k.startswith("/"))
    print("\nY AL REVES --- lo que SABE ejecutar y la maquina NO dice tener")
    print("(un 'which' o un 'dpkg -l' lo desmienten; se arregla anadiendo el")
    print(" paquete a PACKAGES en build-dirtyland-fs.sh y regenerando)\n")
    if not sobran:
        print("  Ninguno.")
    for k in sobran:
        print("  %-24s %s" % (k, "tecleado %d veces" % usado[k]
                              if usado[k] else ""))

    nunca = sorted(k for k in faltan if not usado[k])
    print("\nY %d que tampoco sabe ejecutar pero NADIE ha tecleado." % len(nunca))
    if a.todos:
        for k in nunca:
            print("    %s" % faltan[k])
    else:
        print("  (con --todos se listan)")

    print("\n" + "=" * 72)
    print("  Recuerda por que NO se arregla quitandolos del sistema de")
    print("  ficheros: el dpkg -l los declara instalados, y esa incoherencia")
    print("  seria peor que la de ahora. Se explica en la cabecera de este")
    print("  fichero y en la de commands/dpkg.py.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
