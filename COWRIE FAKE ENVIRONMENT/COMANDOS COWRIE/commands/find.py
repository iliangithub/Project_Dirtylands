# SPDX-FileCopyrightText: 2025 Onder7994
# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
find command
"""

from __future__ import annotations

import fnmatch
import os

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands = {}

# LAS TRES FORMAS DE -perm, que son las de GNU find:
#
#   -perm 2755    exacto: los doce bits, tal cual
#   -perm -4000   TODOS esos bits puestos   (el de "find / -perm -4000")
#   -perm /2000   ALGUNO de esos bits
#
# Sin esto, "find / -perm -4000" ---que es LA orden para buscar por donde
# escalar, la primera que se teclea y la que mas se copia y pega--- listaba
# la maquina entera, porque el "-perm" se colaba por la rama de "argumento
# desconocido" y el "-4000" tambien.
SIMBOLICOS = {"u=s": 0o4000, "u+s": 0o4000, "g=s": 0o2000, "g+s": 0o2000,
              "o=t": 0o1000, "o+t": 0o1000, "+t": 0o1000}


def analiza_perm(texto: str):
    """(bits, comparacion) o None si no se entiende."""
    # La tabla se mira ENTERA primero: "+t" esta en ella tal cual, y
    # quitandole antes el "+" se quedaba en "t", que no esta.
    if texto in SIMBOLICOS:
        return SIMBOLICOS[texto], "/" if texto.startswith("+") else "-"
    como = ""
    if texto[:1] in ("-", "/", "+"):
        como, texto = ("/" if texto[0] == "+" else texto[0]), texto[1:]
    if texto in SIMBOLICOS:
        return SIMBOLICOS[texto], como or "-"
    try:
        return int(texto, 8) & 0o7777, como
    except ValueError:
        return None


def _cowrie_perm_ok(node, uid: int, gid: int, want: str) -> bool:
    mode = node[fs.A_MODE]
    if uid == node[fs.A_UID]:
        bit = 0o400 if want == "r" else 0o100
    elif gid == node[fs.A_GID]:
        bit = 0o040 if want == "r" else 0o010
    else:
        bit = 0o004 if want == "r" else 0o001
    return bool(mode & bit)


def _cowrie_access_denied(fsobj, abspath: str, uid: int, gid: int, target_need) -> bool:
    if uid == 0:
        return False
    parts = [p for p in abspath.split("/") if p]
    cur = ""
    for i, part in enumerate(parts):
        cur = cur + "/" + part
        try:
            node = fsobj.getfile(cur, follow_symlinks=True)
        except Exception:
            return False
        if not node:
            return False
        need = target_need if i == len(parts) - 1 else "x"
        if need is None:
            continue
        if not _cowrie_perm_ok(node, uid, gid, need):
            return True
    return False


class Command_find(HoneyPotCommand):
    """
    find command
    """

    def start(self) -> None:
        self.maxdepth: int = 20
        self.name_pattern = None
        self.type_filter = None
        self.perm_bits = None
        self.perm_como = ""

        self.start_path = self.protocol.cwd

        idx = 0
        while idx < len(self.args):
            arg = self.args[idx]

            if arg == "-name":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-name`\n")
                    self.exit()
                    return
                self.name_pattern = self.args[idx]

            elif arg == "-type":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-type`\n")
                    self.exit()
                    return
                val = self.args[idx]
                if val in ("f", "d"):
                    self.type_filter = val
                else:
                    self.errorWrite("find: unknown argument to -type. Use 'f' or 'd'\n")
                    self.exit()
                    return

            elif arg == "-perm":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-perm'\n")
                    self.exit()
                    return
                analizado = analiza_perm(self.args[idx])
                if analizado is None:
                    self.errorWrite(
                        "find: invalid mode `%s'\n" % self.args[idx])
                    self.exit()
                    return
                self.perm_bits, self.perm_como = analizado

            elif arg == "-maxdepth":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-maxdepth`\n")
                    self.exit()
                    return
                try:
                    self.maxdepth = int(self.args[idx])
                except ValueError:
                    self.errorWrite("find: maxdepth must be an integer\n")
                    self.exit()
                    return

            elif not arg.startswith("-") and self.start_path == self.protocol.cwd:
                self.start_path = self.fs.resolve_path(arg, self.protocol.cwd)

            else:
                # El de verdad dice "predicate", y con acento grave y
                # apostrofe. Medido: find: unknown predicate `-inventado'
                self.errorWrite("find: unknown predicate `%s'\n" % arg)
                self.exit()
                return

            idx += 1

        # UNA RUTA QUE NO EXISTE SE DICE. Antes se recorria en silencio y
        # find salia con 0, como si el directorio estuviera vacio.
        if not self.fs.exists(self.start_path):
            self.errorWrite("find: '%s': No such file or directory\n"
                            % self.start_path)
            self.exit_code = 1
            self.exit()
            return
        try:
            raiz = self.fs.getfile(self.start_path, follow_symlinks=True)
        except Exception:                                      # noqa: BLE001
            raiz = None
        if raiz is None:
            self.exit()
            return
        self.find_recursive(raiz, self.start_path, 0)
        self.exit()

    # POR NODOS, NO POR RUTAS. Antes cada entrada se volvia a resolver desde
    # "/" ---exists, isdir, isfile y getfile, cuatro recorridos del arbol por
    # fichero---, asi que el coste crecia con el cuadrado del tamano. En un
    # directorio pequeno no se nota; en
    #
    #     find / -perm -4000
    #
    # ---que es LA orden para buscar por donde escalar, y de las primeras que
    # se teclean--- la sesion se quedaba colgada minutos y el atacante se iba.
    # El arbol ya esta en memoria: se recorre una vez y en cada nodo se mira
    # lo que hace falta.
    def find_recursive(self, nodo, path: str, depth: int) -> None:
        if depth > self.maxdepth:
            return
        if self._match(nodo, path):
            self.write(f"{path}\n")
        if nodo[fs.A_TYPE] != fs.T_DIR:
            return
        uid = getattr(self.protocol.user, "uid", 0)
        gid = getattr(self.protocol.user, "gid", 0)
        if uid != 0 and not _cowrie_perm_ok(nodo, uid, gid, "r"):
            self.errorWrite(f"find: '{path}': Permission denied\n")
            return
        cola = path if path.endswith("/") else path + "/"
        for hijo in (nodo[fs.A_CONTENTS] or []):
            self.find_recursive(hijo, cola + hijo[fs.A_NAME], depth + 1)

    def _match(self, nodo, path: str) -> bool:
        if self.name_pattern and not fnmatch.fnmatch(nodo[fs.A_NAME],
                                                     self.name_pattern):
            return False
        if self.type_filter == "f" and nodo[fs.A_TYPE] != fs.T_FILE:
            return False
        if self.type_filter == "d" and nodo[fs.A_TYPE] != fs.T_DIR:
            return False
        if self.type_filter == "l" and nodo[fs.A_TYPE] != fs.T_LINK:
            return False
        if self.perm_bits is not None and not self._perm_ok(nodo):
            return False
        return True

    def _perm_ok(self, nodo) -> bool:
        bits = int(nodo[fs.A_MODE]) & 0o7777
        if self.perm_como == "-":
            return bits & self.perm_bits == self.perm_bits
        if self.perm_como == "/":
            return bool(bits & self.perm_bits)
        return bits == self.perm_bits


commands["find"] = Command_find
commands["/bin/find"] = Command_find
