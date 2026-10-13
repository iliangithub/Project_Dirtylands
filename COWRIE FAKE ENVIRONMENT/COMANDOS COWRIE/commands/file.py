# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import os
import stat as stmod

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell import fs as _fs
from cowrie.shell.fs import A_GID, A_MODE, A_TARGET, A_TYPE, A_UID, T_DIR, T_LINK

# Los tipos de nodo especial no siempre estan en versiones viejas del modulo:
# se piden con getattr para que la falta no tumbe el comando entero.
T_BLK = getattr(_fs, "T_BLK", -3)
T_CHR = getattr(_fs, "T_CHR", -4)

# Los numeros mayor/menor de los dispositivos de siempre. No se inventan: son
# los que asigna el kernel y los mismos en cualquier Linux.
# Medido: "/dev/zero: character special (1/5)".
DISPOSITIVOS = {
    "/dev/null": (1, 3), "/dev/zero": (1, 5), "/dev/full": (1, 7),
    "/dev/random": (1, 8), "/dev/urandom": (1, 9),
    "/dev/tty": (5, 0), "/dev/console": (5, 1), "/dev/ptmx": (5, 2),
}

commands = {}


def _cowrie_perm_ok(node, uid: int, gid: int, want: str) -> bool:
    mode = node[A_MODE]
    if uid == node[A_UID]:
        bit = 0o400 if want == "r" else 0o100
    elif gid == node[A_GID]:
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

EXTMAP = {
    ".sh": "POSIX shell script, ASCII text executable",
    ".py": "Python script, ASCII text executable",
    ".pl": "Perl script text executable",
    ".json": "JSON text data",
    ".txt": "ASCII text",
    ".log": "ASCII text",
    ".conf": "ASCII text",
    ".cfg": "ASCII text",
    ".md": "ASCII text",
    ".c": "C source, ASCII text",
    ".gz": "gzip compressed data",
    ".zip": "Zip archive data",
    ".tar": "POSIX tar archive",
    ".png": "PNG image data",
    ".pem": "PEM certificate",
    ".key": "PEM RSA private key",
}


class Command_file(FallaAlAvisar, HoneyPotCommand):
    def describe(self, arg: str) -> str:
        path = self.fs.resolve_path(arg, self.protocol.cwd)
        if _cowrie_access_denied(
            self.fs, path,
            getattr(self.protocol.user, "uid", 0),
            getattr(self.protocol.user, "gid", 0), None,
        ):
            return f"cannot open '{arg}' (Permission denied)"
        f = self.fs.getfile(path, follow_symlinks=False)
        if not f:
            return f"cannot open '{arg}' (No such file or directory)"
        typ = f[A_TYPE]
        modo = int(f[A_MODE])
        if typ == T_DIR:
            # El bit pegajoso SI se anuncia, y con coma: "/tmp: sticky,
            # directory". Es de las primeras cosas que se miran al buscar
            # donde escribir.
            return ("sticky, directory" if modo & stmod.S_ISVTX
                    else "directory")
        if typ == T_LINK:
            # Un enlace ROTO se dice que lo esta. Antes todos salian como si
            # apuntaran a algo, incluidos los que no.
            destino = f[A_TARGET]
            entero = destino if destino.startswith("/") else \
                self.fs.resolve_path(destino, os.path.dirname(path))
            roto = not self.fs.exists(entero)
            return f"{'broken ' if roto else ''}symbolic link to {destino}"
        if typ in (T_CHR, T_BLK):
            clase = "character" if typ == T_CHR else "block"
            mayor, menor = DISPOSITIVOS.get(path, (1, 3))
            return f"{clase} special ({mayor}/{menor})"
        for ext, desc in EXTMAP.items():
            if arg.endswith(ext):
                return desc
        if modo & stmod.S_IXUSR:
            # SETUID Y SETGID VAN DELANTE, separados por coma entre ellos pero
            # sin coma antes del "ELF". Medido:
            #   "setuid ELF 64-bit ..."   "setuid, setgid ELF 64-bit ..."
            # Es justo lo que mira quien busca por donde escalar, y hasta
            # ahora un binario setuid salia igual que cualquier otro.
            marcas = []
            if modo & stmod.S_ISUID:
                marcas.append("setuid")
            if modo & stmod.S_ISGID:
                marcas.append("setgid")
            prefijo = ", ".join(marcas) + " " if marcas else ""
            return prefijo + (
                "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
                "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
                "BuildID[sha1]=3c1e2f9a, for GNU/Linux 3.2.0, stripped"
            )
        return "ASCII text"

    def call(self) -> None:
        paths = [a for a in self.args if not a.startswith("-")]
        if not paths:
            self.errorWrite("Usage: file [OPTION...] [FILE...]\n")
            return
        width = max(len(p) for p in paths)
        for arg in paths:
            self.write(f"{arg}:{' ' * (width - len(arg))} {self.describe(arg)}\n")


commands["file"] = Command_file
commands["/usr/bin/file"] = Command_file
