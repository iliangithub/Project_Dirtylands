# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import stat as stmod
import time

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import (
    A_CTIME,
    A_GID,
    A_MODE,
    A_SIZE,
    A_TYPE,
    A_UID,
    T_DIR,
    T_LINK,
)

commands = {}

# EL DISCO ES UN NVMe, y eso ya lo dicen lsblk ("259:2"), df, /etc/fstab y un
# /proc/modules que carga "nvme" y no carga ni "ahci" ni "libata". Aqui
# poniamos "Device: 801h/2049d", y ese 2049 decodifica a major 8, minor 1:
# /dev/sda1. UN DISCO SATA. Contradecia a todo lo demas de la maquina.
#
# Ademas coreutils 9 ya no escribe ese formato: pone "major,minor" en decimal.
# Medido en un Debian 13.6: "Device: 252,1".
MAJOR, MINOR = 259, 2
DEV = (MAJOR << 8) | MINOR          # lo que veria %d;  %D es su hexadecimal

UIDMAP = {0: "root", 1000: "mihail", 1001: "admin", 1002: "user-ssh", 1003: "mykhailo", 1004: "alyosha"}


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


class Command_stat(FallaAlAvisar, HoneyPotCommand):
    def _name(self, uid: int) -> str:
        return UIDMAP.get(uid, str(uid))

    def call(self) -> None:
        # EL "-c" NO SE MIRABA: "stat -c '%s' fichero" tomaba el formato por
        # un nombre de fichero y contestaba "cannot statx '%s'". Y "stat -c"
        # es como se saca un dato suelto ---el tamano, el propietario--- desde
        # un guion, que es justo para lo que se usa.
        formato = None
        args = list(self.args)
        i = 0
        while i < len(args):
            if args[i] in ("-c", "--format", "--printf") and i + 1 < len(args):
                formato = args[i + 1]
                del args[i:i + 2]
                continue
            if args[i].startswith("--format=") or args[i].startswith("-c"):
                if args[i].startswith("--format="):
                    formato = args[i].split("=", 1)[1]
                elif len(args[i]) > 2:
                    formato = args[i][2:]
                if formato is not None:
                    del args[i]
                    continue
            i += 1
        paths = [a for a in args if not a.startswith("-")]
        terse = "-t" in args
        if not paths:
            self.errorWrite("stat: missing operand\nTry 'stat --help' for more information.\n")
            return
        for arg in paths:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if _cowrie_access_denied(
                self.fs, path,
                getattr(self.protocol.user, "uid", 0),
                getattr(self.protocol.user, "gid", 0), None,
            ):
                self.errorWrite(f"stat: cannot statx '{arg}': Permission denied\n")
                continue
            f = self.fs.getfile(path)
            if not f:
                self.errorWrite(
                    f"stat: cannot statx '{arg}': No such file or directory\n"
                )
                continue
            size = int(f[A_SIZE] or 0)
            mode = int(f[A_MODE])
            typ = f[A_TYPE]
            if typ == T_DIR:
                tstr = "directory"
            elif typ == T_LINK:
                tstr = "symbolic link"
            else:
                tstr = "regular file" if size else "regular empty file"
            blocks = (size + 511) // 512
            perm = stmod.filemode(mode)
            octal = format(mode & 0o7777, "04o")
            ctime = f[A_CTIME] or time.time()
            # El desfase se pide a strftime ("%z") en vez de fijarlo: Kyiv es
            # +0300 en verano y +0200 en invierno, asi que un valor escrito a
            # mano acierta medio ano y contradice al "date" el otro medio.
            # El contenedor va en Europe/Kyiv (TZ y /etc/localtime del compose),
            # asi que localtime ya da la hora buena; solo faltaba el desfase.
            tfmt = time.strftime("%Y-%m-%d %H:%M:%S.000000000 %z", time.localtime(ctime))
            uid = int(f[A_UID])
            gid = int(f[A_GID])
            if formato is not None:
                # Los mismos codigos que escribe coreutils. Los que no se emulan se
                # dejan tal cual en vez de inventarse un valor: un dato inventado se
                # cuela en un guion y no se nota, y uno sin sustituir se ve.
                reemplazos = {
                    "%n": arg, "%s": str(size), "%a": format(mode & 0o7777, "o"),
                    "%A": perm, "%F": tstr, "%U": self._name(uid),
                    "%G": self._name(gid),
                    "%u": str(uid), "%g": str(gid), "%h": "1",
                    "%i": str(abs(hash(path)) % 900000 + 100000),
                    "%b": str(blocks), "%B": "512",
                    "%Y": str(int(ctime)), "%X": str(int(ctime)),
                    "%Z": str(int(ctime)), "%f": format(mode, "x"),
                }
                salida = formato
                for clave, valor in reemplazos.items():
                    salida = salida.replace(clave, valor)
                self.write(salida.replace("\\n", "\n").replace("\\t", "\t") + "\n")
                continue

            if terse:
                self.write(
                    # EL MODO VA EN HEXADECIMAL y con los bits de tipo
                    # ("81a4" para un fichero normal 0644), no en octal; el
                    # dispositivo tambien en hexadecimal; y el penultimo campo
                    # es la fecha de CREACION, donde poniamos un 0. Medido:
                    # "... 81a4 0 0 fc01 34618755 1 0 0 <4 fechas> 4096".
                    f"{path} {size} {blocks} {mode:x} {uid} {gid} {DEV:x} "
                    f"{abs(hash(path)) % 900000 + 100000} 1 0 0 "
                    f"{int(ctime)} {int(ctime)} {int(ctime)} {int(ctime)} 4096\n"
                )
                continue
            self.write(f"  File: {arg}" + (f" -> {f[8]}\n" if typ == T_LINK and f[8] else "\n"))
            # ANCHO 10 Y TABULADOR, no 15 y un espacio. Medido:
            #   '  Size: 13        \tBlocks: 8          IO Block: 4096   ...'
            self.write(
                f"  Size: {size:<10}\tBlocks: {blocks:<10} IO Block: 4096   {tstr}\n"
            )
            # Y un espacio mas antes de "Links": el campo es %-11i seguido de
            # un espacio literal, no %-11i pegado.
            self.write(
                f"Device: {MAJOR},{MINOR}\tInode: "
                f"{abs(hash(path)) % 900000 + 100000:<11} Links: 1\n"
            )
            self.write(
                f"Access: ({octal}/{perm})  Uid: ( {uid:>4}/{self._name(uid):>8})   Gid: ( {gid:>4}/{self._name(gid):>8})\n"
            )
            self.write(f"Access: {tfmt}\n")
            self.write(f"Modify: {tfmt}\n")
            self.write(f"Change: {tfmt}\n")
            # ext4 SI guarda la fecha de creacion, y stat la ensena. El "-"
            # es lo que sale en un sistema de ficheros que no la registra, y
            # el nuestro se declara ext4 en fstab, en df y en mount.
            self.write(f" Birth: {tfmt}\n")


commands["stat"] = Command_stat
commands["/usr/bin/stat"] = Command_stat
commands["/bin/stat"] = Command_stat
