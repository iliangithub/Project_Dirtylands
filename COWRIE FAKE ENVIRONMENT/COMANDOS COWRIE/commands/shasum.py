# SPDX-License-Identifier: BSD-3-Clause
# Familia de checksums SHA + BLAKE2 para Cowrie (Debian 13 coreutils).
# Modelado sobre md5sum.py: calcula el hash REAL del contenido del fichero
# emulado (honeyfs / redirecciones de la sesion).
from __future__ import annotations

import hashlib

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}


class _ShaBase(FallaAlAvisar, HoneyPotCommand):
    algo = "sha256"
    name = "sha256sum"

    def call(self) -> None:
        paths = [a for a in self.args if not a.startswith("-")]
        if not paths:
            # SIN FICHEROS SE LEE DE LA ENTRADA, que es la mitad de las veces
            # que se teclea esto: "cat binario | md5sum", o el "| sha256sum"
            # detras de una descarga. Antes se devolvia sin escribir nada, asi
            # que el atacante veia una linea en blanco donde esperaba su hash
            # ---y un hash vacio no se parece a un error, se parece a que el
            # fichero no tiene nada---.
            #
            # El nombre que escribe coreutils cuando lee de la entrada es un
            # guion: "0bee...  -". Medido.
            if self.input_data is not None:
                digest = hashlib.new(self.algo, self.input_data).hexdigest()
                self.write("%s  -\n" % digest)
            return
        for arg in paths:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if not self.fs.exists(path):
                self.errorWrite(f"{self.name}: {arg}: No such file or directory\n")
                continue
            if self.fs.isdir(path):
                self.errorWrite(f"{self.name}: {arg}: Is a directory\n")
                continue
            try:
                data = self.fs.file_contents(path)
            except Exception:
                data = b""
            digest = hashlib.new(self.algo, data).hexdigest()
            self.write(f"{digest}  {arg}\n")


class Command_sha1sum(_ShaBase):
    algo = "sha1"
    name = "sha1sum"


class Command_sha224sum(_ShaBase):
    algo = "sha224"
    name = "sha224sum"


class Command_sha256sum(_ShaBase):
    algo = "sha256"
    name = "sha256sum"


class Command_sha384sum(_ShaBase):
    algo = "sha384"
    name = "sha384sum"


class Command_sha512sum(_ShaBase):
    algo = "sha512"
    name = "sha512sum"


class Command_b2sum(_ShaBase):
    algo = "blake2b"   # coreutils b2sum = BLAKE2b-512 por defecto (128 hex)
    name = "b2sum"


for _n, _c in [
    ("sha1sum", Command_sha1sum),
    ("sha224sum", Command_sha224sum),
    ("sha256sum", Command_sha256sum),
    ("sha384sum", Command_sha384sum),
    ("sha512sum", Command_sha512sum),
    ("b2sum", Command_b2sum),
]:
    commands[_n] = _c
    commands["/usr/bin/" + _n] = _c
