# SPDX-License-Identifier: BSD-3-Clause
#
# du. El de Cowrie NO ESCRIBIA NADA: un "du -h /tmp/x" contestaba con una
# linea en blanco. Y du es de lo que se teclea nada mas entrar, para ver si
# la maquina tiene sitio donde dejar algo.
#
# Lo que cuenta du es el espacio EN DISCO, no el tamano del fichero: un
# fichero de dos bytes ocupa un bloque de 4 KiB y du dice 4. Por eso "du" y
# "ls -l" del mismo fichero dan numeros distintos, y copiar el de ls seria un
# delator para quien sepa mirar. Medido contra coreutils 9.7 en un Debian 13:
#
#     du -h fichero-de-2-bytes  ->  4.0K<TAB>ruta
#     du    fichero-de-2-bytes  ->  4<TAB>ruta
#     du -b fichero-de-2-bytes  ->  2<TAB>ruta     (ese si es el tamano real)
#
# El separador es un TABULADOR, no espacios: un "du | cut -f2" cuenta con eso.
from __future__ import annotations

from cowrie.shell import fs
from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}

BLOQUE = 4096          # lo que ocupa de verdad el fichero mas pequeno


def humano(kib: int) -> str:
    """El "-h" de coreutils: una cifra decimal y sufijo, redondeando arriba."""
    valor = float(kib)
    for sufijo in ("K", "M", "G", "T"):
        if valor < 1024 or sufijo == "T":
            if valor < 10 and valor != int(valor):
                return "%.1f%s" % (valor, sufijo)
            if valor < 10:
                return "%.1f%s" % (valor, sufijo)
            return "%d%s" % (round(valor), sufijo)
        valor /= 1024
    return "%d" % kib


class Command_du(FallaAlAvisar, HoneyPotCommand):
    def _ocupa(self, nodo) -> int:
        """KiB en disco de un nodo, redondeando al bloque."""
        tam = nodo[fs.A_SIZE] or 0
        if nodo[fs.A_TYPE] == fs.T_DIR:
            return 4
        return ((tam + BLOQUE - 1) // BLOQUE) * (BLOQUE // 1024)

    def _recorre(self, ruta: str, nodo, hondo: int) -> int:
        """Suma un arbol y va escribiendo lo que toca por el camino."""
        total = self._ocupa(nodo)
        if nodo[fs.A_TYPE] == fs.T_DIR:
            for hijo in nodo[fs.A_CONTENTS]:
                sub = ruta.rstrip("/") + "/" + hijo[fs.A_NAME]
                total += self._recorre(sub, hijo, hondo + 1)
        # du escribe los subdirectorios ANTES que el padre, porque va
        # sumando de abajo arriba. Los ficheros sueltos de dentro no se
        # escriben salvo que se pida "-a".
        if not self.resumen and (nodo[fs.A_TYPE] == fs.T_DIR or hondo == 0
                                 or self.todos):
            self._linea(total if nodo[fs.A_TYPE] == fs.T_DIR
                        else self._ocupa(nodo), ruta)
        return total

    def _linea(self, kib: int, ruta: str) -> None:
        if self.bytes_reales:
            try:
                tam = self.fs.getfile(
                    self.fs.resolve_path(ruta, self.protocol.cwd))[fs.A_SIZE]
            except Exception:                                  # noqa: BLE001
                tam = kib * 1024
            self.write("%d\t%s\n" % (tam or 0, ruta))
            return
        self.write("%s\t%s\n" % (humano(kib) if self.humano else kib, ruta))

    def call(self) -> None:
        banderas = "".join(a[1:] for a in self.args
                           if a.startswith("-") and not a.startswith("--"))
        self.humano = "h" in banderas
        self.resumen = "s" in banderas
        self.todos = "a" in banderas
        self.bytes_reales = "b" in banderas
        rutas = [a for a in self.args if not a.startswith("-")] or ["."]

        for ruta in rutas:
            entera = self.fs.resolve_path(ruta, self.protocol.cwd)
            try:
                nodo = self.fs.getfile(entera)
            except Exception:                                  # noqa: BLE001
                nodo = None
            if not nodo:
                self.errorWrite("du: cannot access '%s': No such file or "
                                "directory\n" % ruta)
                self.exit_code = 1
                continue
            total = self._recorre(ruta, nodo, 0)
            if self.resumen:
                self._linea(total, ruta)


commands["du"] = Command_du
commands["/usr/bin/du"] = Command_du
commands["/bin/du"] = Command_du
