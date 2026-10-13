# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: El builtin ulimit de bash, con los limites que declara la maquina.
# ABOUTME: El de la imagen aceptaba las opciones y no escribia NADA.
#
# El de la imagen tenia el cuerpo entero en un "pass": "ulimit -n" ---la forma
# normal de llamarlo, y de lo primero que mira quien va a abrir muchos sockets
# o forkear--- no imprimia ni una linea. Y "ulimit -a" tampoco. Una linea en
# blanco donde va un numero no se parece a un error: se parece a que el shell
# no sabe hacerlo.
#
# Los valores estan medidos en un Debian 13 dentro de un contenedor, que es lo
# que es esta maquina. "max user processes" y "pending signals" dependen de la
# RAM, y esta declara 16 GB: por eso 55100 y no otra cifra.
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

# (letra, etiqueta, unidad, valor). El orden es el que saca "ulimit -a".
LIMITES = [
    ("R", "real-time non-blocking time", "microseconds", "unlimited"),
    ("c", "core file size", "blocks", "unlimited"),
    ("d", "data seg size", "kbytes", "unlimited"),
    ("e", "scheduling priority", "", "0"),
    ("f", "file size", "blocks", "unlimited"),
    ("i", "pending signals", "", "55100"),
    ("l", "max locked memory", "kbytes", "8192"),
    ("m", "max memory size", "kbytes", "unlimited"),
    ("n", "open files", "", "1024"),
    ("p", "pipe size", "512 bytes", "8"),
    ("q", "POSIX message queues", "bytes", "819200"),
    ("r", "real-time priority", "", "0"),
    ("s", "stack size", "kbytes", "8192"),
    ("t", "cpu time", "seconds", "unlimited"),
    ("u", "max user processes", "", "unlimited"),
    ("v", "virtual memory", "kbytes", "unlimited"),
    ("x", "file locks", "", "unlimited"),
]
POR_LETRA = {letra: valor for letra, _e, _u, valor in LIMITES}

USO = "ulimit: usage: ulimit [-SHacdefiklmnpqrstuvxPRT] [limit]\n"


def _linea(letra: str, etiqueta: str, unidad: str, valor: str) -> str:
    """El formato de "ulimit -a".

    El parentesis CIERRA SIEMPRE en la columna 40 ---por eso cada etiqueta
    lleva un relleno distinto---, y cuando no cabe se deja en dos espacios,
    que es lo que le pasa a la primera linea. Medido columna a columna: con
    otro relleno, un guion que corte por posicion saca basura.
    """
    cola = "(%s, -%s)" % (unidad, letra) if unidad else "(-%s)" % letra
    ancho = max(40 - len(cola), len(etiqueta) + 2)
    return "%s%s %s\n" % (etiqueta.ljust(ancho), cola, valor)


class Command_ulimit(HoneyPotCommand):
    def call(self) -> None:
        letras = ""
        for arg in self.args:
            if arg.startswith("-") and len(arg) > 1:
                letras += arg[1:]
            elif arg.startswith("+"):
                continue
            else:
                # "ulimit -n 4096": el senuelo no cambia nada, y bash tampoco
                # se queja si el valor cabe en el limite duro.
                return

        # -S y -H eligen el limite blando o el duro; aqui los dos valen igual.
        letras = letras.replace("S", "").replace("H", "")
        if not letras:
            # "ulimit" a secas es "ulimit -f".
            letras = "f"

        if "a" in letras:
            for letra, etiqueta, unidad, valor in LIMITES:
                self.write(_linea(letra, etiqueta, unidad, valor))
            return

        for letra in letras:
            if letra not in POR_LETRA:
                self.errorWrite("-bash: ulimit: %s: invalid option\n" % letra)
                self.errorWrite(USO)
                self.exit_code = 2
                return
        for letra in letras:
            self.write(POR_LETRA[letra] + "\n")


commands["ulimit"] = Command_ulimit
