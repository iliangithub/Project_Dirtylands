# SPDX-License-Identifier: BSD-3-Clause
"""
tr emulado.

POR QUE ESTE Y NO OTRO. Lo dice la maquina: que_le_falta_al_senuelo.py cruza
los binarios que el sistema de ficheros ANUNCIA con los que Cowrie sabe
ejecutar, y ordena lo que falta por las veces que alguien lo ha tecleado de
verdad contra el senuelo. En 90 dias de log, "tr" salio 276 veces --- el
primero de la lista, por delante de sed (132) y de openssl (6).

Y no fallaba callando: el pickle declara /usr/bin/tr, asi que un
"cat x | tr -d '\\r'" contestaba "Exec format error" en mitad de la tuberia.
Un binario que el propio dpkg da por instalado y que no arranca es de las
contradicciones mas faciles de ver.

TODO ESTA MEDIDO contra el coreutils 9.7 de un debian:trixie:

    tr a-z A-Z          traduce
    tr -d '\\r'          borra
    tr -s ' '           aprieta repetidos
    tr -cd '[:print:]\\n' complemento y borrado
    tr                  -> tr: missing operand
                           Try 'tr --help' for more information.       (1)
    echo x | tr a       -> tr: missing operand after 'a'
                           Two strings must be given when translating.
                           Try 'tr --help' for more information.       (1)

SE TRABAJA EN BYTES, no en texto. Lo que pasa por aqui suele ser la salida de
un binario o un fichero descargado, y decodificarlo a UTF-8 para volver a
codificarlo lo corrompe en cuanto haya un byte que no sea texto. El
"latin-1" de abajo no es una eleccion de idioma: es la unica tabla que mapea
los 256 bytes a 256 caracteres sin perder ninguno.
"""

from __future__ import annotations

import string

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}

CLASES = {
    "alpha": string.ascii_letters,
    "digit": string.digits,
    "alnum": string.ascii_letters + string.digits,
    "upper": string.ascii_uppercase,
    "lower": string.ascii_lowercase,
    "space": " \t\n\v\f\r",
    "blank": " \t",
    "punct": string.punctuation,
    "print": "".join(chr(c) for c in range(0x20, 0x7F)),
    "graph": "".join(chr(c) for c in range(0x21, 0x7F)),
    "cntrl": "".join(chr(c) for c in range(0, 32)) + "\x7f",
    "xdigit": string.hexdigits,
}

ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
           "t": "\t", "v": "\v", "\\": "\\"}


def expande(texto: str) -> list[str]:
    """Un conjunto de tr, ya desplegado en caracteres sueltos.

    Entiende lo que entiende el de verdad: clases "[:digit:]", rangos "a-z",
    escapes "\\n" y octales "\\015", y la repeticion "[x*3]".
    """
    salida: list[str] = []
    i = 0
    while i < len(texto):
        # [:clase:]
        if texto.startswith("[:", i):
            fin = texto.find(":]", i + 2)
            if fin > 0:
                nombre = texto[i + 2:fin]
                salida.extend(CLASES.get(nombre, ""))
                i = fin + 2
                continue
        # [x*n] --- repetir. Sin numero, se rellena luego hasta la otra tabla.
        if texto.startswith("[", i) and "*" in texto[i:i + 8]:
            fin = texto.find("]", i)
            cuerpo = texto[i + 1:fin] if fin > 0 else ""
            if fin > 0 and "*" in cuerpo:
                ch, _, veces = cuerpo.partition("*")
                try:
                    salida.extend(ch * int(veces or 0, 0))
                except ValueError:
                    salida.extend(ch)
                i = fin + 1
                continue
        # escapes
        if texto[i] == "\\" and i + 1 < len(texto):
            sig = texto[i + 1]
            if sig in ESCAPES:
                salida.append(ESCAPES[sig])
                i += 2
                continue
            if sig.isdigit():
                j = i + 1
                while j < len(texto) and j < i + 4 and texto[j].isdigit():
                    j += 1
                try:
                    salida.append(chr(int(texto[i + 1:j], 8) & 0xFF))
                except ValueError:
                    salida.append(sig)
                i = j
                continue
            salida.append(sig)
            i += 2
            continue
        # rango a-z
        if i + 2 < len(texto) and texto[i + 1] == "-" and texto[i + 2] != "]":
            ini, fin_c = ord(texto[i]), ord(texto[i + 2])
            if fin_c >= ini:
                salida.extend(chr(c) for c in range(ini, fin_c + 1))
                i += 3
                continue
        salida.append(texto[i])
        i += 1
    return salida


class Command_tr(FallaAlAvisar, HoneyPotCommand):
    def start(self) -> None:
        self.borrar = self.apretar = self.complemento = self.truncar = False
        conjuntos: list[str] = []
        for a in self.args:
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                for letra in a[1:]:
                    if letra == "d":
                        self.borrar = True
                    elif letra == "s":
                        self.apretar = True
                    elif letra in ("c", "C"):
                        self.complemento = True
                    elif letra == "t":
                        self.truncar = True
                    else:
                        self.errorWrite(
                            "tr: invalid option -- '%s'\n" % letra)
                        self.errorWrite(
                            "Try 'tr --help' for more information.\n")
                        self.exit_code = 1
                        self.exit()
                        return
            else:
                conjuntos.append(a)

        if not conjuntos:
            self.errorWrite("tr: missing operand\n")
            self.errorWrite("Try 'tr --help' for more information.\n")
            self.exit_code = 1
            self.exit()
            return
        # Con -d basta un conjunto; traduciendo hacen falta dos, y el de
        # verdad lo dice en TRES lineas, no en una.
        if len(conjuntos) < 2 and not (self.borrar or self.apretar):
            self.errorWrite("tr: missing operand after '%s'\n" % conjuntos[0])
            self.errorWrite("Two strings must be given when translating.\n")
            self.errorWrite("Try 'tr --help' for more information.\n")
            self.exit_code = 1
            self.exit()
            return

        # UN TERCER CONJUNTO NO SE MIRABA, y el efecto era el peor posible:
        # "tr a b fichero" ---confundirlo con sed o con cat es facil--- no
        # decia nada y se quedaba esperando por la entrada. La sesion se veia
        # colgada sin estarlo.
        if len(conjuntos) > 2:
            self.errorWrite("tr: extra operand '%s'\n" % conjuntos[2])
            self.errorWrite("Try 'tr --help' for more information.\n")
            self.exit()
            return

        self.set1 = expande(conjuntos[0])
        self.set2 = expande(conjuntos[1]) if len(conjuntos) > 1 else []
        if self.complemento:
            dentro = set(self.set1)
            self.set1 = [chr(c) for c in range(256) if chr(c) not in dentro]

        if self.input_data:
            self.writeBytes(self.transforma(self.input_data))
            self.exit()

    def transforma(self, datos: bytes) -> bytes:
        texto = datos.decode("latin-1")
        set1, set2 = self.set1, self.set2

        if self.borrar:
            fuera = set(set1)
            texto = "".join(c for c in texto if c not in fuera)
            # "-d -s": se borra con el PRIMER conjunto y se aprieta con el
            # SEGUNDO. Con solo -d no se aprieta nada.
            if self.apretar and set2:
                texto = self._aprieta(texto, set(set2))
            return texto.encode("latin-1")

        if set2:
            # El segundo conjunto se rellena con su ULTIMO caracter hasta
            # igualar al primero; con -t se recorta el primero en su lugar.
            if self.truncar:
                set1 = set1[:len(set2)]
            elif len(set2) < len(set1):
                set2 = set2 + [set2[-1]] * (len(set1) - len(set2))
            tabla = {ord(a): b for a, b in zip(set1, set2)}
            texto = texto.translate(tabla)

        if self.apretar:
            texto = self._aprieta(texto, set(set2 or set1))
        return texto.encode("latin-1")

    @staticmethod
    def _aprieta(texto: str, cuales: set) -> str:
        salida: list[str] = []
        for c in texto:
            if salida and c == salida[-1] and c in cuales:
                continue
            salida.append(c)
        return "".join(salida)

    def lineReceived(self, line: str) -> None:
        self.writeBytes(self.transforma((line + "\n").encode("latin-1")))

    def eofReceived(self) -> None:
        self.exit()


commands["/usr/bin/tr"] = Command_tr
commands["tr"] = Command_tr
