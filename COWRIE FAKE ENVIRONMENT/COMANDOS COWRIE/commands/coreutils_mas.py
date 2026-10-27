# SPDX-License-Identifier: BSD-3-Clause
#
# arch, tty, stty, nice, timeout, realpath, paste, fold y expr.
#
# Los nueve los DECLARA el sistema de ficheros del senuelo ---son de coreutils,
# que va instalado--- y ninguno estaba emulado, asi que contestaban
#
#     -bash: /usr/bin/arch: No such file or directory
#
# que es la contradiccion de siempre y la peor de todas, porque un
# "command not found" seria normal y esto significa que la maquina miente:
# "ls -l /usr/bin/arch" lo ensena, "which" lo encuentra y "dpkg -l" declara
# coreutils. Es lo mismo que ya paso con basename, dirname, sort y rev.
#
# Todo medido contra los binarios de un Debian 13.
from __future__ import annotations

import re

from cowrie.commands.base import FallaAlAvisar
from cowrie.commands.coreutils_extra import bloque_version
from cowrie.shell.command import HoneyPotCommand

commands = {}


class _Coreutil(FallaAlAvisar, HoneyPotCommand):
    """Lo comun: --version y --help salen del mismo sitio que en los demas."""

    NOMBRE = ""
    AUTORES = ""

    def _atajos(self) -> bool:
        """True si el argumento era --version o --help y ya se ha contestado."""
        if "--version" in self.args:
            self.write(bloque_version(self.NOMBRE, self.AUTORES))
            return True
        return False

    def _no_es_opcion(self) -> list:
        return [a for a in self.args if not a.startswith("-") or a == "-"]


class Command_arch(_Coreutil):
    NOMBRE = "arch"
    AUTORES = "David MacKenzie and Karel Zak"

    def call(self) -> None:
        if self._atajos():
            return
        # DEL MISMO SITIO QUE uname -m. Son la misma cifra y escribirla dos
        # veces es como acaban contradiciendose.
        from cowrie.commands.uname import hardware_platform

        self.write(hardware_platform() + "\n")


class Command_tty(_Coreutil):
    NOMBRE = "tty"
    AUTORES = "David MacKenzie"

    def call(self) -> None:
        if self._atajos():
            return
        # La terminal es la que anuncia el entorno de la sesion. Por SSH sin
        # terminal ---"ssh maquina orden"--- no hay ninguna, y ahi tty dice
        # que no y devuelve 1.
        terminal = self.environ.get("SSH_TTY")
        if not terminal:
            if "-s" not in self.args:
                self.write("not a tty\n")
            self.exit_code = 1
            return
        if "-s" in self.args:
            return
        self.write(terminal + "\n")


class Command_stty(_Coreutil):
    NOMBRE = "stty"
    AUTORES = "David MacKenzie"

    # El bloque de "stty -a" de un Debian 13, con la primera linea aparte
    # porque lleva el tamano de la ventana, que es de cada sesion.
    RESTO = (
        "intr = ^C; quit = ^\\; erase = ^?; kill = ^U; eof = ^D;"
        " eol = <undef>;\n"
        "eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z;"
        " rprnt = ^R;\n"
        "werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;\n"
        "-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts\n"
        "-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl"
        " ixon -ixoff\n"
        "-iuclc -ixany -imaxbel iutf8\n"
        "opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0"
        " bs0 vt0 ff0\n"
        "isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop"
        " -echoprt\n"
        "echoctl echoke -flusho -extproc\n"
    )

    def _tamano(self) -> tuple:
        try:
            return (int(self.environ.get("LINES", "24")),
                    int(self.environ.get("COLUMNS", "80")))
        except ValueError:
            return (24, 80)

    def call(self) -> None:
        if self._atajos():
            return
        filas, columnas = self._tamano()
        if "size" in self.args:
            self.write("%d %d\n" % (filas, columnas))
            return
        if "-a" in self.args or "--all" in self.args:
            self.write("speed 38400 baud; rows %d; columns %d; line = 0;\n"
                       % (filas, columnas))
            self.write(self.RESTO)
            return
        if not self.args:
            self.write("speed 38400 baud; line = 0;\n")
            self.write("-brkint -imaxbel iutf8\n")
            return
        # Cualquier ajuste ---"stty -echo", "stty raw"--- se acepta y se calla,
        # que es lo que hace el de verdad cuando el ajuste es valido.


class Command_nice(_Coreutil):
    NOMBRE = "nice"
    AUTORES = "David MacKenzie"

    def call(self) -> None:
        if self._atajos():
            return

        prioridad = "0"
        resto: list = []
        i = 0
        while i < len(self.args):
            a = self.args[i]
            if resto:
                resto.append(a)
            elif a == "-n":
                i += 1
                prioridad = self.args[i] if i < len(self.args) else "0"
            elif a.startswith("-n"):
                prioridad = a[2:]
            elif a.startswith("--adjustment="):
                prioridad = a.split("=", 1)[1]
            elif a.startswith("-") and a[1:].lstrip("+-").isdigit():
                prioridad = a[1:]
            else:
                resto.append(a)
            i += 1
        if not resto:
            # Sin orden, nice escribe la prioridad ACTUAL, que es 0.
            self.write("0\n")
            return
        from cowrie.commands.bashbuiltins import _relanzar

        _relanzar(self, " ".join(resto))


class Command_timeout(_Coreutil):
    NOMBRE = "timeout"
    AUTORES = "Padraig Brady"

    def call(self) -> None:
        if self._atajos():
            return

        resto = [a for a in self.args
                 if not (a.startswith("-") and a not in ("-", "--"))]
        # El primero es la duracion. Aqui no se espera a nada: lo que se
        # ejecuta son ordenes emuladas y terminan en el acto, asi que el plazo
        # no llega a agotarse nunca ---igual que en un Linux para todo lo que
        # tarde menos que el plazo---.
        if len(resto) < 2:
            self.errorWrite("timeout: missing operand\n")
            self.errorWrite("Try 'timeout --help' for more information.\n")
            self.exit_code = 125
            return
        from cowrie.commands.bashbuiltins import _relanzar

        _relanzar(self, " ".join(resto[1:]))


class Command_realpath(_Coreutil):
    NOMBRE = "realpath"
    AUTORES = "Padraig Brady"

    def call(self) -> None:
        if self._atajos():
            return
        exige = any(a in ("-e", "--canonicalize-existing") for a in self.args)
        nombres = self._no_es_opcion()
        if not nombres:
            self.errorWrite("realpath: missing operand\n")
            self.errorWrite("Try 'realpath --help' for more information.\n")
            return
        for nombre in nombres:
            ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
            if exige and not self.fs.exists(ruta):
                self.errorWrite("realpath: %s: No such file or directory\n"
                                % nombre)
                continue
            self.write(ruta + "\n")


class Command_paste(_Coreutil):
    NOMBRE = "paste"
    AUTORES = "David M. Ihnat and David MacKenzie"

    def call(self) -> None:
        if self._atajos():
            return
        serie = False
        delimitadores = "\t"
        nombres: list = []
        i = 0
        while i < len(self.args):
            a = self.args[i]
            if a in ("-s", "--serial"):
                serie = True
            elif re.match(r"^-[sd]+", a) and not a.startswith("--") \
                    and "s" in a.split("d")[0]:
                # PEGADAS: "-sd," es lo que se escribe de verdad, y con las
                # opciones sueltas ---"-s -d,"--- si funcionaba. Se separa la
                # "s" y lo que venga detras de la "d" es el delimitador.
                serie = True
                if "d" in a:
                    delimitadores = a.split("d", 1)[1] or "\t"
                    if not delimitadores.strip("\t"):
                        i += 1
                        delimitadores = self.args[i] if i < len(self.args) \
                            else "\t"
            elif a == "-d":
                i += 1
                delimitadores = self.args[i] if i < len(self.args) else "\t"
            elif a.startswith("-d") and len(a) > 2:
                delimitadores = a[2:]
            elif a.startswith("--delimiters="):
                delimitadores = a.split("=", 1)[1]
            elif a.startswith("-") and a != "-":
                pass
            else:
                nombres.append(a)
            i += 1
        delimitadores = delimitadores.replace("\\t", "\t").replace("\\n", "\n")
        self.delim = delimitadores or "\t"

        columnas = []
        for nombre in (nombres or ["-"]):
            if nombre == "-":
                columnas.append(self._de_la_entrada())
                continue
            ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
            try:
                columnas.append(self._parte(self.fs.file_contents(ruta)))
            except Exception:                                  # noqa: BLE001
                self.errorWrite("paste: %s: No such file or directory\n"
                                % nombre)
                return

        if serie:
            # "-s" pone cada fichero ENTERO en una linea.
            for col in columnas:
                self.write(self._pega(col) + "\n")
            return
        # Sin "-s" se pegan de una en una: varias "-" reparten la MISMA
        # entrada, una linea por columna, que es el truco de "paste - -".
        if nombres.count("-") > 1:
            lineas = self._de_la_entrada()
            n = len(nombres)
            for i in range(0, len(lineas), n):
                self.write(self._pega(lineas[i:i + n]) + "\n")
            return
        for fila in zip(*columnas):
            self.write(self._pega(list(fila)) + "\n")

    def _pega(self, trozos: list) -> str:
        salida = ""
        for i, trozo in enumerate(trozos):
            if i:
                salida += self.delim[(i - 1) % len(self.delim)]
            salida += trozo
        return salida

    def _parte(self, datos: bytes) -> list:
        texto = datos.decode("utf-8", "replace")
        lineas = texto.split("\n")
        if lineas and lineas[-1] == "":
            lineas.pop()
        return lineas

    def _de_la_entrada(self) -> list:
        return self._parte(self.input_data or b"")


class Command_fold(_Coreutil):
    NOMBRE = "fold"
    AUTORES = "David MacKenzie"

    def call(self) -> None:
        if self._atajos():
            return
        ancho = 80
        por_espacios = False
        nombres: list = []
        i = 0
        while i < len(self.args):
            a = self.args[i]
            if a in ("-s", "--spaces"):
                por_espacios = True
            elif a in ("-b", "--bytes"):
                pass
            elif a == "-w":
                i += 1
                ancho = int(self.args[i]) if i < len(self.args) else 80
            elif a.startswith("-w"):
                ancho = int(a[2:] or 80)
            elif a.startswith("--width="):
                ancho = int(a.split("=", 1)[1])
            elif a.startswith("-") and a[1:].isdigit():
                ancho = int(a[1:])
            elif a.startswith("-") and a != "-":
                pass
            else:
                nombres.append(a)
            i += 1

        datos = self.input_data or b""
        if nombres and nombres[0] != "-":
            ruta = self.fs.resolve_path(nombres[0], self.protocol.cwd)
            try:
                datos = self.fs.file_contents(ruta)
            except Exception:                                  # noqa: BLE001
                self.errorWrite("fold: %s: No such file or directory\n"
                                % nombres[0])
                return
        for linea in datos.decode("utf-8", "replace").split("\n")[:-1] or []:
            for trozo in self._corta(linea, ancho, por_espacios):
                self.write(trozo + "\n")

    @staticmethod
    def _corta(linea: str, ancho: int, por_espacios: bool) -> list:
        if not linea:
            return [""]
        salida = []
        while len(linea) > ancho:
            corte = ancho
            if por_espacios:
                hueco = linea.rfind(" ", 0, ancho + 1)
                if hueco > 0:
                    corte = hueco + 1
            salida.append(linea[:corte])
            linea = linea[corte:]
        salida.append(linea)
        return salida


# --- expr -------------------------------------------------------------------
#
# El de los guiones viejos: "i=$(expr $i + 1)". No es un binario cualquiera,
# es el que usa cualquier bucle escrito antes de que bash tuviera $(( )), y
# sigue apareciendo en los droppers copiados de sitios antiguos.
_ENTERO = re.compile(r"^-?\d+$")


def _num(x: str) -> int:
    return int(x) if _ENTERO.match(x) else 0


class Command_expr(_Coreutil):
    NOMBRE = "expr"
    AUTORES = "Mike Parker"
    # expr sale con 1 si el resultado es cero o vacio, y con 2 si no entiende
    # la expresion. No es lo mismo y un guion mira ese codigo.
    CODIGO_DE_FALLO = 2

    def call(self) -> None:
        if self._atajos():
            return
        if not self.args:
            self.errorWrite("expr: missing operand\n")
            self.errorWrite("Try 'expr --help' for more information.\n")
            return
        try:
            valor = self._evalua(list(self.args))
        except _ErrorExpr as fallo:
            self.errorWrite("expr: %s\n" % fallo.args[0])
            return
        self.write("%s\n" % valor)
        if valor in ("0", ""):
            self.exit_code = 1

    def _evalua(self, args: list) -> str:
        if len(args) == 2 and args[0] == "length":
            return str(len(args[1]))
        if len(args) == 4 and args[0] == "substr":
            texto, desde, cuantos = args[1], _num(args[2]), _num(args[3])
            if desde < 1 or cuantos < 1:
                return ""
            return texto[desde - 1:desde - 1 + cuantos]
        if len(args) == 3 and args[0] == "index":
            for i, c in enumerate(args[1], 1):
                if c in args[2]:
                    return str(i)
            return "0"
        if len(args) == 3:
            return self._binario(args[0], args[1], args[2])
        if len(args) == 1:
            return args[0]
        raise _ErrorExpr(
            "syntax error: unexpected argument '%s'" % args[min(3, len(args) - 1)])

    @staticmethod
    def _binario(izq: str, operador: str, der: str) -> str:
        if operador == "|":
            return izq if izq not in ("", "0") else der
        if operador == "&":
            return izq if izq not in ("", "0") and der not in ("", "0") else "0"
        if operador == ":":
            emparejado = re.match(der, izq)
            if emparejado is None:
                return "0"
            return emparejado.group(1) if emparejado.groups() \
                else str(emparejado.end())
        COMPARA = {"=": "==", "==": "==", "!=": "!=", "<": "<", "<=": "<=",
                   ">": ">", ">=": ">="}
        if operador in COMPARA:
            if _ENTERO.match(izq) and _ENTERO.match(der):
                a, b = int(izq), int(der)
            else:
                a, b = izq, der
            resultado = {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b,
                         ">": a > b, ">=": a >= b}[COMPARA[operador]]
            return "1" if resultado else "0"
        if operador in ("+", "-", "*", "/", "%"):
            a, b = _num(izq), _num(der)
            if operador in ("/", "%") and b == 0:
                raise _ErrorExpr("division by zero")
            return str({"+": a + b, "-": a - b, "*": a * b,
                        "/": int(a / b) if b else 0,
                        "%": a - b * int(a / b) if b else 0}[operador])
        raise _ErrorExpr("syntax error: unexpected argument '%s'" % der)


class _ErrorExpr(Exception):
    pass


for _clase in (Command_arch, Command_tty, Command_stty, Command_nice,
               Command_timeout, Command_realpath, Command_paste,
               Command_fold, Command_expr):
    _nombre = _clase.NOMBRE
    commands[_nombre] = _clase
    commands["/usr/bin/" + _nombre] = _clase
    commands["/bin/" + _nombre] = _clase
