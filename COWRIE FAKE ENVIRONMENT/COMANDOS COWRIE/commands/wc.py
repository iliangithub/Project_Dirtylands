# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: wc de coreutils, con sus columnas, su orden fijo y su relleno.
# ABOUTME: Sustituye al de la imagen, que contaba mal y casi nunca imprimia.
#
# EL DE LA IMAGEN NO SERVIA. Cuatro cosas, todas visibles a la primera:
#
#   * "wc" sin opciones no imprimia NADA ---ni con fichero ni por tuberia---
#     porque el bucle que escribe recorre la lista de opciones, y sin
#     opciones la lista esta vacia. Lo mas comun de todo era lo unico que no
#     funcionaba.
#   * "-w" partia solo por espacios, asi que un texto con saltos de linea
#     contaba UNA palabra: "printf 'a\nb\nc\n' | wc -w" decia 1 y son 3.
#   * el nombre del fichero no salia nunca, ni la linea "total" de varios.
#   * "-m" y "-c" daban lo mismo, y con acentos no lo dan.
#
# Y no imprimia el relleno en columnas, que es lo que hace que la salida de
# wc se reconozca de un vistazo.
#
# EL ANCHO DE LAS COLUMNAS, que es lo menos evidente. Medido en Debian 13
# contra coreutils 9.7:
#
#   wc -l f1        -> "2 f1"            una sola columna y un solo fichero:
#                                        sin relleno
#   wc f1           -> " 2  5 10 f1"     f1 mide 10 bytes: dos digitos, todas
#                                        las columnas a 2
#   wc -l big f1    -> " 2000 big"       10010 bytes entre los dos: cinco
#   cat f1 | wc     -> "      2       5      10"
#
# O sea: el ancho sale del TAMANO EN BYTES de las entradas, no de las cifras
# que se imprimen. Por una tuberia ese tamano no se sabe de antemano y
# coreutils usa 7 fijo; por eso los mismos numeros salen con otro hueco
# segun vengan de un fichero o de un "|", y esa diferencia se ve.
from __future__ import annotations

import getopt

from cowrie.commands.coreutils_extra import bloque_version
from cowrie.shell.command import HoneyPotCommand

commands = {}

# En el orden en que coreutils las imprime, pase el que pase por la linea de
# ordenes: "wc -clwL" saca lineas, palabras, caracteres, bytes y largo.
COLUMNAS = (
    ("-l", "--lines"),
    ("-w", "--words"),
    ("-m", "--chars"),
    ("-c", "--bytes"),
    ("-L", "--max-line-length"),
)
POR_DEFECTO = ("-l", "-w", "-c")

# Cuando no se sabe cuanto va a entrar ---una tuberia--- coreutils reserva
# siete huecos por columna.
ANCHO_DESCONOCIDO = 7

AYUDA = """Usage: wc [OPTION]... [FILE]...
  or:  wc [OPTION]... --files0-from=F
Print newline, word, and byte counts for each FILE, and a total line if
more than one FILE is specified.  A word is a nonempty sequence of non white
space delimited by white space characters or by start or end of input.

With no FILE, or when FILE is -, read standard input.

The options below may be used to select which counts are printed, always in
the following order: newline, word, character, byte, maximum line length.
  -c, --bytes            print the byte counts
  -m, --chars            print the character counts
  -l, --lines            print the newline counts
      --files0-from=F    read input from the files specified by
                           NUL-terminated names in file F;
                           If F is - then read names from standard input
  -L, --max-line-length  print the maximum display width
  -w, --words            print the word counts
      --total=WHEN       when to print a line with total counts;
                           WHEN can be: auto, always, only, never
      --help        display this help and exit
      --version     output version information and exit

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Report any translation bugs to <https://translationproject.org/team/>
Full documentation <https://www.gnu.org/software/coreutils/wc>
or available locally via: info '(coreutils) wc invocation'
"""


def cuenta(datos: bytes, utf8: bool = False) -> dict[str, int]:
    """Las cinco cifras de un texto.

    "-m" cuenta CARACTERES y "-c" bytes, pero solo se diferencian si la
    maquina esta en una configuracion regional que sepa de caracteres. El
    senuelo no exporta LANG ---no lo hace ninguna sesion de las suyas--- asi
    que va en C, y en C un Debian de verdad da lo mismo con los dos: medido.
    """
    texto = datos.decode("utf-8", "replace")
    lineas = datos.count(b"\n")
    palabras = len(texto.split())
    # El largo maximo NO cuenta el salto de linea.
    largo = max((len(x) for x in texto.split("\n")), default=0)
    return {"-l": lineas, "-w": palabras,
            "-m": len(texto) if utf8 else len(datos),
            "-c": len(datos), "-L": largo}


class Command_wc(HoneyPotCommand):
    def start(self) -> None:
        idioma = self.environ.get("LC_ALL") or self.environ.get("LANG") or ""
        self.utf8 = "utf-8" in idioma.lower() or "utf8" in idioma.lower()
        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "cmlLw",
                ["bytes", "chars", "lines", "max-line-length", "words",
                 "total=", "files0-from=", "help", "version"])
        except getopt.GetoptError as err:
            if err.opt and len(err.opt) > 1:
                self.errorWrite(f"wc: unrecognized option '--{err.opt}'\n")
            else:
                self.errorWrite(f"wc: invalid option -- '{err.opt}'\n")
            self.errorWrite("Try 'wc --help' for more information.\n")
            self.exit_code = 1
            self.exit()
            return

        pedidas: list[str] = []
        for opt, _val in optlist:
            if opt == "--help":
                self.write(AYUDA)
                self.exit()
                return
            if opt == "--version":
                self.write(bloque_version(
                    "wc", "Paul Rubin and David MacKenzie"))
                self.exit()
                return
            for corta, larga in COLUMNAS:
                if opt in (corta, larga) and corta not in pedidas:
                    pedidas.append(corta)
        # El orden de la linea de ordenes da igual: siempre el mismo.
        columnas = [c for c, _l in COLUMNAS
                    if c in (pedidas or list(POR_DEFECTO))]

        ficheros = [a for a in args if a != "-"]
        if not ficheros and self.input_data is None and not args:
            # Sin fichero y sin nada por la entrada: un wc de verdad se queda
            # esperando. Aqui no hay a quien esperar, asi que cero de todo.
            self.imprime(cuenta(b"", self.utf8), columnas, ANCHO_DESCONOCIDO, None)
            self.exit()
            return

        if not ficheros:
            datos = self.input_data or b""
            # POR UNA TUBERIA EL ANCHO ES OTRO. Con "< fichero" coreutils si
            # puede preguntar cuanto mide y rellena como con un argumento;
            # con "|" no, y reserva siete. Cowrie ya distingue los dos casos:
            # marca stdin_from_pipe en la tuberia.
            de_tuberia = bool(getattr(
                getattr(self.protocol, "pp", None), "stdin_from_pipe", False))
            ancho = self.ancho(columnas, [len(datos)], 1, de_tuberia)
            self.imprime(cuenta(datos, self.utf8), columnas, ancho, None)
            self.exit()
            return

        leidos: list[tuple[str, bytes]] = []
        fallo = False
        directorio = False
        for nombre in ficheros:
            ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
            if self.fs.isdir(ruta):
                leidos.append((nombre, None))               # type: ignore[arg-type]
                directorio = True
                fallo = True
                continue
            try:
                leidos.append((nombre, self.fs.file_contents(ruta)))
            except Exception:                                  # noqa: BLE001
                self.errorWrite(f"wc: {nombre}: No such file or directory\n")
                fallo = True

        tamanos = [len(d) for _n, d in leidos if d is not None]
        ancho = self.ancho(columnas, tamanos, len(ficheros),
                           de_tuberia=directorio)
        total = dict.fromkeys(("-l", "-w", "-m", "-c", "-L"), 0)
        for nombre, datos in leidos:
            if datos is None:
                self.imprime(cuenta(b"", self.utf8), columnas, ancho, nombre)
                self.errorWrite(f"wc: {nombre}: Is a directory\n")
                continue
            cifras = cuenta(datos, self.utf8)
            self.imprime(cifras, columnas, ancho, nombre)
            for clave, valor in cifras.items():
                total[clave] = (max(total[clave], valor) if clave == "-L"
                                else total[clave] + valor)
        if len(ficheros) > 1:
            self.imprime(total, columnas, ancho, "total")
        if fallo:
            self.exit_code = 1
        self.exit()

    def ancho(self, columnas: list, tamanos: list, cuantos: int,
              de_tuberia: bool) -> int:
        """El hueco que se le deja a cada cifra.

        Una sola columna y una sola entrada van SIN relleno: es el caso de
        "wc -l fichero", que sale pegado a la izquierda.
        """
        if len(columnas) == 1 and cuantos <= 1:
            return 1
        if de_tuberia:
            return ANCHO_DESCONOCIDO
        return max(1, len(str(sum(tamanos))))

    def imprime(self, cifras: dict, columnas: list, ancho: int,
                nombre: str | None) -> None:
        linea = " ".join(str(cifras[c]).rjust(ancho) for c in columnas)
        if nombre is not None:
            linea += " " + nombre
        self.write(linea + "\n")

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="wc",
            input=line,
        )

    def eofReceived(self) -> None:
        self.exit()


commands["/usr/bin/wc"] = Command_wc
commands["/bin/wc"] = Command_wc
commands["wc"] = Command_wc
