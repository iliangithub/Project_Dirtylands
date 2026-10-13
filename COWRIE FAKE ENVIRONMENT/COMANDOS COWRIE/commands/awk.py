# SPDX-FileCopyrightText: 2020-2025 Michel Oosterhof <michel@oosterhof.net>
# SPDX-License-Identifier: BSD-3-Clause
#
# awk emulado. Viene del de Cowrie, con tres cosas cambiadas.
#
# 1. EL "-F" NO EXISTIA. La lista de opciones era "Fvf", sin dos puntos, o sea
#    que declaraba -F, -v y -f como banderas SIN argumento. Con eso:
#
#        awk -F : '{print $2}'   -> el ":" se tomaba por el programa y el
#                                   "{print $2}" por un fichero:
#                                   "awk: {print $2}: No such file or directory"
#        awk -F: '{print $2}'    -> "awk: invalid option -- ':'"
#
#    Ninguna de las dos formas funcionaba, y son LAS DOS que se teclean. Y
#    aunque hubiera pasado el troceo, el separador no se usaba en ningun
#    sitio: el codigo partia siempre por espacios y lo decia un TODO.
#
# 2. DECIA SER GNU AWK Y NO LO ES. "awk --version" contestaba "GNU Awk 4.1.4"
#    y la ayuda era la de gawk, con sus --characters-as-bytes y su gawk.info.
#    En Debian 13 el awk por defecto es MAWK: "dpkg -l" declara
#    mawk 1.3.4.20250131-1 y gawk ni siquiera esta instalado, asi que un
#    "awk --version" seguido de un "dpkg -l | grep awk" se contradecian solos.
#    Ahora la ayuda, la version y los mensajes de error son los de mawk,
#    medidos contra el binario: "awk: not an option: -Z" donde gawk dice
#    "invalid option", y "awk: cannot open ... (No such file or directory)"
#    donde el de antes decia "awk: x: No such file or directory".
#
# 3. NI NF NI NR. Se anaden porque son la mitad de lo que se teclea con awk
#    ---"awk '{print NF}'"--- y porque salen gratis al partir los campos.
from __future__ import annotations

import re
from re import Match

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}

# mawk pone 2 en cualquier error de uso. Sin programa NO es un error: saca la
# ayuda y sale con 0. Medido.
ERROR_USO = 2


class Command_awk(HoneyPotCommand):
    """
    awk command
    """

    # code is an array of dictionaries contain the regexes to match and the code to execute
    code: list[dict[str, str]]

    def start(self) -> None:
        self.fs_sep = " "          # FS, el separador de campos
        self.variables: dict[str, str] = {}
        programa: str | None = None
        ficheros: list[str] = []

        args = list(self.args)
        i = 0
        fin_opciones = False
        while i < len(args):
            a = args[i]
            if fin_opciones or not a.startswith("-") or a == "-":
                if programa is None and not self.variables.get("__de_fichero"):
                    programa = a
                else:
                    ficheros.append(a)
                i += 1
                continue
            if a == "--":
                fin_opciones = True
                i += 1
                continue
            if a in ("--version", "-W") and (a == "--version"
                                             or self._w(args, i) == "version"):
                self.version()
                self.exit()
                return
            if a in ("--help", "--usage") or (a == "-W"
                                              and self._w(args, i) in
                                              ("help", "usage")):
                self.help()
                self.exit()
                return
            if a.startswith("-W"):
                # Las de "-W" son las propias de mawk. Las que no cambian nada
                # de lo que emulamos se aceptan y se ignoran, que es mejor que
                # negarlas: un "-W interactive" no cambia una salida.
                i += 2 if a == "-W" else 1
                continue
            for letra, destino in (("F", "fs"), ("v", "var"), ("f", "prog")):
                if not a.startswith("-" + letra):
                    continue
                valor = a[2:]
                if not valor:
                    if i + 1 >= len(args):
                        self.errorWrite("awk: option -%s lacks argument\n"
                                        % letra)
                        self.exit_code = ERROR_USO
                        self.exit()
                        return
                    valor = args[i + 1]
                    i += 1
                if destino == "fs":
                    self.fs_sep = valor
                elif destino == "var":
                    nombre, _, val = valor.partition("=")
                    self.variables[nombre] = val
                else:
                    ruta = self.fs.resolve_path(valor, self.protocol.cwd)
                    try:
                        programa = self.fs.file_contents(ruta).decode(
                            "utf-8", "replace")
                    except Exception:                          # noqa: BLE001
                        self.errorWrite(
                            'awk: cannot open "%s" (No such file or '
                            "directory)\n" % valor)
                        self.exit_code = ERROR_USO
                        self.exit()
                        return
                    self.variables["__de_fichero"] = "1"
                break
            else:
                # mawk no dice "invalid option": dice "not an option".
                self.errorWrite("awk: not an option: %s\n" % a)
                self.exit_code = ERROR_USO
                self.exit()
                return
            i += 1

        if programa is None:
            self.help()
            self.exit()
            return

        self.variables.pop("__de_fichero", None)
        self.code = self.awk_parser(programa)

        if ficheros:
            for arg in ficheros:
                if arg == "-":
                    self.output(self.input_data)
                    continue
                pname = self.fs.resolve_path(arg, self.protocol.cwd)
                if self.fs.isdir(pname):
                    self.errorWrite(f"awk: {arg}: Is a directory\n")
                    continue
                try:
                    contents = self.fs.file_contents(pname)
                    self.output(contents)
                except FileNotFound:
                    self.errorWrite('awk: cannot open "%s" (No such file or '
                                    "directory)\n" % arg)
                    self.exit_code = ERROR_USO
        else:
            self.output(self.input_data)
        self.exit()

    @staticmethod
    def _w(args: list[str], i: int) -> str:
        """El valor de un "-W xxx", que puede ir pegado o suelto."""
        if args[i] != "-W":
            return args[i][2:]
        return args[i + 1] if i + 1 < len(args) else ""

    def campos(self, linea: str) -> list[str]:
        """Parte la linea segun FS, con las reglas de POSIX.

        Un FS de UN caracter que no sea el espacio parte por ese caracter tal
        cual, aunque sea un metacaracter: "-F." parte por puntos, no por
        cualquier cosa. De dos en adelante es una expresion regular, que es
        lo que hace util el "-F '[0-9]+'". Y el espacio, que es el de por
        defecto, parte por rachas y se come lo de los extremos.
        """
        if self.fs_sep == " ":
            return linea.split()
        if len(self.fs_sep) == 1:
            return linea.split(self.fs_sep)
        return re.split(self.fs_sep, linea)

    def awk_parser(self, program: str) -> list[dict[str, str]]:
        """
        search for awk execution patterns, either direct {} code or only executed for a certain regex
        { }
        /regex/ { }
        """
        code = []
        re1 = r"\s*(\/(?P<pattern>\S+)\/\s+)?\{\s*(?P<code>[^\}]+)\}\s*"
        matches = re.findall(re1, program)
        for m in matches:
            code.append({"regex": m[1], "code": m[2]})
        return code

    def awk_print(self, words: str) -> None:
        """
        This is the awk `print` command that operates on a single line only
        """
        self.write(words)
        self.write("\n")

    @staticmethod
    def separa_comas(texto: str) -> list[str]:
        """Parte por las comas que NO estan entre comillas."""
        partes: list[str] = []
        actual: list[str] = []
        dentro = False
        for c in texto:
            if c == '"':
                dentro = not dentro
            if c == "," and not dentro:
                partes.append("".join(actual))
                actual = []
                continue
            actual.append(c)
        partes.append("".join(actual))
        return partes

    @staticmethod
    def junta(argumentos: str) -> str:
        """Lo que separa una coma de un espacio en un print de awk.

        No son lo mismo y el de antes los trataba igual, con un
        re.sub(r"(,|\\s+)", " ", ...) que ponia un espacio para las dos cosas:

            print $1, $3   -> daba "a  c"  (dos espacios), mawk da "a c"
            print $1 $3    -> daba "a c",  mawk da "ac"

        La coma separa argumentos y entre ellos va OFS, que por defecto es UN
        espacio. Sin coma no hay separacion ninguna: los trozos se PEGAN, y
        por eso "print $1 \" \" $2" es la forma de meter un espacio a mano.
        """
        salida = []
        for parte in Command_awk.separa_comas(argumentos):
            trozos = re.findall(r'"([^"]*)"|(\S+)', parte)
            salida.append("".join(a if a else b for a, b in trozos))
        return " ".join(salida)

    def output(self, inb: bytes | None) -> None:
        """
        This is the awk output.
        """
        if inb:
            inp = inb.decode("utf-8")
        else:
            return

        inputlines = inp.split("\n")
        if inputlines[-1] == "":
            inputlines.pop()

        def repl(m: Match) -> str:
            try:
                return words[int(m.group(1))]
            except IndexError:
                return ""

        for numero, inputline in enumerate(inputlines, start=1):
            # $0 es la linea entera y del $1 en adelante van los campos, que
            # ahora salen de FS y no siempre de los espacios.
            words = self.campos(inputline)
            words.insert(0, inputline)

            for c in self.code:
                if re.match(c["regex"], inputline):
                    line = c["code"]
                    # NF y NR antes que los campos: si no, un "$NF" se
                    # quedaria sin resolver. Y con limites de palabra, o un
                    # "NFX" cualquiera se partiria por la mitad.
                    line = re.sub(r"\bNF\b", str(len(words) - 1), line)
                    line = re.sub(r"\bNR\b", str(numero), line)
                    for nombre, valor in self.variables.items():
                        line = re.sub(r"\b%s\b" % re.escape(nombre),
                                      valor, line)
                    line = re.sub(r"\$(\d+)", repl, line)
                    if re.match(r"^\s*print\b", line):
                        argumentos = re.sub(r"^\s*print\b", "", line).strip()
                        # "print" a secas imprime la linea entera. Antes no se
                        # contemplaba: como el re.sub pedia un espacio detras,
                        # un "{print}" se quedaba sin quitar la palabra y
                        # awk imprimia literalmente "print".
                        if not argumentos:
                            self.awk_print(words[0])
                            continue
                        self.awk_print(self.junta(argumentos))

    def lineReceived(self, line: str) -> None:
        """
        This function logs standard input from the user send to awk
        """
        self.protocol.events.dispatch(
            "cowrie.session.input",
            "INPUT (%(realm)s): %(input)s",
            realm="awk",
            input=line,
        )

        self.output(line.encode())

    def eofReceived(self) -> None:
        """
        ctrl-d is end-of-file, time to terminate
        """
        self.exit()

    def help(self) -> None:
        """La de mawk 1.3.4, medida. La de antes era la de gawk."""
        self.write(
            """Usage: mawk [Options] [Program] [file ...]

Program:
    The -f option value is the name of a file containing program text.
    If no -f option is given, a "--" ends option processing; the following
    parameters are the program text.

Options:
    -f program-file  Program  text is read from file instead of from the
                     command-line.  Multiple -f options are accepted.
    -F value         sets the field separator, FS, to value.
    -v var=value     assigns value to program variable var.
    --               unambiguous end of options.

    Implementation-specific options are prefixed with "-W".  They can be
    abbreviated:

    -W version       show version information and exit.
    -W dump          show assembler-like listing of program and exit.
    -W help          show this message and exit.
    -W interactive   set unbuffered output, line-buffered input.
    -W exec file     use file as program as well as last option.
    -W posix         stricter POSIX checking.
    -W random=number set initial random seed.
    -W sprintf=number adjust size of sprintf buffer.
    -W traditional   pre-POSIX 2001.
    -W usage         show this message and exit.
"""
        )

    def version(self) -> None:
        """La version sale del listado de dpkg, como en ping y en sudo: el
        numero es el unico dato que otra pieza del senuelo tambien publica."""
        version = "1.3.4 20250131"
        try:
            from cowrie.commands.dpkg import datos_de, leer_paquetes
            crudo, _arch = datos_de(leer_paquetes(), "mawk",
                                    por_defecto=("1.3.4.20250131-1", "amd64"))
            partes = crudo.split("-")[0].split(".")
            if len(partes) >= 4:
                version = "%s %s" % (".".join(partes[:3]), partes[3])
        except Exception:                                      # noqa: BLE001
            pass
        self.write(
            "mawk %s\n"
            "Copyright 2008-2024,2025, Thomas E. Dickey\n"
            "Copyright 1991-1996,2014, Michael D. Brennan\n"
            "\n"
            "random-funcs:       srandom/random\n"
            "regex-funcs:        internal\n"
            "\n"
            "compiled limits:\n"
            "sprintf buffer      8192\n"
            "maximum-integer     9223372036854775808\n" % version
        )


commands["/usr/bin/awk"] = Command_awk
commands["/bin/awk"] = Command_awk
commands["awk"] = Command_awk
commands["mawk"] = Command_awk
commands["/usr/bin/mawk"] = Command_awk
