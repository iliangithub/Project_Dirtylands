# SPDX-License-Identifier: BSD-3-Clause
"""
sed emulado.

EL SEGUNDO DE LA LISTA. que_le_falta_al_senuelo.py cruza los binarios que el
sistema de ficheros ANUNCIA con los que Cowrie sabe ejecutar y ordena lo que
falta por las veces que alguien lo ha tecleado de verdad: 276 para tr, y 132
para este. Y como con tr, no fallaba callando --- el pickle declara
/usr/bin/sed, asi que un "sed -i 's/x/y/' fichero" contestaba "Exec format
error" y ahi se quedaba el guion del atacante.

QUE ENTIENDE, que es lo que se teclea de verdad:

    s/re/rep/[gip]     con CUALQUIER delimitador: s|a|b|  s#a#b#
    Nd  Np  Nq         por numero de linea
    $d  $p             la ultima
    /re/d  /re/p       por patron
    N,Md   N,$d        rangos
    1!d                negacion
    -n  -e  -i[SUF]  -E/-r  -s

LO QUE NO, y lo dice como el de verdad: a, i, c, y, w... contestan
"unknown command". Fingir que se han aplicado seria peor que no tenerlas.

EL DETALLE QUE NO SE ADIVINA: sed usa BRE de POSIX, no la sintaxis de Python.
En BRE los parentesis, el "+" y el "?" son LITERALES, y son "\\(", "\\+" y "\\?"
los que hacen de metacaracteres --- justo al reves que en Python. Sin
traducir eso, un "s/a+/b/" sustituiria "a" repetida cuando el de verdad busca
la cadena "a+" literal. Con -E/-r se comporta como Python y no hay que tocar
nada.

Y en el reemplazo, "&" es la coincidencia entera; en Python eso se escribe
"\\g<0>".

TODO MEDIDO contra el sed 4.9 de un debian:trixie, incluidos los errores:

    sed                 -> el uso entero, por stdout, y sale con 1
    sed 's/a' f         -> sed: -e expression #1, char 3: unterminated `s' command
    sed 's/a/b/' /nada  -> sed: can't read /nada: No such file or directory  (2)
"""

from __future__ import annotations

import re

from cowrie.shell.command import HoneyPotCommand

commands = {}

CORCHETES = re.compile(r"\[\^?\]?[^]]*\]")


def bre_a_python(patron: str) -> str:
    """BRE de POSIX a la sintaxis de re.

    En BRE "(" es literal y "\\(" abre grupo; en Python es al reves. Lo que
    va dentro de un [...] se copia tal cual, porque ahi no son metacaracteres
    ni en uno ni en otro.
    """
    salida: list[str] = []
    i = 0
    while i < len(patron):
        if patron[i] == "[":
            m = CORCHETES.match(patron, i)
            if m:
                salida.append(m.group(0))
                i = m.end()
                continue
        c = patron[i]
        if c == "\\" and i + 1 < len(patron):
            sig = patron[i + 1]
            salida.append(sig if sig in "(){}|+?" else "\\" + sig)
            i += 2
            continue
        salida.append("\\" + c if c in "(){}|+?" else c)
        i += 1
    return "".join(salida)


def reemplazo_a_python(texto: str) -> str:
    """"&" es la coincidencia entera; en Python se escribe "\\g<0>"."""
    salida: list[str] = []
    i = 0
    while i < len(texto):
        c = texto[i]
        if c == "\\" and i + 1 < len(texto):
            sig = texto[i + 1]
            # "\\&" es un ampersand LITERAL; dejarlo escapado hace que
            # re.sub proteste por un escape que no conoce.
            salida.append("&" if sig == "&" else "\\" + sig)
            i += 2
            continue
        salida.append("\\g<0>" if c == "&" else c)
        i += 1
    return "".join(salida)


class ErrorGuion(Exception):
    """Lo que sed contesta y por que caracter va."""

    def __init__(self, mensaje: str, caracter: int):
        super().__init__(mensaje)
        self.mensaje = mensaje
        self.caracter = caracter


def analiza(guion: str, extendida: bool):
    """Una orden: (direccion, negada, letra, parametros)."""
    i = 0
    while i < len(guion) and guion[i] in " \t;\n":
        i += 1
    dir1 = dir2 = None

    def lee_direccion(j):
        if j < len(guion) and guion[j] == "$":
            return "$", j + 1
        if j < len(guion) and guion[j].isdigit():
            k = j
            while k < len(guion) and guion[k].isdigit():
                k += 1
            return int(guion[j:k]), k
        if j < len(guion) and guion[j] == "/":
            k = guion.find("/", j + 1)
            while k > 0 and guion[k - 1] == "\\":
                k = guion.find("/", k + 1)
            if k < 0:
                raise ErrorGuion("unterminated address regex", len(guion))
            return re.compile(guion[j + 1:k] if extendida
                              else bre_a_python(guion[j + 1:k])), k + 1
        return None, j

    dir1, i = lee_direccion(i)
    if dir1 is not None and i < len(guion) and guion[i] == ",":
        dir2, i = lee_direccion(i + 1)
    negada = False
    while i < len(guion) and guion[i] in " !":
        negada = negada or guion[i] == "!"
        i += 1
    if i >= len(guion):
        raise ErrorGuion("missing command", i + 1)

    letra = guion[i]
    if letra == "s":
        # La posicion que da sed aqui es la LONGITUD de la expresion, no la
        # del caracter que falla. Medido: "s/a" da 3 y "s/a/b" da 5, aunque
        # el problema en los dos este al final.
        if i + 1 >= len(guion):
            raise ErrorGuion("unterminated `s' command", len(guion))
        sep = guion[i + 1]
        trozos, actual, j = [], [], i + 2
        while j < len(guion) and len(trozos) < 2:
            if guion[j] == "\\" and j + 1 < len(guion):
                actual.append(guion[j:j + 2])
                j += 2
                continue
            if guion[j] == sep:
                trozos.append("".join(actual))
                actual = []
                j += 1
                continue
            actual.append(guion[j])
            j += 1
        if len(trozos) < 2:
            raise ErrorGuion("unterminated `s' command", len(guion))
        banderas = ""
        while j < len(guion) and guion[j] in "gipIm0123456789":
            banderas += guion[j]
            j += 1
        return (dir1, dir2, negada, "s", (trozos[0], trozos[1], banderas)), j
    if letra in "dpqP=":
        return (dir1, dir2, negada, letra, None), i + 1
    raise ErrorGuion("unknown command: `%s'" % letra, i + 1)


class Command_sed(HoneyPotCommand):
    def start(self) -> None:
        self.callado = False
        self.en_sitio = False
        self.sufijo = ""
        self.extendida = False
        guiones: list[str] = []
        ficheros: list[str] = []

        args = list(self.args)
        i = 0
        primero_es_guion = not any(
            a.startswith("-e") or a in ("--expression",) for a in args)
        while i < len(args):
            a = args[i]
            if a == "-n" or a == "--quiet" or a == "--silent":
                self.callado = True
            elif a in ("-E", "-r", "--regexp-extended"):
                self.extendida = True
            elif a in ("-s", "--separate", "-u", "--unbuffered"):
                pass
            elif a == "-e":
                i += 1
                if i < len(args):
                    guiones.append(args[i])
            elif a.startswith("-e"):
                guiones.append(a[2:])
            elif a.startswith("-i"):
                self.en_sitio = True
                self.sufijo = a[2:]
            elif a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                # Banderas pegadas: -ne, -rn...
                for letra in a[1:]:
                    if letra == "n":
                        self.callado = True
                    elif letra in ("E", "r"):
                        self.extendida = True
                    elif letra == "i":
                        self.en_sitio = True
            elif primero_es_guion and not guiones:
                guiones.append(a)
            else:
                ficheros.append(a)
            i += 1

        if not guiones:
            self._uso()
            return

        self.ordenes = []
        for n, g in enumerate(guiones, 1):
            resto, desplazamiento = g, 0
            while resto.strip(" \t;\n"):
                try:
                    orden, consumido = analiza(resto, self.extendida)
                except ErrorGuion as err:
                    self.errorWrite(
                        "sed: -e expression #%d, char %d: %s\n"
                        % (n, err.caracter + desplazamiento, err.mensaje))
                    self.exit_code = 1
                    self.exit()
                    return
                self.ordenes.append(orden)
                resto = resto[consumido:]
                desplazamiento += consumido

        if ficheros:
            for f in ficheros:
                self._procesa_fichero(f)
            self.exit()
        elif self.input_data is not None:
            self.writeBytes(self._aplica(self.input_data))
            self.exit()

    # ------------------------------------------------------------------
    def _uso(self) -> None:
        """Sin guion, sed escribe el uso ENTERO y sale con 1.

        Es el mismo texto que "sed --help", asi que se lee del fichero de
        ayudas en vez de duplicarlo: son cuarenta lineas y tenerlas dos veces
        garantiza que algun dia digan cosas distintas.
        """
        texto = ""
        try:
            from cowrie.commands.ayuda import ayudas

            texto = (ayudas().get("sed") or {}).get("texto", "")
        except Exception:                                  # noqa: BLE001
            texto = ""
        self.write(texto or
                   "Usage: sed [OPTION]... {script-only-if-no-other-script}"
                   " [input-file]...\n")
        self.exit_code = 1
        self.exit()

    def _procesa_fichero(self, nombre: str) -> None:
        ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
        try:
            datos = self.fs.file_contents(ruta)
        except Exception:                                  # noqa: BLE001
            self.errorWrite("sed: can't read %s: No such file or directory\n"
                            % nombre)
            self.exit_code = 2
            return
        salida = self._aplica(datos)
        if self.en_sitio:
            self._guarda(ruta, salida)
        else:
            self.writeBytes(salida)

    def _guarda(self, ruta: str, contenido: bytes) -> None:
        """Escribe de verdad, como hace nano: nodo y artefacto.

        Sin el artefacto el fichero quedaria en el listado y un "cat"
        posterior lo daria vacio, que es peor que no tocarlo.
        """
        try:
            from cowrie.core.artifact import Artifact

            self.fs.mkfile(ruta, self.current_user["uid"],
                           self.current_user["gid"], len(contenido), 33188)
            artefacto = Artifact("sed")
            with artefacto:
                artefacto.write(contenido)
            self.fs.update_realfile(self.fs.getfile(ruta),
                                    artefacto.shasumFilename)
        except Exception:                                  # noqa: BLE001
            self.errorWrite("sed: couldn't open temporary file: "
                            "Permission denied\n")
            self.exit_code = 4

    # ------------------------------------------------------------------
    def _aplica(self, datos: bytes) -> bytes:
        texto = datos.decode("latin-1")
        final = texto.endswith("\n")
        lineas = texto.split("\n")
        if final:
            lineas.pop()
        salida: list[str] = []
        ultimo = len(lineas)
        rangos: dict[int, bool] = {}

        for numero, linea in enumerate(lineas, 1):
            imprimir = not self.callado
            borrada = False
            for idx, (d1, d2, negada, letra, params) in enumerate(self.ordenes):
                if not self._toca(idx, d1, d2, negada, numero, ultimo, linea,
                                  rangos):
                    continue
                if letra == "d":
                    borrada = True
                    break
                if letra in ("p", "P"):
                    salida.append(linea)
                elif letra == "q":
                    if imprimir:
                        salida.append(linea)
                    return self._junta(salida, final)
                elif letra == "=":
                    salida.append(str(numero))
                elif letra == "s":
                    linea = self._sustituye(linea, params)
            if borrada:
                continue
            if imprimir:
                salida.append(linea)
        return self._junta(salida, final)

    @staticmethod
    def _junta(lineas: list[str], final: bool) -> bytes:
        if not lineas:
            return b""
        return ("\n".join(lineas) + ("\n" if final else "")).encode("latin-1")

    def _toca(self, idx, d1, d2, negada, numero, ultimo, linea, rangos) -> bool:
        def casa(d):
            if d is None:
                return True
            if d == "$":
                return numero == ultimo
            if isinstance(d, int):
                return numero == d
            return bool(d.search(linea))

        if d2 is None:
            resultado = casa(d1)
        else:
            # Un rango se abre cuando casa el primero y se cierra con el
            # segundo; hay que recordarlo entre lineas.
            dentro = rangos.get(idx, False)
            if not dentro:
                resultado = casa(d1)
                if resultado:
                    rangos[idx] = True
            else:
                resultado = True
                if casa(d2):
                    rangos[idx] = False
        return resultado != negada

    def _sustituye(self, linea: str, params) -> str:
        patron, reemplazo, banderas = params
        opciones = re.IGNORECASE if ("i" in banderas or "I" in banderas) else 0
        cuantas = 0 if "g" in banderas else 1
        try:
            compilado = re.compile(
                patron if self.extendida else bre_a_python(patron), opciones)
            return compilado.sub(reemplazo_a_python(reemplazo), linea, cuantas)
        except re.error:
            return linea

    def lineReceived(self, line: str) -> None:
        self.writeBytes(self._aplica((line + "\n").encode("latin-1")))

    def eofReceived(self) -> None:
        self.exit()


commands["/usr/bin/sed"] = Command_sed
commands["/bin/sed"] = Command_sed
commands["sed"] = Command_sed
