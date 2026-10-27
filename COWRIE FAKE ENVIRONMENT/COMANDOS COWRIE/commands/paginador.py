# SPDX-License-Identifier: BSD-3-Clause
#
# El paginador que systemd le pone a systemctl y journalctl.
#
# NO ES UN "less" GENERICO. systemd no lanza less a secas: le pasa
# LESS=FRSXMK, y cada letra cambia lo que se ve:
#
#   F  si el texto cabe en una pantalla, ni se pagina: se vuelca y se sale.
#   R  deja pasar los colores.
#   S  las lineas largas NO se parten: se cortan, y el corte se marca con un
#      ">" en video inverso en la ultima columna.
#   X  no usa la pantalla alternativa, asi que al salir el texto SE QUEDA.
#      Un less normal hace lo contrario y la pantalla vuelve limpia; copiar
#      el comportamiento del less normal aqui seria el fallo tipico.
#   M  el aviso de abajo es el largo: "lines 1-23", y con el total detras en
#      cuanto se ha llegado al final.
#   K  Ctrl-C sale, que en un less normal no sale.
#
# Todo medido en un debian:trixie con systemd 257 arrancado como PID 1, sobre
# un pseudo-terminal de tamano conocido: no vale medirlo sin terminal, porque
# sin el no hay paginador ninguno.
#
# CUANDO PAGINA. Medido moviendo las dos variables: con un terminal de 24
# filas empieza a paginar a las 23 lineas, y con 22 lineas de texto pagina en
# terminales de hasta 23 filas. O sea: pagina si las lineas son >= alto - 1.
from __future__ import annotations

# Cowrie recorre command_modules y hace commands.update(module.commands) SIN
# comprobar que exista. Este modulo no exporta ningun comando, pero el
# diccionario tiene que estar igual: sin el, el senuelo no arranca ---revienta
# al importar shell/protocol.py, antes de escuchar en ningun puerto---. Lo
# mismo vale para ayuda.py y authlog.py.
commands: dict = {}

ENTRAR = "\x1b[?1h\x1b="
SALIR = "\r\x1b[K\x1b[?1l\x1b>"
CORTE = "\x1b[m\x1b[7m>\x1b[27m"
INVERSO, FIN_INVERSO = "\x1b[7m", "\x1b[27m"


def tamano(cmd) -> tuple:
    """(ancho, alto) VIVOS, como los mira nano.

    COLUMNS y LINES no valen solos: shell/honeypot.py los escribe una vez al
    abrir la sesion y estirar la ventana despues no los toca.
    """
    ancho = alto = 0
    sesion = getattr(getattr(cmd, "protocol", None), "user", None)
    tam = getattr(sesion, "windowSize", None)
    try:
        alto, ancho = int(tam[0]), int(tam[1])
    except (TypeError, ValueError, IndexError):
        pass
    entorno = getattr(cmd, "environ", None) or {}
    if ancho <= 0:
        try:
            ancho = int(entorno.get("COLUMNS", "80"))
        except (TypeError, ValueError):
            ancho = 80
    if alto <= 0:
        try:
            alto = int(entorno.get("LINES", "24"))
        except (TypeError, ValueError):
            alto = 24
    return max(20, ancho), max(6, alto)


def hay_terminal(cmd) -> bool:
    """False si la salida va a una tuberia o a un fichero.

    Sin terminal NO HAY PAGINADOR, y eso importa mas de lo que parece: lo que
    hace un guion de botnet es encadenar, y ahi el comando de verdad tampoco
    pagina. Si paginaramos siempre, un "journalctl | grep ssh" se llenaria de
    avisos de "lines 1-23" que ningun Linux mete en una tuberia.
    """
    pp = getattr(getattr(cmd, "protocol", None), "pp", None)
    if pp is None:
        return True
    # LA TABLA DE DESCRIPTORES LO SABE MEJOR. Con next_command se cazan las
    # tuberias, pero no un "> fichero": ese deja next_command a None y la
    # salida se va igualmente a un sitio que no es la pantalla. Cowrie ya lo
    # anota en targets[1], que dice a donde va la salida de verdad.
    destino = getattr(pp, "targets", {}).get(1)
    if destino is not None:
        return destino[0] == "terminal"
    return (getattr(pp, "next_command", None) is None
            and not getattr(pp, "redirect", False))


class Paginador:
    """El de systemd. Se queda con el terminal hasta que pulsen q."""

    SALIR = SALIR

    def entrada(self) -> str:
        return ENTRAR

    def __init__(self, cmd, texto: str, nombre: str = ""):
        self.nombre = nombre
        self.cmd = cmd
        self.lineas = texto.split("\n")
        if self.lineas and self.lineas[-1] == "":
            self.lineas.pop()
        self.inicio = 0
        self.visto_el_final = False
        self.previos: dict = {}
        self.char_previo = None

    # ------------------------------------------------------------- pintar
    def _alto_util(self) -> int:
        return max(1, tamano(self.cmd)[1] - 1)

    def filas(self) -> list:
        """Las filas de PANTALLA. Con la S de systemd hay una por linea."""
        return [self._recorta(l) for l in self.lineas]

    def _recorta(self, linea: str) -> str:
        """Corta a lo ancho y marca el corte, que es lo que hace la S."""
        ancho = tamano(self.cmd)[0]
        if len(linea) < ancho:
            return linea
        return linea[:ancho - 1] + CORTE

    # El total y el "(END)" NO salen en la primera pantalla aunque el texto
    # quepa entero: less no sabe cuantas lineas hay hasta que INTENTA leer
    # mas alla. Medido: 23 lineas en 24 filas dan "lines 1-23" a secas, y
    # solo tras moverse aparece "lines 1-23/23 (END)".
    def _aviso(self) -> str:
        filas = self.filas()
        primera = self.inicio + 1
        ultima = min(len(filas), self.inicio + self._alto_util())
        texto = "lines %d-%d" % (primera, ultima)
        if self.visto_el_final:
            texto += "/%d" % len(filas)
            if ultima >= len(filas):
                texto += " (END)"
        return INVERSO + texto + FIN_INVERSO + "\x1b[K"

    def _pinta(self, primera_vez: bool = False) -> None:
        alto = self._alto_util()
        if not primera_vez:
            # Volver arriba del todo y limpiar: repintar entero es lo unico
            # que sirve igual para bajar que para subir, y menos codigo es
            # menos sitio donde dejarse la pantalla a medias.
            self.cmd.write("\r\x1b[K")
            self.cmd.write("\x1b[%dA" % alto)
            self.cmd.write("\x1b[J")
        filas = self.filas()
        trozo = filas[self.inicio:self.inicio + alto]
        if not primera_vez and self.inicio + alto >= len(filas):
            self.visto_el_final = True
        self.cmd.write("".join(f + "\r\n" for f in trozo))
        self.cmd.write(self._aviso())

    # ------------------------------------------------------------ moverse
    def _mueve(self, cuantas: int) -> None:
        tope = max(0, len(self.filas()) - self._alto_util())
        nuevo = min(tope, max(0, self.inicio + cuantas))
        if nuevo == self.inicio:
            # Ya no hay a donde ir. Si es porque estamos abajo del todo, eso
            # es justo el momento en que less descubre cuantas lineas habia.
            if self.inicio >= tope:
                self.visto_el_final = True
            self.cmd.write("\r" + self._aviso())
            return
        self.inicio = nuevo
        self._pinta()

    def _tecla(self, ch) -> None:
        if isinstance(ch, bytes):
            ch = ch.decode("latin-1", "replace")
        alto = self._alto_util()
        if ch in ("q", "Q", ":"):
            self.suelta()
            return
        if ch in (" ", "f", "\x06"):
            self._mueve(alto)
        elif ch in ("b", "\x02"):
            self._mueve(-alto)
        elif ch in ("d", "\x04"):
            self._mueve(alto // 2)
        elif ch in ("u", "\x15"):
            self._mueve(-(alto // 2))
        elif ch in ("j", "e", "\x0e"):
            self._mueve(1)
        elif ch in ("k", "y", "\x10"):
            self._mueve(-1)
        elif ch in ("g", "<"):
            self._mueve(-len(self.filas()))
        elif ch in ("G", ">"):
            self._mueve(len(self.filas()))
        # Cualquier otra tecla no hace nada, como en less.

    # --------------------------------------------------------- teclado
    def toma(self) -> None:
        protocol = self.cmd.protocol
        t = getattr(protocol, "terminal", None)

        def clave(nombre, respaldo):
            valor = getattr(t, nombre, None)
            return respaldo if valor is None else valor

        mapa = {
            b"\r": lambda: self._tecla("j"),
            b"\n": lambda: self._tecla("j"),
            b"\x03": self.suelta,                    # la bandera K
            clave("UP_ARROW", b"[UP_ARROW]"): lambda: self._tecla("k"),
            clave("DOWN_ARROW", b"[DOWN_ARROW]"): lambda: self._tecla("j"),
            clave("PGUP", b"[PGUP]"): lambda: self._tecla("b"),
            clave("PGDN", b"[PGDN]"): lambda: self._tecla(" "),
            clave("HOME", b"[HOME]"): lambda: self._tecla("g"),
            clave("END", b"[END]"): lambda: self._tecla("G"),
        }
        for k, funcion in mapa.items():
            self.previos[k] = protocol.keyHandlers.get(k)
            protocol.keyHandlers[k] = funcion
        # Las imprimibles ---espacio, q, b...--- no pasan por keyHandlers.
        self.char_previo = getattr(protocol, "characterReceived", None)
        protocol.characterReceived = lambda ch, mas=False: self._tecla(ch)

    def suelta(self) -> None:
        protocol = self.cmd.protocol
        if self.char_previo is not None:
            protocol.characterReceived = self.char_previo
            self.char_previo = None
        for k, antes in self.previos.items():
            if antes is None:
                protocol.keyHandlers.pop(k, None)
            else:
                protocol.keyHandlers[k] = antes
        self.previos = {}
        self.cmd.write(self.SALIR)
        self.cmd.exit()

    def arranca(self) -> None:
        self.cmd.write(self.entrada())
        self._pinta(primera_vez=True)
        self.toma()


class PaginadorLess(Paginador):
    """El less que teclea el atacante, SIN las opciones de systemd.

    Se parece poco al de arriba, y confundirlos es el error facil:

      - USA LA PANTALLA ALTERNATIVA. Al salir, el texto DESAPARECE y vuelve
        lo que hubiera antes. El de systemd hace justo lo contrario.
      - NO CORTA las lineas largas: las parte y siguen en la fila de abajo,
        asi que una linea puede ocupar varias filas de pantalla.
      - PAGINA SIEMPRE, aunque el fichero quepa entero: no lleva la F.
      - El aviso de abajo es EL NOMBRE DEL FICHERO, no "lines 1-23", y le
        pone " (END)" en cuanto se ve la ultima fila ---esta vez si, desde la
        primera pantalla---.

    Todo medido en un debian:trixie sobre pseudo-terminal.
    """

    SALIR = "\r\x1b[K\x1b[?1l\x1b>\x1b[?1049l\x1b[23;0;0t"

    def entrada(self) -> str:
        alto = tamano(self.cmd)[1]
        return "\x1b[?1049h\x1b[22;0;0t\x1b[%d;1H\x1b[?1h\x1b=\r" % alto

    def filas(self) -> list:
        """Aqui una linea larga ocupa VARIAS filas, porque se parte."""
        ancho = tamano(self.cmd)[0]
        salida = []
        for linea in self.lineas:
            if not linea:
                salida.append("")
                continue
            for i in range(0, len(linea), ancho):
                salida.append(linea[i:i + ancho])
        return salida

    def _aviso(self) -> str:
        filas = self.filas()
        ultima = min(len(filas), self.inicio + self._alto_util())
        texto = self.nombre
        if ultima >= len(filas):
            texto += " (END)" if texto else "(END)"
        return INVERSO + texto + FIN_INVERSO + "\x1b[K"


class PaginadorMore(Paginador):
    """more, que es de util-linux y no tiene nada que ver con less.

    No toca la pantalla alternativa, no sabe volver atras y su aviso es un
    PORCENTAJE. Y ese porcentaje va por BYTES leidos, no por lineas: con un
    fichero de 30 numeros, tras nueve lineas dice 22%, que es 18 bytes de 81.
    Contarlo por lineas daria 30% y seria un numero que ese more no escribe.
    """

    SALIR = "\r\x1b[K"

    def entrada(self) -> str:
        return ""

    def _aviso(self) -> str:
        filas = self.filas()
        hasta = min(len(filas), self.inicio + self._alto_util())
        leidos = sum(len(f) + 1 for f in filas[:hasta])
        total = sum(len(f) + 1 for f in filas) or 1
        return (INVERSO + "--More--(%d%%)" % (leidos * 100 // total)
                + FIN_INVERSO)

    def _pinta(self, primera_vez: bool = False) -> None:
        """more NO repinta: sigue escribiendo hacia abajo.

        Por eso no tiene tecla para subir. Repintar como el otro dejaria un
        more capaz de volver atras, que no existe.
        """
        alto = self._alto_util()
        filas = self.filas()
        if not primera_vez:
            self.cmd.write("\r")
        trozo = filas[self.inicio:self.inicio + alto]
        if not primera_vez and self.inicio + alto >= len(filas):
            self.visto_el_final = True
        self.cmd.write("".join(f + "\r\n" for f in trozo))
        self.cmd.write(self._aviso())

    def _tecla(self, ch) -> None:
        if isinstance(ch, bytes):
            ch = ch.decode("latin-1", "replace")
        if ch in ("q", "Q"):
            self.suelta()
            return
        alto = self._alto_util()
        tope = max(0, len(self.filas()) - alto)
        if ch in (" ", "f"):
            if self.inicio >= tope:
                self.suelta()          # al llegar al final, more TERMINA
                return
            self._mueve(alto)
        elif ch in ("j", "\r", "\n"):
            if self.inicio >= tope:
                self.suelta()
                return
            self._mueve(1)


def vuelca_less(cmd, texto: str, nombre: str = "") -> bool:
    """El less de verdad, que pagina aunque el fichero quepa."""
    if not texto or not hay_terminal(cmd):
        return False
    PaginadorLess(cmd, texto, nombre).arranca()
    return True


def vuelca_more(cmd, texto: str) -> bool:
    """more si NO cabe; si cabe no pagina, como hace el de verdad."""
    if not texto or not hay_terminal(cmd):
        return False
    p = PaginadorMore(cmd, texto)
    if len(p.filas()) < tamano(cmd)[1]:
        return False
    p.arranca()
    return True


def vuelca(cmd, texto: str) -> bool:
    """El paginador de systemd.

    Devuelve True si se ha quedado con el terminal, en cuyo caso el comando
    NO debe llamar a exit(): lo hara el paginador cuando pulsen q. Si
    devuelve False no ha escrito nada: escribe quien llama. Los tres
    ---este, less y more--- comparten ese contrato a proposito: cuando unos
    escribian y otros no, el texto salia dos veces.
    """
    if not texto:
        return False
    cuantas = texto.count("\n") + (0 if texto.endswith("\n") else 1)
    if not hay_terminal(cmd) or cuantas < tamano(cmd)[1] - 1:
        return False
    p = Paginador(cmd, texto)
    p.arranca()
    return True
