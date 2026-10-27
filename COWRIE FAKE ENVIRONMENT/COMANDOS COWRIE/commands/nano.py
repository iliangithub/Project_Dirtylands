# SPDX-License-Identifier: GPL-2.0-or-later
#
# nano emulado.
#
# POR QUE EXISTE. Cowrie no puede ejecutar un editor a pantalla completa, asi
# que servia para "nano" un fichero de texto con un error de excusa ---y encima
# el error de Vim---. El coste no es solo de realismo: quien entra a dejar un
# guion suele hacerlo con nano, y al toparse con el error se va. Se pierde
# justo lo que mas interesa capturar, que es lo que el atacante iba a ESCRIBIR.
#
# QUE HACE Y QUE NO. Reproduce el flujo que se usa de verdad: abre, se teclea,
# ^O guarda y ^X sale. El fichero acaba en el disco falso, asi que un "cat"
# posterior lo devuelve, y el contenido se registra en el log.
#
# No es un nano completo: no hay busqueda, ni cortar y pegar, ni movimiento
# libre del cursor por el texto ya escrito. La shell de Cowrie es de LINEA
# ---recvline hace la edicion y entrega la linea al pulsar Enter--- asi que
# reescribir una linea anterior no es posible sin reimplementar el terminal
# entero. Se dibuja lo que se ve y se acepta lo que se teclea.
#
# COMO CAPTURA LAS TECLAS. keyHandlers es un diccionario POR SESION ---Twisted
# lo crea en connectionMade--- asi que este comando le anade ^O, ^X y ^G
# mientras esta abierto y los quita al salir. Por eso no hace falta parchear el
# protocolo de Cowrie, que es codigo que atraviesan TODAS las sesiones.
from __future__ import annotations

import time

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands = {}

VERSION = "8.4"

# Las dos filas de atajos, tal como las imprime un nano de verdad. El ^ y la
# letra van en video inverso; el resto, normal.
# LA BARRA DE ATAJOS CRECE CON EL TERMINAL. Antes esto eran dos filas fijas de
# seis columnas: en un terminal ancho el nano de verdad ensena mas atajos y el
# nuestro se quedaba con los mismos seis y media pantalla vacia. Se ve de un
# vistazo poniendo los dos nano uno encima del otro.
#
# Las parejas van en el orden en que las saca nano, y estan MEDIDAS contra un
# nano real (TERM=xterm, LANG=C) a 80, 120 y 160 columnas: salen 6, 8 y 10
# columnas respectivamente. Esa progresion es la formula de bottombars():
#
#     columnas = (ancho + 40) / 20        ancho de cada hueco = ancho / columnas
#
# y cuadra en los tres casos: (80+40)/20=6, (120+40)/20=8, (160+40)/20=10; y
# 80/6=13, 120/8=15, 160/10=16. El 13 de antes era ese mismo numero, pero
# escrito a mano y solo valido a 80.
ATAJOS = (
    (("^G", "Help"),     ("^X", "Exit")),
    (("^O", "Write Out"), ("^R", "Read File")),
    (("^W", "Where Is"), ("^\\", "Replace")),
    (("^K", "Cut"),      ("^U", "Paste")),
    (("^T", "Execute"),  ("^J", "Justify")),
    (("^C", "Location"), ("^/", "Go To Line")),
    (("M-U", "Undo"),    ("M-E", "Redo")),
    (("M-A", "Set Mark"), ("M-6", "Copy")),
    (("M-]", "To Bracket"), ("^Q", "Where Was")),
    (("M-Q", "Previous"), ("M-W", "Next")),
)

# PANTALLA ALTERNATIVA. Es lo que hace que al salir de un editor tu terminal
# vuelva a estar como lo dejaste, con todo lo que habias escrito antes.
#
# El nano de verdad lo hace: capturado de un `nano` 8.4 sobre TERM=xterm, lo
# primero que manda es \x1b[?2004h\x1b[?1049h, y \x1b[?1049h es exactamente el
# `smcup` que declara el terminfo de xterm. El terminal guarda la pantalla
# entera, te da un lienzo en blanco, y al recibir `rmcup` (\x1b[?1049l) la
# devuelve intacta.
#
# Nosotros no la usabamos, y el efecto se nota: al abrir el editor se borraba
# la sesion del atacante de un \x1b[2J, y al salir se quedaba otra pantalla en
# blanco donde antes estaba su trabajo. Ningun editor se comporta asi, y es de
# las cosas que se ven sin buscarlas.
PANTALLA_ALT = "\x1b[?1049h"
PANTALLA_NORMAL = "\x1b[?1049l"

INVERSO = "\x1b[7m"
NORMAL = "\x1b[0m"

# nano usa DOS estilos en la linea de estado, y la diferencia se ve a un metro
# de la pantalla. Comprobado contra un GNU nano 8.4 de verdad:
#
#   [ Wrote 1 line ]              -> \x1b[0;7m      video inverso
#   [ Error writing ...: ... ]    -> \x1b[0;1m\x1b[37m\x1b[41m   blanco sobre ROJO
#
# Un aviso de permisos que saliera en video inverso normal pasaria por un
# mensaje cualquiera, y es justo el que tiene que llamar la atencion.
ROJO = "\x1b[0;1m\x1b[37m\x1b[41m"
FIN_ROJO = "\x1b[39;49m\x1b[m"


# --- Permisos ---------------------------------------------------------------
#
# Media docena de modulos nuestros llevan ya su copia de este par de funciones
# (cat, ls, find, stat, file y fs). La de aqui anade lo que a las otras les
# falta: el permiso de ESCRITURA. Sin el, nano guardaria en /etc/passwd siendo
# un usuario normal, que es precisamente lo que un atacante prueba primero.
def _perm_ok(node, uid: int, gid: int, want: str) -> bool:
    mode = node[fs.A_MODE]
    if uid == node[fs.A_UID]:
        bit = {"r": 0o400, "w": 0o200, "x": 0o100}[want]
    elif gid == node[fs.A_GID]:
        bit = {"r": 0o040, "w": 0o020, "x": 0o010}[want]
    else:
        bit = {"r": 0o004, "w": 0o002, "x": 0o001}[want]
    return bool(mode & bit)


def _puede(fsobj, ruta: str, uid: int, gid: int, quiere: str) -> bool:
    """True si ese uid/gid puede hacer `quiere` sobre `ruta`.

    Comprueba tambien el permiso de paso (x) de cada directorio del camino: sin
    el, un /home/otro con modo 0750 no protegeria nada. root pasa siempre, como
    en un Linux de verdad.
    """
    if uid == 0:
        return True
    try:
        node = fsobj.getfile(ruta, follow_symlinks=True)
    except Exception:                                      # noqa: BLE001
        return False
    if not node:
        return False
    partes = [p for p in ruta.split("/") if p][:-1]
    actual = ""
    for parte in partes:
        actual += "/" + parte
        try:
            dirnode = fsobj.getfile(actual, follow_symlinks=True)
        except Exception:                                  # noqa: BLE001
            return False
        if not dirnode or not _perm_ok(dirnode, uid, gid, "x"):
            return False
    return _perm_ok(node, uid, gid, quiere)


def _dir_de(ruta: str) -> str:
    padre = ruta.rsplit("/", 1)[0]
    return padre if padre else "/"


class Command_nano(HoneyPotCommand):
    """nano/pico. Guarda de verdad lo que se escriba."""

    def start(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        self.nombre = args[0] if args else ""
        self.lineas: list[str] = []
        self.modificado = False
        # Estado del dialogo de abajo: None, "guardar" o "salir".
        self.preguntando: str | None = None
        self.previos: dict = {}
        self.tamano_previo = None
        # EDITOR DE PANTALLA, no de linea. fila/col son la posicion del cursor
        # dentro del texto, e `inicio` es la primera linea visible cuando el
        # fichero no cabe entero. Antes no existia nada de esto: la linea que
        # se escribia la llevaba recvline y al pulsar Enter se cerraba para
        # siempre, asi que no se podia volver atras a corregir nada. En un nano
        # de verdad se navega por todo el texto, y era de lo primero que
        # delataba al nuestro.
        self.fila = 0
        self.col = 0
        self.inicio = 0
        self.char_previo = None

        # Los avisos de permisos se calculan aqui pero se pintan DESPUES de
        # dibujar la pantalla: nano los deja en la linea de estado, encima de
        # los atajos, y si se escribieran antes el redibujado los borraria.
        self.avisos: list[str] = []
        self.sin_titulo = False

        if self.nombre:
            ruta = self.fs.resolve_path(self.nombre, self.protocol.cwd)
            self._mirar_permisos(ruta)
            try:
                if self.fs.exists(ruta) and not self.fs.isdir(ruta) and self.legible:
                    crudo = self.fs.file_contents(ruta)
                    texto = crudo.decode("utf-8", errors="replace")
                    self.lineas = texto.split("\n")
                    if self.lineas and self.lineas[-1] == "":
                        self.lineas.pop()
            except Exception:                              # noqa: BLE001
                self.lineas = []

        self._tomar_teclas()
        self._tomar_tamano()
        self.write(PANTALLA_ALT)
        self._dibujar()
        # Se emiten en orden, como hace nano: el ultimo es el que queda a la
        # vista, y es siempre el mas concreto.
        for texto in self.avisos:
            self._aviso(texto, error=True)

    def _mirar_permisos(self, ruta: str) -> None:
        """Decide si el fichero se puede leer y escribir, y con que aviso.

        Los mensajes NO estan redactados: son los de un GNU nano 8.4 de verdad,
        copiados de una sesion contra un Debian 13. Un texto parecido pero no
        igual es tan delator como no poner ninguno.
        """
        uid = getattr(self.protocol.user, "uid", 0)
        gid = getattr(self.protocol.user, "gid", 0)
        self.legible = True
        self.escribible = True

        carpeta = _dir_de(ruta)
        existe = False
        try:
            existe = self.fs.exists(ruta)
        except Exception:                                  # noqa: BLE001
            existe = False

        # El directorio primero: sin permiso de paso no se llega ni a mirar.
        if not _puede(self.fs, carpeta, uid, gid, "x"):
            self.avisos.append(f"Path '{carpeta}' is not accessible")
            self.legible = False
            self.escribible = False
            return
        if not _puede(self.fs, carpeta, uid, gid, "w"):
            self.avisos.append(f"Directory '{carpeta}' is not writable")
            # Un directorio no escribible solo impide CREAR: si el fichero ya
            # existe y es nuestro, se puede seguir escribiendo en el.
            if not existe:
                self.escribible = False

        if existe:
            if not _puede(self.fs, ruta, uid, gid, "r"):
                self.avisos.append(f"Error reading {ruta}: Permission denied")
                self.legible = False
                self.escribible = False
                # nano abre un buffer vacio y el titulo pasa a "New Buffer".
                self.sin_titulo = True
            elif not _puede(self.fs, ruta, uid, gid, "w"):
                self.avisos.append(f"File '{ruta}' is unwritable")
                self.escribible = False

    # ------------------------------------------------------------- teclado
    def _tomar_teclas(self) -> None:
        """Se queda ^O, ^X y ^G mientras el editor esta abierto.

        Se guarda lo que hubiera antes para devolverlo al salir: dejar estos
        manejadores puestos convertiria un ^X del shell en una llamada a un
        editor que ya no existe.
        """
        # ARRIBA y ABAJO tambien, y estas son las que de verdad delataban.
        # Sin taparlas, recvline las sigue tratando como el historial del
        # shell: dentro del editor, pulsar arriba METIA EL ULTIMO COMANDO
        # EJECUTADO COMO TEXTO en el fichero. No hay editor que haga eso, y
        # es de lo primero que toca cualquiera que este escribiendo.
        #
        # OJO CON EL NOMBRE DE LA TECLA. El primer intento uso b"[A", que es
        # lo que manda el terminal por el cable, y no funciono nunca: para
        # cuando llega a keyHandlers, insults ya ha traducido la secuencia a
        # su constante, que es b"[UP_ARROW]". Se cogen del propio terminal
        # ---igual que hace recvline, que arranca con t = self.terminal---
        # en vez de escribirlas a mano, que es como se cuelan estos fallos.
        #
        # IZQUIERDA y DERECHA se dejan en paz a proposito: mueven el cursor
        # dentro de la linea que se esta escribiendo, que es exactamente lo
        # que hacen en un nano de verdad. Solo estorban arriba y abajo,
        # porque este nano es de LINEA ---la edicion la hace recvline y
        # entrega la linea al pulsar Enter--- y no hay a donde subir.
        t = getattr(self.protocol, "terminal", None)

        def tecla(nombre: str, respaldo):
            """La constante que use ESTE terminal, sea del tipo que sea.

            Antes esto exigia `isinstance(valor, bytes)` y, si no lo era, se
            quedaba con el respaldo escrito a mano. Parecia prudente y era lo
            contrario: descartaba en silencio una constante perfectamente
            valida y registraba el manejador bajo una clave que nadie iba a
            enviar jamas ---el mismo fallo que el b"[A" original, con otro
            disfraz---. La clave solo tiene que coincidir con lo que
            keystrokeReceived recibe, que es literalmente `terminal.X`.
            """
            valor = getattr(t, nombre, None)
            return respaldo if valor is None else valor

        mapa = {
            b"\x0f": self._ctrl_o,
            b"\x18": self._ctrl_x,
            b"\x07": self._ctrl_g,
            b"\x03": self._ctrl_c,
            # Las cuatro flechas mueven el cursor POR EL TEXTO. Antes arriba y
            # abajo se tragaban ---no habia a donde ir--- e izquierda y derecha
            # las llevaba recvline, o sea que solo se movian dentro de la linea
            # que se estaba escribiendo y no se podia volver a una anterior.
            tecla("UP_ARROW", b"[UP_ARROW]"): self._arriba,
            tecla("DOWN_ARROW", b"[DOWN_ARROW]"): self._abajo,
            tecla("LEFT_ARROW", b"[LEFT_ARROW]"): self._izquierda,
            tecla("RIGHT_ARROW", b"[RIGHT_ARROW]"): self._derecha,
            tecla("HOME", b"[HOME]"): self._inicio_linea,
            tecla("END", b"[END]"): self._fin_linea,
            tecla("BACKSPACE", b"\x7f"): self._borrar_atras,
            tecla("DELETE", b"[DELETE]"): self._borrar_delante,
            b"\r": self._intro,
            b"\n": self._intro,
        }
        for tecla, funcion in mapa.items():
            self.previos[tecla] = self.protocol.keyHandlers.get(tecla)
            self.protocol.keyHandlers[tecla] = funcion

        # Las teclas IMPRIMIBLES no pasan por keyHandlers: recvline las manda a
        # characterReceived, que es quien las mete en SU linea. Hay que
        # quedarselo o el texto seguiria siendo suyo y no nuestro. Es el mismo
        # gesto que ya hace top.py.
        self.char_previo = getattr(self.protocol, "characterReceived", None)
        self.protocol.characterReceived = self._caracter

    def _soltar_teclas(self) -> None:
        if self.char_previo is not None:
            self.protocol.characterReceived = self.char_previo
            self.char_previo = None
        for tecla, antes in self.previos.items():
            if antes is None:
                self.protocol.keyHandlers.pop(tecla, None)
            else:
                self.protocol.keyHandlers[tecla] = antes
        self.previos = {}

    # -------------------------------------------------------------- edicion
    # Todo lo de aqui abajo comparte una regla: si hay un DIALOGO abierto
    # (guardar, salir), la tecla NO es para el texto, es para el dialogo, y se
    # le devuelve a recvline. Un nano de verdad hace lo mismo: el texto es una
    # pantalla, pero la pregunta de abajo es un campo de una linea.

    def _en_dialogo(self) -> bool:
        return bool(self.preguntando)

    def _asegurar(self) -> None:
        """Un buffer vacio sigue teniendo una linea: la vacia."""
        if not self.lineas:
            self.lineas = [""]
        self.fila = max(0, min(self.fila, len(self.lineas) - 1))
        self.col = max(0, min(self.col, len(self.lineas[self.fila])))

    def _caracter(self, ch, mas=False) -> None:
        if self._en_dialogo():
            if self.char_previo:
                # El contrato de recvline es BYTES, y eso es lo que llega en
                # produccion. Si alguna vez llegara texto se convierte en vez
                # de reventar: una excepcion aqui no se queda en un log, se ve
                # en la pantalla del que esta dentro.
                self.char_previo(
                    ch.encode("utf-8", "replace") if isinstance(ch, str) else ch,
                    mas)
            return
        if isinstance(ch, bytes):
            ch = ch.decode("utf-8", "replace")
        if not ch or ch < " ":
            return
        self._asegurar()
        linea = self.lineas[self.fila]
        self.lineas[self.fila] = linea[:self.col] + ch + linea[self.col:]
        self.col += len(ch)
        self.modificado = True
        self._dibujar()

    def _intro(self) -> None:
        if self._en_dialogo():
            antes = self.previos.get(b"\r") or self.previos.get(b"\n")
            if antes:
                antes()
            return
        self._asegurar()
        linea = self.lineas[self.fila]
        self.lineas[self.fila] = linea[:self.col]
        self.lineas.insert(self.fila + 1, linea[self.col:])
        self.fila += 1
        self.col = 0
        self.modificado = True
        self._dibujar()

    def _borrar_atras(self) -> None:
        if self._en_dialogo():
            antes = self.previos.get(b"\x7f")
            if antes:
                antes()
            return
        self._asegurar()
        if self.col > 0:
            linea = self.lineas[self.fila]
            self.lineas[self.fila] = linea[:self.col - 1] + linea[self.col:]
            self.col -= 1
        elif self.fila > 0:
            # Se pega esta linea al final de la anterior, como cualquier editor.
            previa = self.lineas[self.fila - 1]
            self.col = len(previa)
            self.lineas[self.fila - 1] = previa + self.lineas[self.fila]
            del self.lineas[self.fila]
            self.fila -= 1
        else:
            return
        self.modificado = True
        self._dibujar()

    def _borrar_delante(self) -> None:
        if self._en_dialogo():
            return
        self._asegurar()
        linea = self.lineas[self.fila]
        if self.col < len(linea):
            self.lineas[self.fila] = linea[:self.col] + linea[self.col + 1:]
        elif self.fila < len(self.lineas) - 1:
            self.lineas[self.fila] = linea + self.lineas[self.fila + 1]
            del self.lineas[self.fila + 1]
        else:
            return
        self.modificado = True
        self._dibujar()

    # ------------------------------------------------------------ movimiento
    def _arriba(self) -> None:
        if self._en_dialogo():
            return
        self._asegurar()
        if self.fila > 0:
            self.fila -= 1
            self.col = min(self.col, len(self.lineas[self.fila]))
            self._dibujar()

    def _abajo(self) -> None:
        if self._en_dialogo():
            return
        self._asegurar()
        if self.fila < len(self.lineas) - 1:
            self.fila += 1
            self.col = min(self.col, len(self.lineas[self.fila]))
            self._dibujar()

    def _izquierda(self) -> None:
        if self._en_dialogo():
            antes = self.previos.get(getattr(
                getattr(self, "protocol", None), "terminal", None) and
                getattr(self.protocol.terminal, "LEFT_ARROW", b"[LEFT_ARROW]"))
            if antes:
                antes()
            return
        self._asegurar()
        if self.col > 0:
            self.col -= 1
        elif self.fila > 0:
            # Al principio de linea se salta al FINAL de la anterior.
            self.fila -= 1
            self.col = len(self.lineas[self.fila])
        else:
            return
        self._dibujar()

    def _derecha(self) -> None:
        if self._en_dialogo():
            return
        self._asegurar()
        if self.col < len(self.lineas[self.fila]):
            self.col += 1
        elif self.fila < len(self.lineas) - 1:
            self.fila += 1
            self.col = 0
        else:
            return
        self._dibujar()

    def _inicio_linea(self) -> None:
        if self._en_dialogo():
            return
        self._asegurar()
        self.col = 0
        self._dibujar()

    def _fin_linea(self) -> None:
        if self._en_dialogo():
            return
        self._asegurar()
        self.col = len(self.lineas[self.fila])
        self._dibujar()

    # ------------------------------------------------------------- pantalla
    def _tam(self) -> tuple[int, int]:
        """(ancho, alto) VIVOS, no los del momento del login.

        COLUMNS y LINES no valen para esto. `shell/honeypot.py` los escribe
        UNA sola vez, al abrir el shell, copiandolos del tamano que tenia la
        ventana entonces; estirar el terminal despues no los toca. Un nano
        que los lea se queda dibujado al tamano viejo para siempre, con las
        barras de atajos ancladas donde ya no va el borde: es justo lo que se
        veia al agrandar la ventana, la barra repetida a media pantalla.

        El que si se actualiza es el de la sesion. `windowChanged` lo
        reescribe cada vez que el cliente avisa de un cambio de tamano, y
        viene como (alto, ancho), en ese orden. Se cae a COLUMNS/LINES solo
        si no hubiera sesion, que es el caso de las pruebas.
        """
        ancho = alto = 0
        sesion = getattr(getattr(self, "protocol", None), "user", None)
        tam = getattr(sesion, "windowSize", None)
        try:
            alto, ancho = int(tam[0]), int(tam[1])       # type: ignore[index]
        except (TypeError, ValueError, IndexError):
            pass
        if ancho <= 0:
            try:
                ancho = int(self.environ.get("COLUMNS", "80"))
            except (TypeError, ValueError):
                ancho = 80
        if alto <= 0:
            try:
                alto = int(self.environ.get("LINES", "24"))
            except (TypeError, ValueError):
                alto = 24
        return max(20, ancho), max(6, alto)

    def _ancho(self) -> int:
        return self._tam()[0]

    def _alto(self) -> int:
        return self._tam()[1]

    # ---------------------------------------------------------- redimensionar
    def _tomar_tamano(self) -> None:
        """Se entera de los cambios de tamano mientras el editor esta abierto.

        Cowrie guarda el tamano nuevo y no avisa a nadie: `windowChanged` es
        una asignacion y nada mas. Un nano de verdad se redibuja entero al
        recibir SIGWINCH, asi que aqui se envuelve ese metodo para hacer lo
        mismo. Se llama primero al original ---que es quien apunta el tamano
        nuevo--- y solo despues se redibuja, o se repintaria con el viejo.
        """
        sesion = getattr(getattr(self, "protocol", None), "user", None)
        anterior = getattr(sesion, "windowChanged", None)
        if sesion is None or not callable(anterior):
            return
        self.tamano_previo = anterior

        def al_redimensionar(windowSize, _antes=anterior):
            _antes(windowSize)
            try:
                self._dibujar()
                for texto in self.avisos:
                    self._aviso(texto, error=True)
            except Exception:                              # noqa: BLE001
                # Redibujar nunca puede tumbar la sesion: si algo falla, el
                # editor se queda como estaba y el atacante ve una ventana
                # mal dibujada, que es mucho menos raro que una desconexion.
                pass

        sesion.windowChanged = al_redimensionar

    def _soltar_tamano(self) -> None:
        sesion = getattr(getattr(self, "protocol", None), "user", None)
        if sesion is not None and self.tamano_previo is not None:
            sesion.windowChanged = self.tamano_previo
        self.tamano_previo = None

    def _titulo(self) -> str:
        """La barra de titulo, con el nombre centrado como lo centra nano.

        Antes se centraba en el hueco QUE QUEDA despues del "GNU nano 8.4", asi
        que el nombre salia corrido a la derecha y no en el medio de la linea.
        Se nota a simple vista comparandolo con un nano de verdad, y se nota
        mas al estirar el terminal.

        La posicion esta MEDIDA contra GNU nano 8.4 a tres anchuras (80, 100 y
        120) y con tres nombres de distinta longitud:

            inicio = (ancho - len(nombre) + 1) // 2 + 2

        El +2 es el hueco que nano reserva a la derecha para el estado, y la
        suma antes de dividir es su redondeo hacia arriba: con nombres de
        longitud impar, sin ella queda una columna a la izquierda.
        """
        ancho = self._ancho()
        izq = f"  GNU nano {VERSION}"
        centro = self.nombre if (self.nombre and not self.sin_titulo) else "New Buffer"
        der = "Modified" if self.modificado else ""

        inicio = (ancho - len(centro) + 1) // 2 + 2
        # Si el nombre es tan largo que se comeria la version, se pega a ella.
        inicio = max(inicio, len(izq) + 1)
        linea = izq.ljust(inicio) + centro
        if der:
            linea = linea.ljust(max(0, ancho - len(der) - 2)) + der + "  "
        return INVERSO + linea[:ancho].ljust(ancho) + NORMAL

    def _barra(self) -> list:
        """Las dos filas de atajos, tantas columnas como quepan.

        Reproduce bottombars() de nano: el numero de columnas sale del ancho
        del terminal, no de una lista fija, y cada hueco ocupa lo mismo. En un
        terminal ancho aparecen atajos que a 80 columnas no caben ---Undo,
        Redo, Set Mark, Copy...--- que es lo que hace el nano de verdad y lo
        que delataba al nuestro al agrandar la ventana.
        """
        ancho = self._ancho()
        columnas = max(1, min(len(ATAJOS), (ancho + 40) // 20))
        hueco = max(1, ancho // columnas)

        filas = []
        for cual in (0, 1):
            pintada = ""
            usado = 0
            for pareja in ATAJOS[:columnas]:
                tecla, etiqueta = pareja[cual]
                celda = f"{tecla} {etiqueta}".ljust(hueco)
                if usado + len(celda) > ancho:
                    celda = celda[:ancho - usado]
                    if not celda:
                        break
                # El video inverso va SOLO en la tecla, como en nano.
                corte = min(len(tecla), len(celda))
                pintada += INVERSO + celda[:corte] + NORMAL + celda[corte:]
                usado += len(celda)
            filas.append(pintada)
        return filas

    def _dibujar(self) -> None:
        """Pinta la ventana visible del texto y deja el cursor DONDE ESTA.

        Antes escribia el fichero entero y ponia el cursor al final: con mas
        lineas que pantalla, el texto se salia por arriba y el cursor no tenia
        nada que ver con el punto de edicion. Ahora la ventana sigue al cursor.

        Se redibuja entero en cada pulsacion. Para un fichero de las medidas
        que escribe un atacante eso no se nota, y es MUCHO mas seguro que
        actualizar trozos: un fallo de redibujado parcial deja basura en la
        pantalla del que esta dentro, que es exactamente lo que delata.
        """
        t = self.protocol.terminal
        ancho, alto = self._tam()
        self._asegurar()

        # Filas para texto: se descuentan el titulo, la linea en blanco, la de
        # estado y las dos de atajos.
        visibles = max(1, alto - 5)
        if self.fila < self.inicio:
            self.inicio = self.fila
        elif self.fila >= self.inicio + visibles:
            self.inicio = self.fila - visibles + 1
        self.inicio = max(0, min(self.inicio, max(0, len(self.lineas) - 1)))

        t.eraseDisplay()
        t.cursorHome()
        self.write(self._titulo() + "\r\n\r\n")
        for linea in self.lineas[self.inicio:self.inicio + visibles]:
            self.write(linea[:ancho] + "\r\n")
        self._pintar_barra()
        t.cursorPosition(max(0, min(self.col, ancho - 1)),
                         2 + (self.fila - self.inicio))

    def _pintar_barra(self, mensaje: str = "") -> None:
        t = self.protocol.terminal
        alto = self._alto()
        t.saveCursor()
        if mensaje:
            t.cursorPosition(0, alto - 3)
            t.eraseLine()
            self.write(INVERSO + mensaje + NORMAL)
        for i, fila in enumerate(self._barra()):
            t.cursorPosition(0, alto - 2 + i)
            t.eraseLine()
            self.write(fila)
        t.restoreCursor()

    def _aviso(self, texto: str, error: bool = False) -> None:
        """La linea de estado de nano, centrada.

        Con error=True sale en blanco sobre rojo, que es lo que hace nano con
        todo lo que tiene que ver con permisos.
        """
        t = self.protocol.terminal
        alto = self._alto()
        t.saveCursor()
        t.cursorPosition(0, alto - 3)
        t.eraseLine()
        etiqueta = f"[ {texto} ]".center(self._ancho())[:self._ancho()]
        if error:
            self.write(ROJO + etiqueta + FIN_ROJO)
        else:
            self.write(INVERSO + etiqueta + NORMAL)
        t.restoreCursor()

    # ------------------------------------------------------------- entrada
    def lineReceived(self, line: str) -> None:
        if self.preguntando == "guardar":
            destino = line.strip() or self.nombre
            self.preguntando = None
            self._guardar(destino)
            return
        if self.preguntando == "salir":
            respuesta = line.strip().lower()
            self.preguntando = None
            if respuesta.startswith("y"):
                self.preguntando = "guardar"
                self._preguntar(f"Write to File: {self.nombre}")
            elif respuesta.startswith("n"):
                self._salir()
            else:
                self._pintar_barra()
            return

        # Fuera de un dialogo, Enter ya no llega hasta aqui: lo lleva _intro,
        # que parte la linea por donde este el cursor. Si llegara ---por
        # ejemplo si alguien quita el manejador--- se ignora en vez de anadir
        # una linea suelta al final, que es lo que hacia antes y lo que hacia
        # imposible volver atras a corregir.
        self._dibujar()

    def _preguntar(self, texto: str) -> None:
        t = self.protocol.terminal
        alto = self._alto()
        t.cursorPosition(0, alto - 3)
        t.eraseLine()
        self.write(INVERSO + texto + NORMAL + " ")

    # -------------------------------------------------------------- atajos
    def _ctrl_o(self) -> None:
        self.preguntando = "guardar"
        self._preguntar(f"Write to File: {self.nombre}")

    def _ctrl_x(self) -> None:
        if self.modificado:
            self.preguntando = "salir"
            self._preguntar("Save modified buffer?")
            return
        self._salir()

    def _nada(self) -> None:
        """Una tecla que el editor reconoce y no hace nada visible con ella."""
        return

    def _ctrl_c(self) -> None:
        """^C en nano no mata: ensena la posicion en el fichero."""
        total = max(1, len(self.lineas))
        caracteres = sum(len(l) for l in self.lineas)
        self._aviso("line %d/%d (%d%%), col 1/1 (100%%), char %d/%d (100%%)"
                    % (total, total, 100, caracteres, caracteres))

    def _ctrl_g(self) -> None:
        self._aviso("Help is not available in this build")

    # --------------------------------------------------------------- salir
    def _guardar(self, destino: str) -> None:
        if not destino:
            self._aviso("Cancelled")
            self._pintar_barra()
            return
        contenido = ("\n".join(self.lineas) + "\n").encode("utf-8", "replace")
        ruta = self.fs.resolve_path(destino, self.protocol.cwd)

        # La comprobacion va ANTES de tocar nada. Antes se confiaba en que
        # fs.mkfile fallara, y no falla: Cowrie da de alta el nodo sin mirar
        # permisos, asi que un usuario normal "guardaba" en /etc/passwd y nano
        # contestaba "Wrote 1 line". Eso no lo hace ningun Linux.
        uid = getattr(self.protocol.user, "uid", 0)
        gid = getattr(self.protocol.user, "gid", 0)
        carpeta = _dir_de(ruta)
        try:
            ya_existe = self.fs.exists(ruta)
        except Exception:                                  # noqa: BLE001
            ya_existe = False

        if not _puede(self.fs, carpeta, uid, gid, "x"):
            self._aviso(f"Error writing {destino}: Permission denied", error=True)
            self._pintar_barra()
            return
        if ya_existe:
            permitido = _puede(self.fs, ruta, uid, gid, "w")
        else:
            permitido = _puede(self.fs, carpeta, uid, gid, "w")
        if not permitido:
            self._aviso(f"Error writing {destino}: Permission denied", error=True)
            self._pintar_barra()
            return

        try:
            self.fs.mkfile(ruta, self.current_user["uid"], self.current_user["gid"],
                           len(contenido), 33188)
        except Exception:                                  # noqa: BLE001
            self._aviso(f"Error writing {destino}: Permission denied", error=True)
            self._pintar_barra()
            return

        # El contenido se deja en un artefacto para que un "cat" posterior lo
        # devuelva de verdad. Sin esto el fichero existiria en el listado y
        # saldria vacio, que es peor que no crearlo.
        #
        # Va en su PROPIO try, y no junto al mkfile: los permisos ya se han
        # comprobado arriba, asi que un fallo aqui no es "Permission denied"
        # sino un problema nuestro guardando el artefacto. Meterlo en el mismo
        # bloque hacia que nano contestara un error de permisos que no era
        # cierto ---y a un atacante le diria que no puede escribir donde si
        # puede, que es la clase de incoherencia que delata al senuelo.
        try:
            self._persistir(ruta, contenido)
        except Exception:                                  # noqa: BLE001
            pass

        self.nombre = destino
        self.modificado = False
        # Se registra lo que ha escrito, que es el motivo de todo esto. NO se
        # usa file_download ni file_upload a proposito: esos dos alimentan la
        # tuberia de muestras hacia VirusTotal y MalwareBazaar, y un guion
        # tecleado a mano no es una muestra capturada en circulacion.
        try:
            self.protocol.events.dispatch(
                "cowrie.session.file_write",
                "Wrote %(lines)s lines to %(outfile)s with nano",
                outfile=ruta, lines=len(self.lineas),
                contents=contenido.decode("utf-8", "replace")[:4096],
            )
        except Exception:                                  # noqa: BLE001
            pass
        self._aviso(f"Wrote {len(self.lineas)} line"
                    f"{'' if len(self.lineas) == 1 else 's'}")
        self._pintar_barra()

    def _persistir(self, ruta: str, contenido: bytes) -> None:
        """Deja los bytes en disco y engancha el nodo del pickle a ellos."""
        from cowrie.core.artifact import Artifact

        # OJO: el __enter__ de Artifact devuelve el DESCRIPTOR, no el objeto,
        # asi que "with Artifact(...) as a" deja en "a" un fichero y no algo
        # con shasumFilename. Se guarda la referencia aparte, y se lee el
        # nombre DESPUES del with, que es cuando close() lo calcula.
        artefacto = Artifact("nano")
        with artefacto:
            artefacto.write(contenido)
        self.fs.update_realfile(self.fs.getfile(ruta), artefacto.shasumFilename)

    def _salir(self) -> None:
        # No hace falta limpiar nada: al volver a la pantalla normal ---en
        # exit()--- el terminal restaura por su cuenta lo que hubiera antes de
        # abrir el editor. Borrar aqui solo borraria el lienzo que se va a
        # tirar, y ademas dejaria la sesion del atacante en blanco, que es
        # justo lo que se quiere evitar.
        self.exit()

    def handle_CTRL_C(self) -> None:
        # En nano, ^C no mata: ensena la posicion. Y si hay un dialogo abierto,
        # lo cancela. Salir es ^X, y confundirlos delataria.
        if self.preguntando:
            self.preguntando = None
            self._pintar_barra()
            return
        self._asegurar()
        self._aviso("line %d/%d (col %d)" % (
            self.fila + 1, len(self.lineas), self.col + 1))

    def exit(self, code: int | None = None) -> None:
        # Va en exit() y no en _salir() a proposito: asi la pantalla se
        # devuelve por CUALQUIER camino de salida, incluido uno que se anada
        # despues y se olvide de restaurarla. Dejarse la pantalla alternativa
        # puesta le deja el terminal inservible a quien esta al otro lado.
        if not getattr(self, "exited", False):
            self.write(PANTALLA_NORMAL)
        self._soltar_teclas()
        self._soltar_tamano()
        HoneyPotCommand.exit(self, code)


commands["/usr/bin/nano"] = Command_nano
commands["nano"] = Command_nano
# pico es un enlace a nano en Debian, asi que es el MISMO programa.
commands["/usr/bin/pico"] = Command_nano
commands["pico"] = Command_nano
