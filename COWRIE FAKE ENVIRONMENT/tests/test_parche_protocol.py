#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_parche_protocol.py --- el prompt de contrasena que se comia a si mismo.

    python3 "COWRIE FAKE ENVIRONMENT/tests/test_parche_protocol.py"

Esto no comprueba que un texto se sustituya por otro: PULSA las teclas, antes
y despues del parche, contra un terminal de mentira que apunta todo lo que
recibe. Antes, borrar dentro de una contrasena movia el cursor y se comia el
prompt; despues, el terminal no recibe nada.

El fragmento de abajo esta copiado LETRA POR LETRA del protocol.py que corre
dentro del contenedor. La clase base imita lo que hace recvline (Twisted):
escribir SIEMPRE en el terminal, sepa o no que hay una contrasena en curso ---
que es justo el origen del fallo. Si algun dia el fichero de la imagen cambia,
el propio parche se niega a aplicarse, que es la otra mitad de esta prueba.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
PARCHE = os.path.join(AQUI, "..", "parche-protocol.py")

# La base imita a recvline; la clase de abajo esta copiada del fichero real.
ORIGINAL = '''
class _Recvline:
    """Lo que hace Twisted: tocar el terminal pase lo que pase."""

    def handle_BACKSPACE(self):
        if self.lineBufferIndex > 0:
            self.lineBufferIndex -= 1
            del self.lineBuffer[self.lineBufferIndex]
            self.terminal.apunta("cursorBackward")
            self.terminal.apunta("deleteCharacter")

    def handle_DELETE(self):
        self.terminal.apunta("deleteCharacter")

    def handle_LEFT(self):
        self.terminal.apunta("cursorBackward")

    def handle_RIGHT(self):
        self.terminal.apunta("cursorForward")

    def handle_HOME(self):
        self.terminal.apunta("cursorHome")

    def handle_END(self):
        self.terminal.apunta("cursorForward")

    def handle_UP(self):
        self.terminal.apunta("historial: el comando anterior, en claro")

    def handle_DOWN(self):
        self.terminal.apunta("historial")


class HoneyPotInteractiveProtocol(_Recvline):
    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?
        """
        self.resetTimeout()  # Reset the idle timeout
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            assert self.terminal is not None
            self.terminal.write(ch)

    def handle_RETURN(self) -> None:
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(b"".join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        recvline.RecvLine.handle_RETURN(self)

    def handle_TAB(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_TAB()

    def handle_CTRL_K(self) -> None:
        assert self.terminal is not None
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]

    def handle_CTRL_L(self) -> None:
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        assert self.terminal is not None
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()

    def handle_CTRL_U(self) -> None:
        assert self.terminal is not None
        for _ in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex :]
        self.lineBufferIndex = 0
'''

OK = MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba %r\n          obtuvo   %r"
              % (que, esperado, obtenido))


class TerminalFalso:
    """Apunta todo lo que le mandan. Si aqui llega algo durante una
    contrasena, el atacante lo ha visto en pantalla."""

    def __init__(self):
        self.visto = []

    def apunta(self, que):
        self.visto.append(que)

    def write(self, datos):
        self.visto.append("write:%r" % datos)

    def __getattr__(self, nombre):
        # cursorBackward, deleteCharacter, eraseDisplay, eraseToLineEnd...
        return lambda *a, **k: self.visto.append(nombre)


def carga(fuente):
    """Ejecuta el fragmento y devuelve la clase."""
    espacio = {}
    exec(compile(fuente, "<protocol>", "exec"), espacio)
    return espacio["HoneyPotInteractiveProtocol"]


def instancia(clase, contrasena, buffer_=b"abc"):
    obj = clase()
    obj.terminal = TerminalFalso()
    obj.password_input = contrasena
    obj.mode = "insert"
    obj.cmdstack = []
    obj.historyLines = []
    obj.lineBuffer = [bytes([b]) for b in buffer_]
    obj.lineBufferIndex = len(obj.lineBuffer)
    obj.resetTimeout = lambda: None
    obj.drawInputLine = lambda: obj.terminal.apunta("drawInputLine")
    return obj


def parchea(fuente):
    """Escribe el fragmento, lo parchea y devuelve (codigo, texto, salida)."""
    fh = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                     encoding="utf-8")
    fh.write(fuente)
    fh.close()
    r = subprocess.run([sys.executable, PARCHE, fh.name],
                       capture_output=True, text=True)
    texto = io.open(fh.name, encoding="utf-8").read()
    os.unlink(fh.name)
    return r.returncode, texto, (r.stdout + r.stderr)


print()
print("Antes del parche: el terminal se mueve, y por eso se come el prompt")
_Antes = carga(ORIGINAL)
_o = instancia(_Antes, contrasena=True)
_o.handle_BACKSPACE()
comprueba("el borrado mueve el cursor aunque no haya eco", True,
          "cursorBackward" in _o.terminal.visto)
_o = instancia(_Antes, contrasena=True)
_o.handle_UP()
comprueba("y la flecha arriba pinta el historial", 1, len(_o.terminal.visto))

print()
print("Se aplica")
_cod, _texto, _dice = parchea(ORIGINAL)
comprueba("el parche se aplica", 0, _cod)
comprueba("y lo que queda compila", True, "PARCHE DIRTYLAND" in _texto)

_Despues = carga(_texto)

print()
print("Despues: en modo contrasena no llega NADA al terminal")
# Cada tecla por separado, porque cada una llegaba por su cuenta.
for _tecla in ("handle_BACKSPACE", "handle_DELETE", "handle_LEFT",
               "handle_RIGHT", "handle_HOME", "handle_END", "handle_UP",
               "handle_DOWN", "handle_CTRL_K", "handle_CTRL_L",
               "handle_CTRL_U"):
    _o = instancia(_Despues, contrasena=True)
    getattr(_o, _tecla)()
    comprueba("%s no escribe nada" % _tecla, [], _o.terminal.visto)

# El tabulador no llega al comando: completar dentro de una contrasena
# escribiria rutas en pantalla.
_o = instancia(_Despues, contrasena=True)
_o.cmdstack = [type("C", (), {"handle_TAB": lambda s: 1 / 0})()]
_o.handle_TAB()
comprueba("el tabulador no se pasa al comando", [], _o.terminal.visto)

print()
print("Pero el borrado SIGUE borrando: la contrasena se puede corregir")
_o = instancia(_Despues, contrasena=True, buffer_=b"abc")
_o.handle_BACKSPACE()
comprueba("del buffer si sale el caracter", [b"a", b"b"], _o.lineBuffer)
comprueba("y el indice le sigue", 2, _o.lineBufferIndex)
_o.handle_CTRL_U()
comprueba("y Ctrl-U mata la linea, como en sudo", [], _o.lineBuffer)

print()
print("Y fuera del modo contrasena todo sigue igual que antes")
_o = instancia(_Despues, contrasena=False)
_o.handle_BACKSPACE()
comprueba("el borrado normal si mueve el cursor",
          ["cursorBackward", "deleteCharacter"], _o.terminal.visto)
_o = instancia(_Despues, contrasena=False)
_o.handle_UP()
comprueba("y la flecha arriba sigue trayendo el historial", 1,
          len(_o.terminal.visto))
_o = instancia(_Despues, contrasena=False)
_o.handle_CTRL_L()
comprueba("y Ctrl-L sigue repintando", True,
          "drawInputLine" in _o.terminal.visto)

print()
print("Y dentro de un sh (dash) no hay edicion de linea")
# dash no tiene historial ni completado: por SSH el terminal va en modo
# canonico, asi que el borrado y Ctrl-U los hace el nucleo ---y siguen
# funcionando--- pero las flechas y el tabulador son bytes que dash no
# interpreta. Medido contra dash 0.5.12: la flecha arriba escribe "^[[A".
def _con_dash(sabor):
    o = instancia(_Despues, contrasena=False)
    o.cmdstack = [type("S", (), {"dash": sabor})()]
    return o


# dash NO NAVEGA: escribe la secuencia y esos caracteres acaban en la orden.
# Medido: "^[[A" en pantalla y dash protestando por ello al pulsar Enter.
for _tecla, _sec in (("handle_UP", "^[[A"), ("handle_DOWN", "^[[B"),
                     ("handle_LEFT", "^[[D"), ("handle_RIGHT", "^[[C"),
                     ("handle_HOME", "^[[H"), ("handle_END", "^[[F"),
                     ("handle_DELETE", "^[[3~")):
    _o = _con_dash(True)
    _o.lineBuffer = []
    _o.lineBufferIndex = 0
    getattr(_o, _tecla)()
    comprueba("en sh, %s escribe %r" % (_tecla, _sec), _sec,
              b"".join(_o.lineBuffer).decode())
    # Y SE VE: si no se escribiera en el terminal, el atacante teclearia a
    # ciegas, que es otra cosa que no hace ningun dash.
    comprueba("   y se ve en pantalla", True, len(_o.terminal.visto) == len(_sec))

# LA CUENTA CUADRA, que es la razon de meter caracteres literales y no el byte
# de escape: el terminal dibuja un ESC como "^[" ---dos columnas para un
# byte--- y el borrado retrocede una columna por byte. Ese desajuste es el que
# hacia que el prompt de contrasena se comiera a si mismo.
_o = _con_dash(True)
_o.lineBuffer = []
_o.lineBufferIndex = 0
_o.handle_UP()
comprueba("un byte por columna, para que el borrado cuadre",
          (4, 4), (len(_o.lineBuffer), len(_o.terminal.visto)))

# El tabulador no completa: entra en la linea, como en dash.
_o = _con_dash(True)
_o.lineBuffer = []
_o.lineBufferIndex = 0
_o.cmdstack[0].handle_TAB = lambda: 1 / 0    # completar seria un delator
_o.handle_TAB()
comprueba("en sh el tabulador se escribe, no completa", "\t",
          b"".join(_o.lineBuffer).decode())

# Pero lo que el nucleo si hace en modo canonico sigue haciendose.
_o = _con_dash(True)
_o.handle_BACKSPACE()
comprueba("en sh el borrado SIGUE borrando",
          ["cursorBackward", "deleteCharacter"], _o.terminal.visto)
_o = _con_dash(True)
_o.handle_CTRL_U()
comprueba("y Ctrl-U sigue matando la linea", [], _o.lineBuffer)

# Y en una shell que NO es dash, el historial sigue estando.
_o = _con_dash(False)
_o.handle_UP()
comprueba("en bash la flecha arriba sigue trayendo el historial", 1,
          len(_o.terminal.visto))

print()
print("Lo que se niega a hacer")
_cod, _texto2, _dice = parchea(_texto)
comprueba("aplicarse dos veces (idempotente)", 0, _cod)
comprueba("   y no toca nada la segunda", True, "ya estaba parcheado" in _dice)
comprueba("   ni duplica los guardias", 5, _texto2.count("PARCHE DIRTYLAND"))

_roto = ORIGINAL.replace("    def handle_CTRL_U(self) -> None:",
                         "    def handle_CTRL_U(self, x=None) -> None:")
_cod, _texto3, _dice = parchea(_roto)
comprueba("parchear un fichero que ya no es el esperado", 1, _cod)
comprueba("   y lo dice nombrando el fragmento", True,
          "NO ES EL ESPERADO" in _dice)
comprueba("   sin tocar el fichero", True, "PARCHE DIRTYLAND" not in _texto3)

print()
print("-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
