#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Parche del protocol.py de Cowrie: el prompt de contrasena se comia a si mismo.

    sudo /opt/dirtyland/cowrie/parche-protocol.py \\
         /opt/dirtyland/cowrie/parches/protocol.py

QUE SE VE SIN ESTO, y se vio en la maquina, no se dedujo:

  1. Escribes una letra en "[sudo] password for root: " y le das al borrado.
     El cursor retrocede sobre el PROMPT y se lleva un caracter del mensaje.
     Vuelves a escribir una letra, vuelves a borrar, y se lleva otra. Con
     paciencia se borra el mensaje entero.

  2. Las flechas arriba/abajo PINTAN el comando anterior en el hueco de la
     contrasena: el historial se escribe en el terminal aunque el eco este
     apagado.

  3. Ctrl-L repinta la linea de entrada... con la contrasena dentro, en claro.

POR QUE PASA. characterReceived() ya se calla el eco cuando password_input
esta puesto ---eso estaba bien---, pero las teclas de EDICION no estan
definidas en HoneyPotInteractiveProtocol: se heredan de recvline (Twisted),
que siempre escribe en el terminal. Y como en modo contrasena no hay nada
escrito en pantalla, cada borrado se come lo unico que hay delante del
cursor, que es el propio prompt.

LA REGLA QUE SE APLICA, que es la de sudo(8): mientras se lee una contrasena
solo cuentan los caracteres, el borrado y el matar la linea. Todo lo demas
---flechas, historial, tabulador, Inicio/Fin, Ctrl-K, Ctrl-L--- no hace nada,
y NADA escribe en el terminal.

POR QUE UN PARCHE Y NO EL FICHERO ENTERO. Son 547 lineas de Cowrie que no son
nuestras. Traerlas al repositorio obliga a rehacerlas en cada actualizacion de
la imagen, y lo que cambiamos son cinco metodos. Es el mismo trato que se le
da al mssql.py de Dionaea, y por lo mismo.

SE NIEGA A ADIVINAR. Si el fichero no es exactamente el que esperamos ---otro
digest de la imagen, por ejemplo--- no toca nada y lo dice. Un parche a medias
sobre un fichero que ya cambio no da ningun error y deja el senuelo
comportandose de una forma que no esta escrita en ninguna parte.
"""

from __future__ import annotations

import io
import sys

MARCA = "PARCHE DIRTYLAND"

GUARDIAS = '''    # --- PARCHE DIRTYLAND: en modo contrasena el terminal no se mueve ---
    #
    # characterReceived() ya se calla el eco, pero las teclas de edicion se
    # heredan de recvline y SIEMPRE escriben en el terminal. Sin eco no hay
    # nada en pantalla que borrar, asi que el cursor retrocedia sobre el
    # propio prompt: escribir una letra y borrarla se comia un caracter de
    # "[sudo] password for root: ". Ver COWRIE FAKE ENVIRONMENT/parche-protocol.py.
    def _leyendo_contrasena(self) -> bool:
        return bool(getattr(self, "password_input", False))

    def _sin_edicion(self) -> bool:
        # dash NO tiene edicion de linea. Por SSH el terminal va en modo
        # canonico: el borrado y Ctrl-U los hace el nucleo ---y por eso siguen
        # funcionando--- pero las flechas, Inicio/Fin y el tabulador son solo
        # bytes que dash no interpreta. Medido contra dash 0.5.12: la flecha
        # arriba escribe "^[[A" en pantalla y esos bytes acaban en la orden.
        # Aqui no hacen nada, que se parece mucho mas a dash que traer el
        # historial de bash.
        pila = getattr(self, "cmdstack", None)
        return bool(pila) and bool(getattr(pila[-1], "dash", False))

    def handle_BACKSPACE(self) -> None:
        if self._leyendo_contrasena():
            if self.lineBufferIndex > 0:
                self.lineBufferIndex -= 1
                del self.lineBuffer[self.lineBufferIndex]
            return
        super().handle_BACKSPACE()

    def handle_DELETE(self) -> None:
        if self._leyendo_contrasena():
            if self.lineBufferIndex < len(self.lineBuffer):
                del self.lineBuffer[self.lineBufferIndex]
            return
        if self._sin_edicion():
            self._dash_teclea(b"^[[3~")
            return
        super().handle_DELETE()

    def handle_LEFT(self) -> None:
        if self._leyendo_contrasena():
            return
        if self._sin_edicion():
            self._dash_teclea(b"^[[D")
            return
        super().handle_LEFT()

    def handle_RIGHT(self) -> None:
        if self._leyendo_contrasena():
            return
        if self._sin_edicion():
            self._dash_teclea(b"^[[C")
            return
        super().handle_RIGHT()

    def handle_HOME(self) -> None:
        if self._leyendo_contrasena():
            return
        if self._sin_edicion():
            self._dash_teclea(b"^[[H")
            return
        super().handle_HOME()

    def handle_END(self) -> None:
        if self._leyendo_contrasena():
            return
        if self._sin_edicion():
            self._dash_teclea(b"^[[F")
            return
        super().handle_END()

    def _dash_teclea(self, texto) -> None:
        """Mete en la linea lo que se VE al pulsar la tecla en dash.

        dash no tiene edicion: la flecha arriba no trae nada del historial,
        el terminal ESCRIBE la secuencia y esos caracteres acaban en la orden.
        Medido: "^[[A" en pantalla, y al pulsar Enter dash protesta por ello.

        Se meten los CARACTERES literales "^", "[", "[", "A" y no el byte de
        escape de verdad. Motivo: el terminal dibuja un ESC como "^[", o sea
        DOS columnas para UN byte, y el borrado de esta clase retrocede una
        columna por byte. Ese desajuste entre lo que se ve y lo que se guarda
        es exactamente el que hacia que el prompt de contrasena se comiera a
        si mismo. Con cuatro caracteres para cuatro columnas, el borrado
        cuadra y en pantalla se lee lo mismo.
        """
        for i in range(len(texto)):
            self.characterReceived(texto[i:i + 1], False)

    def handle_UP(self) -> None:
        # Sin esto la flecha arriba PINTA el comando anterior en el hueco de
        # la contrasena, en claro.
        if self._leyendo_contrasena():
            return
        if self._sin_edicion():
            self._dash_teclea(b"^[[A")
            return
        super().handle_UP()

    def handle_DOWN(self) -> None:
        if self._leyendo_contrasena():
            return
        if self._sin_edicion():
            self._dash_teclea(b"^[[B")
            return
        super().handle_DOWN()

'''

# (que se busca, con que se sustituye)
CAMBIOS = (
    # 1. Los guardias nuevos, delante del primer handle_ que ya existe.
    (
        """    def handle_RETURN(self) -> None:
        if len(self.cmdstack) == 1:
""",
        GUARDIAS + """    def handle_RETURN(self) -> None:
        if len(self.cmdstack) == 1:
""",
    ),
    # 2. El tabulador no completa nada dentro de una contrasena.
    (
        """    def handle_TAB(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_TAB()
""",
        """    def handle_TAB(self) -> None:
        if self._leyendo_contrasena():   # PARCHE DIRTYLAND
            return
        if self._sin_edicion():
            # dash no completa nada: el tabulador entra en la linea.
            self._dash_teclea(b"\t")
            return
        if self.cmdstack:
            self.cmdstack[-1].handle_TAB()
""",
    ),
    # 3. Ctrl-K borra hasta el final de linea EN PANTALLA.
    (
        """    def handle_CTRL_K(self) -> None:
        assert self.terminal is not None
        self.terminal.eraseToLineEnd()
""",
        """    def handle_CTRL_K(self) -> None:
        if self._leyendo_contrasena():   # PARCHE DIRTYLAND
            return
        assert self.terminal is not None
        self.terminal.eraseToLineEnd()
""",
    ),
    # 4. Ctrl-L repinta la linea de entrada: con la contrasena dentro.
    (
        """        assert self.terminal is not None
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()
""",
        """        if self._leyendo_contrasena():   # PARCHE DIRTYLAND
            return
        assert self.terminal is not None
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()
""",
    ),
    # 5. Ctrl-U si mata la linea ---sudo tambien lo hace--- pero sin pintar.
    (
        """    def handle_CTRL_U(self) -> None:
        assert self.terminal is not None
        for _ in range(self.lineBufferIndex):
""",
        """    def handle_CTRL_U(self) -> None:
        if self._leyendo_contrasena():   # PARCHE DIRTYLAND
            self.lineBuffer = self.lineBuffer[self.lineBufferIndex:]
            self.lineBufferIndex = 0
            return
        assert self.terminal is not None
        for _ in range(self.lineBufferIndex):
""",
    ),
)


def main() -> int:
    if len(sys.argv) != 2:
        print("uso: parche-protocol.py <ruta del protocol.py>", file=sys.stderr)
        return 2
    ruta = sys.argv[1]

    try:
        texto = io.open(ruta, encoding="utf-8").read()
    except OSError as err:
        print("no se pudo leer %s: %s" % (ruta, err), file=sys.stderr)
        return 1

    # Idempotente: el README se copia y se pega, y correrlo dos veces no puede
    # romper nada.
    if MARCA in texto:
        print("ya estaba parcheado, no se toca nada")
        return 0

    for viejo, _nuevo in CAMBIOS:
        veces = texto.count(viejo)
        if veces != 1:
            print(
                "ESTE protocol.py NO ES EL ESPERADO: el fragmento\n\n%s\n"
                "aparece %d veces (deberia aparecer 1). No se parchea nada.\n"
                "Probablemente ha cambiado la version de Cowrie: hay que\n"
                "revisar los metodos de edicion a mano antes de montar nada."
                % (viejo.rstrip(), veces),
                file=sys.stderr,
            )
            return 1

    for viejo, nuevo in CAMBIOS:
        texto = texto.replace(viejo, nuevo, 1)

    io.open(ruta, "w", encoding="utf-8").write(texto)

    # Se comprueba lo escrito, no se da por bueno el write. Y ademas se
    # compila: un parche que deja el fichero con un error de sintaxis tumba a
    # Cowrie entero al arrancar, no un comando suelto.
    comprobar = io.open(ruta, encoding="utf-8").read()
    if comprobar.count(MARCA) != 5:
        print("el parche no quedo como debia", file=sys.stderr)
        return 1
    try:
        compile(comprobar, ruta, "exec")
    except SyntaxError as err:
        print("el fichero parcheado no compila: %s" % err, file=sys.stderr)
        return 1
    print("parcheado: %s" % ruta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
