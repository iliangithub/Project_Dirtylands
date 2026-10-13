#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_parche_mssql.py --- el bucle de Dionaea que colgaba el senuelo.

    python3 DIONAEA/tests/test_parche_mssql.py

Esto no comprueba que un texto se sustituya por otro: EJECUTA el bucle, antes
y despues del parche, y comprueba que uno no termina nunca y el otro si.

El fragmento de codigo de abajo esta copiado LETRA POR LETRA del mssql.py que
corre dentro del contenedor (sacado con "docker cp" de la imagen fijada por
digest en el compose). Se cierra la funcion despues del bucle, porque lo que
hay detras ---el reparto por tipo de paquete--- no llega a ejecutarse nunca
con la entrada que provoca el fallo. Si algun dia el fichero de la imagen
cambia, el propio parche se niega a aplicarse, que es la otra mitad de esta
prueba.

EL FALLO, en una linea: se comprueba el Length de la cabecera, luego se
reescribe la cabecera con un trozo truncado, y se avanza con el Length de la
reescrita. Un atacante que declare un Length entre 1 y 7 hace que el offset
avance 0 y el bucle no salga jamas. Paso el 2026-08-23 y otra vez el 28.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
PARCHE = os.path.join(AQUI, "..", "parche-mssql.py")

# Copiado del fichero de la imagen. La indentacion importa: el parche busca
# estos fragmentos exactos y se niega si no los encuentra tal cual.
ORIGINAL = '''import traceback

logger = None
TDS_STATUS_EOM = 1


class mssqld:
    def handle_io_in(self, data: bytes) -> int:
        offset = 0
        chunk = b''
        while len(data) > offset:
            p = None
            try:
                if len(data) - offset < 8:  # length of TDS_Header
                    logger.warning("Incomplete TDS_Header")
                    return offset

                p = TDS_Header(data[offset:offset+8])
                p.show()

                if p.Length == 0:
                    logger.warning("Bad TDS Header, Length = 0")
                    return offset

                if len(data[offset:]) < p.Length:
                    return offset

                chunk = data[offset:offset+p.Length]
                p = TDS_Header(chunk)

                offset += p.Length
                self.buf += chunk[8:]
                self.pendingPacketType = p.Type

                if p.Status != TDS_STATUS_EOM:
                    # Command spans multiple packets TDS_ things
                    # this is not the last packet
                    continue
            except Exception:
                t = traceback.format_exc()
                logger.error(t)
                return offset
            return offset
        return offset
'''


class Vueltas(BaseException):
    """El bucle no termina. Se corta para que la prueba no se cuelgue.

    Hereda de BaseException Y NO DE Exception a proposito: el bucle de Dionaea
    esta envuelto en un "except Exception: return offset" que se tragaba este
    corte y hacia que la prueba diera el bucle por terminado. O sea que la
    primera version de esta prueba decia que no habia fallo. Ese "except" tan
    ancho es, de paso, parte de por que el problema es dificil de ver desde
    dentro."""


class Registro:
    def __init__(self):
        self.avisos = []

    def warning(self, texto, *args):
        self.avisos.append(texto % args if args else texto)

    def error(self, texto, *args):
        self.avisos.append(texto % args if args else texto)


def entorno(tope=2000):
    """Los dobles minimos para poder ejecutar el bucle de verdad."""
    cuenta = {"n": 0}

    class TDS_Header:
        # Imita a scapy en lo unico que importa aqui: si le das menos bytes de
        # los que ocupa la cabecera, RELLENA CON CEROS en vez de fallar. De ahi
        # sale el Length 0 que congela el bucle.
        def __init__(self, datos=b"", **kw):
            cuenta["n"] += 1
            if cuenta["n"] > tope:
                raise Vueltas()
            crudo = bytes(datos)[:8]
            crudo += b"\x00" * (8 - len(crudo))
            self.Type = crudo[0]
            self.Status = crudo[1]
            self.Length = int.from_bytes(crudo[2:4], "big")

        def show(self):
            pass

    reg = Registro()
    ambito = {"TDS_Header": TDS_Header, "logger": reg, "__name__": "mssql"}
    return ambito, reg


def cargar(fuente):
    ambito, reg = entorno()
    exec(compile(fuente, "mssql.py", "exec"), ambito)
    ambito["logger"] = reg
    obj = ambito["mssqld"]()
    obj.buf = b""
    obj.pendingPacketType = None
    return obj, reg


# El paquete que cuelga a Dionaea. Dice medir UN byte; la cabecera TDS son 8,
# asi que es imposible, pero el Length lo escribe quien se conecta y nada le
# impide poner lo que quiera.
#   byte 0 = Type, byte 1 = Status, bytes 2-3 = Length (big endian)
#
# Tiene que ser 1, 2 o 3, y el motivo es fino: el trozo que se corta son los
# primeros Length bytes, o sea el principio de la propia cabecera. Con 4 o mas
# ese trozo todavia incluye los bytes 2-3, el reparseo devuelve el mismo
# Length y el offset avanza ---mal, pero avanza---. Con 1, 2 o 3 los bytes del
# Length quedan fuera, el reparseo los rellena con ceros, el Length sale 0 y
# el offset no se mueve nunca.
VENENO = b"\x01\x00\x00\x01" + b"A" * 12

OK = 0
MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>"
              % (que, esperado, obtenido))


def main():
    print()
    print("El fallo, ejecutado")
    obj, _reg = cargar(ORIGINAL)
    try:
        obj.handle_io_in(VENENO)
        colgado = False
    except Vueltas:
        colgado = True
    comprueba("sin parche, el bucle no termina nunca", True, colgado)

    tmp = tempfile.mkdtemp()
    ruta = os.path.join(tmp, "mssql.py")
    io.open(ruta, "w", encoding="utf-8").write(ORIGINAL)

    def parchear(destino):
        return subprocess.run([sys.executable, PARCHE, destino],
                              capture_output=True, text=True)

    r = parchear(ruta)
    comprueba("el parche se aplica", 0, r.returncode)

    parcheado = io.open(ruta, encoding="utf-8").read()
    obj2, reg2 = cargar(parcheado)
    try:
        devuelto = obj2.handle_io_in(VENENO)
        colgado2 = False
    except Vueltas:
        devuelto = None
        colgado2 = True
    comprueba("con parche, termina", False, colgado2)
    # Devolver 0 significa "no he consumido nada": Dionaea cierra o espera mas
    # datos, que es lo correcto ante una cabecera imposible.
    comprueba("y no da por consumido nada", 0, devuelto)
    comprueba("dejando dicho lo que llego", True,
              any("Length = 1" in a for a in reg2.avisos))

    # Con 4..7 no se colgaba ---el offset avanzaba--- pero seguia siendo una
    # cabecera imposible que se procesaba a medias. El parche la rechaza
    # tambien, que es lo que dice el protocolo.
    obj_corto, reg_corto = cargar(parcheado)
    comprueba("un Length de 4 tampoco se acepta ya", 0,
              obj_corto.handle_io_in(b"\x01\x00\x00\x04" + b"A" * 12))
    comprueba("y se dice cual era", True,
              any("Length = 4" in a for a in reg_corto.avisos))

    print()
    print("Lo que el parche NO puede hacer")
    # Se ejecuta dos veces porque el README se copia y se pega, y porque tras
    # una reinstalacion no se sabe si ya estaba puesto.
    r2 = parchear(ruta)
    comprueba("aplicarlo dos veces no rompe nada", 0, r2.returncode)
    comprueba("y lo dice en vez de callarse", True, "ya estaba" in r2.stdout)
    comprueba("el fichero no cambia la segunda vez", parcheado,
              io.open(ruta, encoding="utf-8").read())

    # Si cambia el digest de la imagen, este fichero puede venir distinto. Un
    # parche aplicado a medias se monta encima sin dar error y el senuelo se
    # comporta de una forma que no esta escrita en ningun sitio.
    otro = os.path.join(tmp, "otro.py")
    io.open(otro, "w", encoding="utf-8").write(
        ORIGINAL.replace("if p.Length == 0:", "if p.Length == 1:"))
    r3 = parchear(otro)
    comprueba("sobre un fichero que no reconoce, se niega", 1, r3.returncode)
    comprueba("y explica por que", True, "NO ES EL ESPERADO" in r3.stderr)
    comprueba("sin tocar el fichero",
              ORIGINAL.replace("if p.Length == 0:", "if p.Length == 1:"),
              io.open(otro, encoding="utf-8").read())

    print()
    print("Un paquete legitimo sigue funcionando igual")
    # Length 12 = 8 de cabecera + 4 de datos, Status = EOM. Antes y despues
    # del parche tiene que consumirlo entero y devolver 12.
    bueno = b"\x01\x01\x00\x0c" + b"B" * 8
    obj3, _ = cargar(parcheado)
    comprueba("se consume el paquete entero", 12, obj3.handle_io_in(bueno))
    obj4, _ = cargar(ORIGINAL)
    comprueba("y el parche no cambia ese resultado", 12,
              obj4.handle_io_in(bueno))

    # Una cabecera cortada de verdad (menos de 8 bytes en el buffer) ya se
    # trataba bien: no se toca ese camino.
    obj5, reg5 = cargar(parcheado)
    comprueba("una cabecera incompleta sigue devolviendo 0", 0,
              obj5.handle_io_in(b"\x01\x01\x00"))
    comprueba("y avisando", True,
              any("Incomplete" in a for a in reg5.avisos))

    print()
    print("-------------------------------------")
    print("ok: %d   fallos: %d" % (OK, MAL))
    return 1 if MAL else 0


if __name__ == "__main__":
    sys.exit(main())
