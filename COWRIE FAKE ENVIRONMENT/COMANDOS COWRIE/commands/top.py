# SPDX-License-Identifier: BSD-3-Clause
"""
top para el senuelo.

Cowrie sirve como "top" un fichero enlatado con el texto
"E82: Cannot allocate any buffer, exiting...", que es un mensaje de ERROR DE VIM.
Escribir "top" y que conteste Vim delata el senuelo en un solo comando, igual
que pasaba con "nano" y su E558.

Los procesos NO se inventan aqui: salen del mismo ps_command_output.json que
alimenta a "ps aux", asi que las dos listas no pueden contradecirse. Lo unico
que se calcula es la parte que cambia sola: la hora, el uptime y el reparto de
tareas por estado.

Se redibuja cada 3 segundos, que es el intervalo por defecto de top. Una
pantalla congelada durante medio minuto tambien es un indicio.
"""

from __future__ import annotations

import json
import os
import time

from twisted.internet import reactor

from cowrie.commands.base import IGNIS_BOOT_EPOCH
from cowrie.shell.command import HoneyPotCommand

commands = {}

PS_JSON = "/opt/ps_command_output.json"
INTERVALO = 3.0
INVERSO = "\x1b[7m"
NORMAL = "\x1b[0m"


# La copia que habia aqui decia "1 days" y no sabia escribir "45 min". Ahora
# es la misma funcion que usan "uptime" y "w": ver base.formato_uptime().
from cowrie.commands.base import formato_uptime as _uptime_corto


def lineas_memoria(total, libre, usada, cache, swap_total, swap_libre,
                   disponible) -> tuple[str, str]:
    """Las dos lineas de memoria de top, aparte para poder medirlas.

    SIN ESPACIO DETRAS DE LOS DOS PUNTOS NI DE LAS COMAS: el %9.1f ya trae su
    propio relleno, y anadir otro dejaba un espacio de mas en cada uno de los
    ocho campos. Medido en un Debian 13.6:

      'MiB Mem :  15647.8 total,   2356.5 free,   8321.8 used,   6069.2 buff/cache'
      'MiB Swap:   1952.0 total,   1952.0 free,      0.0 used.   7326.1 avail Mem'

    Y el PUNTO antes de "avail Mem" en la linea de Swap no es una errata: top
    usa punto ahi y coma en los otros tres.
    """
    return (
        f"MiB Mem :{total:9.1f} total,{libre:9.1f} free,"
        f"{usada:9.1f} used,{cache:9.1f} buff/cache",
        f"MiB Swap:{swap_total:9.1f} total,{swap_libre:9.1f} free,"
        f"{swap_total - swap_libre:9.1f} used.{disponible:9.1f} avail Mem",
    )



class Command_top(HoneyPotCommand):
    def start(self) -> None:
        self.previos: dict[bytes, object] = {}
        self.pendiente = None
        self.procesos = self._cargar()
        self._tomar_teclas()
        self._pintar()

    # ------------------------------------------------------------ datos
    def _cargar(self) -> list[dict]:
        try:
            with open(PS_JSON, encoding="utf-8") as f:
                datos = json.load(f)["command"]["ps"]
        except Exception:
            return []
        # top ordena por %CPU descendente; a igualdad, por PID.
        return sorted(datos, key=lambda p: (-float(p.get("CPU", 0)), p.get("PID", 0)))

    # ---------------------------------------------------------- teclado
    def _tomar_teclas(self) -> None:
        """q y ^C cierran top. Lo demas se traga, como hace top de verdad."""
        # Las flechas arriba/abajo tambien, por lo mismo que en nano: sin
        # taparlas, recvline las sigue tratando como el historial del shell y
        # dentro de top aparecerian los comandos ya ejecutados. El nombre de
        # la tecla se coge del terminal, porque para cuando llega aqui insults
        # ya tradujo la secuencia del cable a su constante.
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
            b"\x03": self._salir,
            b"\x04": self._salir,
            tecla("UP_ARROW", b"[UP_ARROW]"): self._nada,
            tecla("DOWN_ARROW", b"[DOWN_ARROW]"): self._nada,
        }
        for tecla, funcion in mapa.items():
            self.previos[tecla] = self.protocol.keyHandlers.get(tecla)
            self.protocol.keyHandlers[tecla] = funcion
        # Las teclas imprimibles no pasan por keyHandlers: hay que interceptar
        # characterReceived, que es quien las recibe.
        self.char_previo = self.protocol.characterReceived
        self.protocol.characterReceived = self._tecla

    def _soltar_teclas(self) -> None:
        for tecla, antes in self.previos.items():
            if antes is None:
                self.protocol.keyHandlers.pop(tecla, None)
            else:
                self.protocol.keyHandlers[tecla] = antes
        self.previos = {}
        if getattr(self, "char_previo", None) is not None:
            self.protocol.characterReceived = self.char_previo
            self.char_previo = None

    def _tecla(self, ch, moreCharactersComing=False) -> None:
        letra = ch.decode("utf-8", "ignore") if isinstance(ch, bytes) else str(ch)
        if letra in ("q", "Q"):
            self._salir()
        elif letra == " ":
            self._pintar()
        # Cualquier otra tecla no hace nada visible, y sobre todo NO se escribe
        # en la linea de comandos: dentro de top la pantalla no es un prompt.

    def _nada(self) -> None:
        """Se traga la tecla sin hacer nada."""

    def _salir(self) -> None:
        if self.pendiente is not None and self.pendiente.active():
            self.pendiente.cancel()
        self.pendiente = None
        self.protocol.terminal.eraseDisplay()
        self.protocol.terminal.cursorHome()
        self.exit()

    # ---------------------------------------------------------- pantalla
    def _alto(self) -> int:
        try:
            return int(self.environ.get("LINES", 24))
        except (TypeError, ValueError):
            return 24

    def _ancho(self) -> int:
        try:
            return int(self.environ.get("COLUMNS", 80))
        except (TypeError, ValueError):
            return 80

    def _cabecera(self) -> list[str]:
        arriba = time.time() - IGNIS_BOOT_EPOCH
        estados = [str(p.get("STAT", "S"))[:1] for p in self.procesos]
        corriendo = estados.count("R")
        parados = estados.count("T")
        zombis = estados.count("Z")
        durmiendo = len(estados) - corriendo - parados - zombis

        mem = self._memoria()
        return [
            f"top - {time.strftime('%H:%M:%S')} up {_uptime_corto(arriba)},  1 user, "
            f" load average: 0.00, 0.01, 0.00",
            f"Tasks: {len(self.procesos):3d} total, {corriendo:3d} running, "
            f"{durmiendo:3d} sleeping, {parados:3d} stopped, {zombis:3d} zombie",
            "%Cpu(s):  0.8 us,  0.4 sy,  0.0 ni, 98.7 id,  0.1 wa,  "
            "0.0 hi,  0.0 si,  0.0 st",
            mem[0],
            mem[1],
            "",
        ]

    def _memoria(self) -> tuple[str, str]:
        """Lee el mismo /proc/meminfo del honeyfs que usa free."""
        datos = {}
        try:
            with open("/opt/honeyfs/proc/meminfo", encoding="utf-8") as f:
                for linea in f:
                    campos = linea.split(":")
                    if len(campos) == 2:
                        datos[campos[0]] = int(campos[1].split()[0])
        except Exception:
            datos = {}

        def mib(clave):
            return datos.get(clave, 0) / 1024.0

        total = mib("MemTotal")
        libre = mib("MemFree")
        cache = mib("Buffers") + mib("Cached")
        usada = total - libre - cache
        return lineas_memoria(total, libre, usada, cache,
                              mib("SwapTotal"), mib("SwapFree"),
                              mib("MemAvailable"))

    def _fila(self, p: dict) -> str:
        # El JSON guarda VSZ y RSS multiplicados por mil, igual que los lee el
        # "ps" de Cowrie. top los ensena en kibibytes.
        virt = int(p.get("VSZ", 0)) // 1000
        res = int(p.get("RSS", 0)) // 1000
        shr = res // 4
        minutos = float(p.get("TIME", 0.0))
        tiempo = f"{int(minutos)}:{int(round((minutos % 1) * 60)):02d}.{0:02d}"
        orden = str(p.get("COMMAND", ""))
        # top ensena el nombre del ejecutable, no la linea de ordenes entera.
        corto = orden.strip("[]").split()[0].split("/")[-1] if orden.strip() else "?"
        return (
            f"{p.get('PID', 0):7d} {str(p.get('USER', 'root')):<9.9s}"
            f" 20   0 {virt:7d} {res:6d} {shr:6d} "
            f"{str(p.get('STAT', 'S'))[:1]} "
            f"{float(p.get('CPU', 0.0)):5.1f} {float(p.get('MEM', 0.0)):5.1f} "
            f"{tiempo:>9s} {corto}"
        )

    def _pintar(self) -> None:
        term = self.protocol.terminal
        cabecera = self._cabecera()
        hueco = max(1, self._alto() - len(cabecera) - 1)

        term.eraseDisplay()
        term.cursorHome()
        for linea in cabecera:
            self.write(linea[: self._ancho()] + "\n")
        columnas = (
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM"
            "     TIME+ COMMAND"
        )
        self.write(INVERSO + columnas.ljust(self._ancho())[: self._ancho()] + NORMAL + "\n")
        for p in self.procesos[:hueco]:
            self.write(self._fila(p)[: self._ancho()] + "\n")

        self.pendiente = reactor.callLater(INTERVALO, self._pintar)

    def exit(self, code=None) -> None:
        self._soltar_teclas()
        if self.pendiente is not None and self.pendiente.active():
            self.pendiente.cancel()
        self.pendiente = None
        HoneyPotCommand.exit(self, code)


commands["top"] = Command_top
commands["/usr/bin/top"] = Command_top
commands["/bin/top"] = Command_top
