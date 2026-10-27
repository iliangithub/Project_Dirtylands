# SPDX-License-Identifier: BSD-3-Clause
"""
df para el senuelo.

Cowrie trae un "df" enlatado, pero vive en share/cowrie/txtcmds/bin/df y en un
Debian moderno NO se dispara nunca: /bin es un enlace a /usr/bin, el PATH mira
/usr/bin antes que /bin, y la ruta que Cowrie resuelve es /usr/bin/df. Al no
encontrar enlatado en esa ruta, el shell caia al ultimo recurso y contestaba
"cannot execute binary file: Exec format error", que es lo que veia el atacante
al escribir "df -h". De ahi que esto sea un modulo: gana siempre, y ademas un
fichero enlatado no puede distinguir "df" de "df -h", que dan salidas distintas.

Los numeros no son libres. Salen de lo que ya afirman otras piezas:
  - lsblk.py         -> nvme0n1 con p1 (512M, /boot/efi), p2 (463.3G, /) y p3 (2G, swap)
  - /proc/meminfo    -> MemTotal 16777216 kB
  - el dmesg enlatado -> "Memory: 16305312K/16777216K available"
Y de ahi los tmpfs: /dev es la mitad de la memoria DISPONIBLE (8152656 = 16305312/2),
/run el 10% de la total y /dev/shm el 50% de la total. Son las cuentas que hacen
el kernel y systemd de verdad, asi que cuadran solas.
"""

from __future__ import annotations

import math

from cowrie.shell.command import HoneyPotCommand

commands = {}

# (dispositivo, tipo, bloques de 1K, usados, inodos, inodos usados, punto de montaje)
TABLA = [
    ("udev", "devtmpfs", 8152656, 0, 2038164, 470, "/dev"),
    ("tmpfs", "tmpfs", 1677720, 1728, 2097152, 923, "/run"),
    ("/dev/nvme0n1p2", "ext4", 477821436, 71303168, 30375936, 412863, "/"),
    ("tmpfs", "tmpfs", 8388608, 0, 2097152, 1, "/dev/shm"),
    ("tmpfs", "tmpfs", 5120, 0, 2097152, 3, "/run/lock"),
    ("/dev/nvme0n1p1", "vfat", 523244, 6232, 0, 0, "/boot/efi"),
]

# ext4 reserva un 5% para root: no cuenta como usado ni como disponible.
RESERVA_EXT4 = 0.05


def humano(kb: int) -> str:
    """Formatea como 'df -h': tres cifras y redondeo hacia ARRIBA, como coreutils."""
    if kb == 0:
        return "0"
    valor = float(kb)
    unidad = "K"
    for siguiente in ("M", "G", "T"):
        if valor < 1024:
            break
        valor /= 1024.0
        unidad = siguiente
    if valor < 10:
        return f"{math.ceil(valor * 10) / 10:.1f}{unidad}"
    return f"{math.ceil(valor)}{unidad}"


class Command_df(HoneyPotCommand):
    def call(self) -> None:
        formato = "k"
        con_tipo = False
        inodos = False
        rutas = []

        for arg in self.args:
            if arg.startswith("-") and len(arg) > 1 and not arg.startswith("--"):
                for letra in arg[1:]:
                    if letra in ("h", "H"):
                        formato = "h"
                    elif letra == "k":
                        formato = "k"
                    elif letra == "m":
                        formato = "m"
                    elif letra == "T":
                        con_tipo = True
                    elif letra == "i":
                        inodos = True
            elif arg in ("--human-readable", "--si"):
                formato = "h"
            elif arg == "--print-type":
                con_tipo = True
            elif arg == "--inodes":
                inodos = True
            elif not arg.startswith("-"):
                rutas.append(arg)

        filas = TABLA
        if rutas:
            filas = [f for f in TABLA if self._monta(f[6], rutas)]
            if not filas:
                for r in rutas:
                    self.errorWrite(
                        f"df: {r}: No such file or directory\n"
                    )
                return

        self.write(self._render(filas, formato, con_tipo, inodos))

    def _monta(self, punto: str, rutas: list[str]) -> bool:
        """Un df con rutas ensena el sistema de ficheros que las contiene."""
        for r in rutas:
            ruta = self.fs.resolve_path(r, self.protocol.cwd)
            if ruta == punto or ruta.startswith(punto.rstrip("/") + "/"):
                # Gana el punto de montaje mas profundo, como hace df de verdad.
                mejor = max(
                    (f[6] for f in TABLA if ruta == f[6] or ruta.startswith(f[6].rstrip("/") + "/")),
                    key=len,
                )
                if mejor == punto:
                    return True
        return False

    def _render(self, filas, formato: str, con_tipo: bool, inodos: bool) -> str:
        cabecera = ["Filesystem"]
        if con_tipo:
            cabecera.append("Type")
        if inodos:
            cabecera += ["Inodes", "IUsed", "IFree", "IUse%"]
        elif formato == "h":
            cabecera += ["Size", "Used", "Avail", "Use%"]
        elif formato == "m":
            cabecera += ["1M-blocks", "Used", "Available", "Use%"]
        else:
            cabecera += ["1K-blocks", "Used", "Available", "Use%"]
        cabecera.append("Mounted on")

        cuerpo = []
        for disp, tipo, total, usado, inod, iusado, punto in filas:
            fila = [disp]
            if con_tipo:
                fila.append(tipo)
            if inodos:
                if inod == 0:
                    fila += ["0", "0", "0", "-"]
                else:
                    libres = inod - iusado
                    fila += [
                        str(inod),
                        str(iusado),
                        str(libres),
                        f"{math.ceil(iusado * 100 / inod)}%",
                    ]
            else:
                reserva = int(total * RESERVA_EXT4) if tipo == "ext4" else 0
                libre = total - usado - reserva
                pct = "0%" if usado == 0 else f"{math.ceil(usado * 100 / (usado + libre))}%"
                if formato == "h":
                    fila += [humano(total), humano(usado), humano(libre), pct]
                elif formato == "m":
                    fila += [
                        str(total // 1024),
                        str(usado // 1024),
                        str(libre // 1024),
                        pct,
                    ]
                else:
                    fila += [str(total), str(usado), str(libre), pct]
            fila.append(punto)
            cuerpo.append(fila)

        # df alinea a la izquierda la primera columna y la ultima, y a la
        # derecha las del medio. Los anchos los manda el contenido.
        anchos = [
            max(len(f[i]) for f in [cabecera] + cuerpo) for i in range(len(cabecera))
        ]
        # coreutils reserva 5 para las columnas de tamano en modo humano: si no,
        # "Size" y "Avail" salen pegados y no se parece a un df de verdad.
        if formato == "h" and not inodos:
            base = 2 if con_tipo else 1
            for i in range(base, base + 3):
                anchos[i] = max(anchos[i], 5)
        ultima = len(cabecera) - 1
        salida = []
        for fila in [cabecera] + cuerpo:
            trozos = []
            for i, celda in enumerate(fila):
                if i == 0 or i == ultima:
                    trozos.append(celda.ljust(anchos[i]) if i == 0 else celda)
                else:
                    trozos.append(celda.rjust(anchos[i]))
            salida.append(" ".join(trozos).rstrip())
        return "\n".join(salida) + "\n"


commands["df"] = Command_df
commands["/usr/bin/df"] = Command_df
commands["/bin/df"] = Command_df
