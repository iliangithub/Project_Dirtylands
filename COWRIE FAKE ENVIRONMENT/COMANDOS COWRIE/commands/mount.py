# SPDX-License-Identifier: BSD-3-Clause
"""
mount para el senuelo.

Mismo motivo que df.py: el enlatado de Cowrie vive en txtcmds/bin/mount y en un
Debian con /usr fusionado no se dispara nunca, asi que "mount" contestaba
"cannot execute binary file: Exec format error". Ademas el enlatado describia un
Debian Lenny (/dev/sda1 ext3, /lib/init/rw), que no se parece en nada a la
leyenda.

La tabla NO esta aqui: se lee de /opt/honeyfs/proc/mounts, que es el mismo
fichero que sirve "cat /proc/mounts" y "cat /etc/mtab". Asi las tres salidas no
pueden contradecirse, que es justo el error que se comete al mantenerlas por
separado. La ruta /opt/honeyfs es la que monta el docker-compose y la misma que
usa el free.py de Cowrie.
"""

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

MOUNTS = "/opt/honeyfs/proc/mounts"

# Solo por si el honeyfs no estuviera montado: mas vale una tabla corta pero
# coherente que un "mount" que no imprime nada, que no lo hace ningun Linux.
RESPALDO = (
    "/dev/nvme0n1p2 / ext4 rw,relatime,errors=remount-ro 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
)


def _tabla() -> str:
    """La tabla de montajes, de /opt/honeyfs/proc/mounts.

    La leen mount y umount por la misma funcion a proposito: si cada uno la
    leyera por su cuenta acabarian discrepando, y un `mount` que ensena / y un
    `umount /` que dice "not mounted" es exactamente el tipo de contradiccion
    que este fichero existe para evitar.
    """
    try:
        with open(MOUNTS, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return RESPALDO


class Command_mount(HoneyPotCommand):
    def call(self) -> None:
        # Con argumentos, mount intenta montar algo. Dentro de un contenedor sin
        # privilegios eso falla, y falla con este mensaje.
        opciones = [a for a in self.args if not a.startswith("-")]
        if opciones:
            self.errorWrite(
                f"mount: {opciones[-1]}: must be superuser to use mount.\n"
            )
            return

        crudo = _tabla()

        salida = []
        for linea in crudo.splitlines():
            campos = linea.split()
            if len(campos) < 4:
                continue
            origen, destino, tipo, opts = campos[0], campos[1], campos[2], campos[3]
            salida.append(f"{origen} on {destino} type {tipo} ({opts})")
        self.write("\n".join(salida) + "\n")


commands["mount"] = Command_mount
commands["/usr/bin/mount"] = Command_mount
commands["/bin/mount"] = Command_mount


class Command_umount(HoneyPotCommand):
    """umount, que faltaba estando mount.

    La asimetria se ve sin buscarla: se podia montar y no desmontar, y
    `umount` contestaba que /usr/bin/umount no existe justo despues de que
    `ls -la /usr/bin/umount` lo ensenara. Un atacante que mire ese par ya sabe
    lo que tiene delante.

    NO desmonta nada: el senuelo no tiene nada que desmontar. Contesta lo que
    contesta umount(8) en los dos casos que se dan de verdad ---sin argumentos
    y con un punto que no esta montado--- y para lo que si esta en la tabla
    responde el "target is busy" de un / o un /proc, que es lo que sale al
    intentar desmontarlos de verdad como root.
    """

    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        if not args:
            # Sin punto de montaje, umount pide uno. El texto es el de
            # util-linux, que es de donde sale el binario en Debian.
            self.errorWrite("umount: bad usage\n")
            self.errorWrite("Try 'umount --help' for more information.\n")
            self.exit_code = 1
            return

        montados = set()
        for linea in _tabla().splitlines():
            campos = linea.split()
            if len(campos) >= 2:
                montados.add(campos[1])

        for destino in args:
            ruta = self.fs.resolve_path(destino, self.protocol.cwd)
            if ruta in montados or destino in montados:
                # Lo que dice un umount de verdad al intentar desmontar algo
                # en uso, que es lo que pasa con / y con /proc.
                self.errorWrite(f"umount: {destino}: target is busy.\n")
                self.exit_code = 32
            else:
                self.errorWrite(f"umount: {destino}: not mounted.\n")
                self.exit_code = 32


commands["umount"] = Command_umount
commands["/usr/bin/umount"] = Command_umount
commands["/bin/umount"] = Command_umount
