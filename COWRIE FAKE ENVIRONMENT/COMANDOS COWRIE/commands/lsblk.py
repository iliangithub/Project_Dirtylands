# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

# EL ARBOL VA EN ASCII ("|-" y "`-"), no en Unicode. lsblk lo elige por el
# LOCALE y la sesion del senuelo corre en POSIX: no exporta LANG. Medido en un
# trixie 13.6. Ver la nota de pstree.py.
commands = {}

# El disco lo decide /proc/modules, no el gusto de nadie. La leyenda carga
# "nvme" y "nvme_core" y NO carga "ahci" ni "libata", asi que un /dev/sda seria
# imposible: sin driver SATA no hay disco SATA. Por el mismo motivo desaparece
# el "sr0" de antes, que exigiria "sr_mod" y "cdrom".
#
# El reparto tiene que cuadrar con tres sitios mas:
#   - /proc/meminfo dice SwapTotal 2097148 kB, que es exactamente una particion
#     de 2 GiB menos la cabecera de 4 kB. De ahi el tamano de nvme0n1p3.
#   - "df" y "mount" (sus modulos) y /etc/fstab (el honeyfs).
#   - el "dmesg" enlatado, que anuncia "nvme0n1: p1 p2 p3" y monta la raiz en
#     el dispositivo 259:2, el mismo MAJ:MIN que sale aqui.
# 512M + 463.3G + 2G = 465.8G, el tamano de un SSD de 500 GB.
OUTPUT = """NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
nvme0n1     259:0    0 465.8G  0 disk
|-nvme0n1p1 259:1    0   512M  0 part /boot/efi
|-nvme0n1p2 259:2    0 463.3G  0 part /
`-nvme0n1p3 259:3    0     2G  0 part [SWAP]
"""


class Command_lsblk(HoneyPotCommand):
    def call(self) -> None:
        self.write(OUTPUT)


commands["lsblk"] = Command_lsblk
commands["/usr/bin/lsblk"] = Command_lsblk
commands["/bin/lsblk"] = Command_lsblk
