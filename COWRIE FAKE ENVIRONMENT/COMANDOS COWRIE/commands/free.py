# SPDX-FileCopyrightText: 2015-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
This module ...
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand

commands = {}

# El formato es el de procps-ng 4.x, que es el que trae Debian 13. Las anchuras
# no son decorativas: la primera columna ocupa 7 y la de "total" 13, y a partir
# de ahi todas 12. Asi la cabecera cae exactamente donde la pone un free real.
FREE_OUTPUT = (
    f"{'':<7}{'total':>13}{'used':>12}{'free':>12}"
    f"{'shared':>12}{'buff/cache':>12}{'available':>12}\n"
    "{Mem}\n{Swap}\n"
)


def humano(kb: int) -> str:
    """Formatea como "free -h" de procps-ng: unidades BINARIAS con sufijo "i".

    Cowrie dividia entre 1000 y escribia "16G". Un Debian 13 escribe "16Gi", y
    con un decimal cuando el numero baja de 10 ("2.0Gi", "4.2Gi"). El sufijo sin
    la "i" es de una version de free anterior a la que dice tener la maquina.
    """
    if kb == 0:
        return "0B"
    valor = float(kb)
    unidad = "Ki"
    for siguiente in ("Mi", "Gi", "Ti"):
        if valor < 1024:
            break
        valor /= 1024.0
        unidad = siguiente
    if valor < 10:
        return f"{valor:.1f}{unidad}"
    return f"{round(valor)}{unidad}"


class Command_free(HoneyPotCommand):
    """
    free
    """

    def call(self) -> None:
        # Parse options or display no files
        try:
            opts, _args = getopt.getopt(self.args, "mh")
        except getopt.GetoptError:
            self.do_free()
            return

        # Parse options
        for o, _a in opts:
            if o in ("-h"):
                self.do_free(fmt="human")
                return
            elif o in ("-m"):
                self.do_free(fmt="megabytes")
                return
        self.do_free()

    def do_free(self, fmt: str = "kilobytes") -> None:
        """
        print free statistics
        """

        # Get real host memstats and add the calculated fields
        raw_mem_stats = self.get_free_stats()

        if raw_mem_stats == {}:
            return

        raw_mem_stats["calc_total_buffers_and_cache"] = (
            raw_mem_stats["Buffers"] + raw_mem_stats["Cached"]
        )
        raw_mem_stats["calc_total_used"] = raw_mem_stats["MemTotal"] - (
            raw_mem_stats["MemFree"] + raw_mem_stats["calc_total_buffers_and_cache"]
        )
        raw_mem_stats["calc_swap_used"] = (
            raw_mem_stats["SwapTotal"] - raw_mem_stats["SwapFree"]
        )

        if fmt == "megabytes":
            # "free -m" cuenta en mebibytes (1024), no en millones.
            for key, value in raw_mem_stats.items():
                raw_mem_stats[key] = int(value / 1024)

        if fmt == "human":
            def celda(v):
                return humano(v)
        else:
            def celda(v):
                return str(v)

        fila_mem = (
            f"{'Mem:':<7}"
            f"{celda(raw_mem_stats['MemTotal']):>13}"
            f"{celda(raw_mem_stats['calc_total_used']):>12}"
            f"{celda(raw_mem_stats['MemFree']):>12}"
            f"{celda(raw_mem_stats['Shmem']):>12}"
            f"{celda(raw_mem_stats['calc_total_buffers_and_cache']):>12}"
            f"{celda(raw_mem_stats['MemAvailable']):>12}"
        )
        fila_swap = (
            f"{'Swap:':<7}"
            f"{celda(raw_mem_stats['SwapTotal']):>13}"
            f"{celda(raw_mem_stats['calc_swap_used']):>12}"
            f"{celda(raw_mem_stats['SwapFree']):>12}"
        )
        self.write(FREE_OUTPUT.format(Mem=fila_mem, Swap=fila_swap))

    def get_free_stats(self) -> dict[str, int]:
        """
        Get the free stats from /proc
        """
        needed_keys = [
            "Buffers",
            "Cached",
            "MemTotal",
            "MemFree",
            "SwapTotal",
            "SwapFree",
            "Shmem",
            "MemAvailable",
        ]
        mem_info_map: dict[str, int] = {}
        try:
            with open("/opt/honeyfs/proc/meminfo") as proc_file:
                for line in proc_file:
                    tokens = line.split(":")

                    # Later we are going to do some math on those numbers, better not include uneeded keys for performance
                    if tokens[0] in needed_keys:
                        mem_info_map[tokens[0]] = int(tokens[1].lstrip().split(" ")[0])
        except Exception:
            pass

        # Got a map with all tokens from /proc/meminfo and sizes in KBs
        return mem_info_map


commands["/usr/bin/free"] = Command_free
commands["free"] = Command_free
