# SPDX-License-Identifier: BSD-3-Clause
#
# service, sacado de las MISMAS fuentes que systemctl y que el sistema de
# ficheros.
#
# EL DE LA IMAGEN DESCRIBIA OTRA MAQUINA. "service --status-all" contestaba
# una lista fija de cuarenta y tantos servicios ---cups, lightdm, bluetooth,
# network-manager, avahi-daemon, apport, plymouth, open-vm-tools--- que es un
# escritorio Ubuntu dentro de una maquina virtual de VMware. Aqui la leyenda
# es un servidor Debian 13, y la contradiccion se ve poniendo las dos ordenes
# seguidas: "systemctl" lista catorce unidades que no incluyen ninguna de
# esas, y "dpkg -l" no declara ni cups ni lightdm.
#
# Y "service ssh status" no escribia NADA.
#
# Ahora la lista sale de /etc/init.d ---el propio sistema de ficheros--- y el
# estado de cada uno de la tabla de systemctl, asi que las tres piezas no
# pueden contarse historias distintas. Medido en un Debian 13: los servicios
# activos llevan "[ + ]" y el resto "[ - ]", con un espacio delante.
from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_service(FallaAlAvisar, HoneyPotCommand):
    def _activos(self) -> set:
        """Los servicios que la tabla de systemctl da por activos."""
        from cowrie.commands.systemctl import UNITS

        activos = set()
        for linea in UNITS.split("\n"):
            trozos = linea.split()
            if len(trozos) > 2 and trozos[0].endswith(".service") \
                    and trozos[2] == "active":
                activos.add(trozos[0][:-len(".service")])
        return activos

    def _guiones(self) -> list:
        """Lo que hay en /etc/init.d, que es lo que service sabe listar."""
        from cowrie.shell import fs as _fs

        try:
            return sorted(h[_fs.A_NAME] for h in self.fs.get_path("/etc/init.d"))
        except Exception:                                      # noqa: BLE001
            return []

    def call(self) -> None:
        if not self.args or self.args[0] in ("--status-all", "-a"):
            if not self.args:
                self.errorWrite(
                    "Usage: service < option > | --status-all |"
                    " [ service_name [ command | --full-restart ] ]\n")
                return
            activos = self._activos()
            for nombre in self._guiones():
                self.write(" [ %s ]  %s\n"
                           % ("+" if nombre in activos else "-", nombre))
            return

        nombre = self.args[0]
        orden = self.args[1] if len(self.args) > 1 else ""
        if nombre not in self._guiones() and nombre not in self._activos():
            self.errorWrite("%s: unrecognized service\n" % nombre)
            return

        if orden == "status":
            # Con systemd, "service X status" es "systemctl status X": lo dice
            # el propio guion de Debian. Se saca del mismo sitio para que no
            # puedan discrepar.
            from cowrie.commands.systemctl import UNIT_STATUS

            if nombre in UNIT_STATUS:
                self.write(UNIT_STATUS[nombre])
            else:
                self.write("* %s.service\n     Loaded: not-found (Reason:"
                           " Unit %s.service not found.)\n     Active:"
                           " inactive (dead)\n" % (nombre, nombre))
                self.exit_code = 3
            return

        if orden in ("start", "stop", "restart", "reload", "force-reload"):
            # El envoltorio avisa de que redirige a systemctl, y luego pide
            # autenticacion como haria systemctl.
            self.write("Redirecting to /bin/systemctl %s %s.service\n"
                       % (orden, nombre))
            if self.protocol.user.username != "root":
                self.errorWrite("Failed to %s %s.service: Interactive"
                                " authentication required.\n"
                                % (orden, nombre))
            return

        self.errorWrite(
            "Usage: /etc/init.d/%s {start|stop|status|restart|"
            "try-restart|reload|force-reload}\n" % nombre)


commands["/usr/sbin/service"] = Command_service
commands["service"] = Command_service
