# SPDX-License-Identifier: BSD-3-Clause
#
# ln. NO EXISTIA, y el sistema de ficheros del senuelo declara /usr/bin/ln:
# "ls -l" lo ensena, "which" lo encuentra, "dpkg -l" declara coreutils, y
# teclearlo contestaba
#
#     -bash: /usr/bin/ln: No such file or directory
#
# que es la contradiccion peor de todas ---un "command not found" seria
# normal; esto significa que la maquina miente---. Y "ln -s" se teclea: es
# como se deja un binario colgado de una ruta del PATH sin moverlo de sitio.
#
# Los enlaces se crean DE VERDAD en el sistema de ficheros emulado, asi que
# un "readlink" o un "ls -l" posteriores dicen lo que tienen que decir. Todo
# medido contra coreutils 9.7 en un Debian 13.
from __future__ import annotations

import stat as _stat

from cowrie.shell import fs
from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_ln(FallaAlAvisar, HoneyPotCommand):
    def call(self) -> None:
        simbolico = False
        forzar = False
        destinos = []
        for a in self.args:
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                simbolico = simbolico or "s" in a[1:]
                forzar = forzar or "f" in a[1:]
            elif a in ("--symbolic",):
                simbolico = True
            elif a in ("--force",):
                forzar = True
            elif not a.startswith("-"):
                destinos.append(a)

        if len(destinos) < 1:
            self.errorWrite("ln: missing file operand\n"
                            "Try 'ln --help' for more information.\n")
            self.exit_code = 1
            return
        if len(destinos) < 2:
            self.errorWrite("ln: missing destination file operand after "
                            "'%s'\nTry 'ln --help' for more information.\n"
                            % destinos[0])
            self.exit_code = 1
            return

        origen, nombre = destinos[0], destinos[1]
        ruta_dst = self.fs.resolve_path(nombre, self.protocol.cwd)

        # Un enlace simbolico se puede crear apuntando a algo que NO existe;
        # uno duro no. Es la diferencia que se nota al teclearlos.
        if not simbolico:
            ruta_src = self.fs.resolve_path(origen, self.protocol.cwd)
            if not self.fs.exists(ruta_src):
                self.errorWrite("ln: failed to access '%s': No such file or "
                                "directory\n" % origen)
                self.exit_code = 1
                return

        if self.fs.exists(ruta_dst):
            if not forzar:
                self.errorWrite(
                    "ln: failed to create %s link '%s': File exists\n"
                    % ("symbolic" if simbolico else "hard", nombre))
                self.exit_code = 1
                return
            try:
                self.fs.remove(ruta_dst)
            except Exception:                                  # noqa: BLE001
                pass

        try:
            if simbolico:
                # Un enlace se lista con permisos 777: no son los del destino.
                self.fs.mkfile(ruta_dst, self.protocol.user.uid,
                               self.protocol.user.gid, len(origen),
                               _stat.S_IFLNK | 0o777)
                nodo = self.fs.getfile(ruta_dst)
                nodo[fs.A_TYPE] = fs.T_LINK
                nodo[fs.A_TARGET] = origen
            else:
                # El duro es OTRO NOMBRE del mismo contenido, asi que se copia
                # el nodo entero: sin el fichero real detras, un "cat" del
                # enlace saldria vacio y el de al lado no.
                origen_nodo = self.fs.getfile(
                    self.fs.resolve_path(origen, self.protocol.cwd))
                self.fs.mkfile(ruta_dst, origen_nodo[fs.A_UID],
                               origen_nodo[fs.A_GID],
                               origen_nodo[fs.A_SIZE],
                               origen_nodo[fs.A_MODE])
                self.fs.update_realfile(self.fs.getfile(ruta_dst),
                                        origen_nodo[fs.A_REALFILE])
        except fs.FileNotFound:
            self.errorWrite("ln: failed to create %s link '%s': No such file "
                            "or directory\n"
                            % ("symbolic" if simbolico else "hard", nombre))
            self.exit_code = 1
        except Exception:                                      # noqa: BLE001
            self.errorWrite("ln: failed to create %s link '%s': Permission "
                            "denied\n"
                            % ("symbolic" if simbolico else "hard", nombre))
            self.exit_code = 1


commands["ln"] = Command_ln
commands["/usr/bin/ln"] = Command_ln
commands["/bin/ln"] = Command_ln
