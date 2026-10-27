# SPDX-License-Identifier: BSD-3-Clause
"""
nohup.

El de Cowrie tiene tres fallos que se ven en la ultima orden de casi cualquier
dropper, que es justo la que decide si el atacante cree que su binario ha
arrancado:

  1. Si "nohup.out" YA EXISTE no escribe absolutamente nada. Silencio. El nohup
     de verdad anuncia el fichero SIEMPRE, exista o no.
  2. Crea el fichero con modo 0644, y el de verdad lo crea 0600. Se ve con un
     "ls -la" a continuacion.
  3. No mira si la orden que le pasan existe. Un dropper al que le haya fallado
     la descarga recibia el mensaje de exito igual.

Los textos estan MEDIDOS contra coreutils en Debian 13, con un pseudo-terminal,
porque el mensaje cambia segun donde vaya la salida:

    nohup ./x        -> nohup: ignoring input and appending output to 'nohup.out'
    nohup ./x &      -> nohup: appending output to 'nohup.out'

La diferencia es la entrada: cuando la orden va al fondo, su entrada ya no es
el terminal y nohup no tiene nada que ignorar. El "&" llega en los argumentos,
asi que se puede distinguir.

Y si la orden no existe, ademas:

    nohup: failed to run command './x': No such file or directory

y entonces NO se crea nohup.out.
"""

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_nohup(HoneyPotCommand):
    def call(self) -> None:
        if not self.args:
            self.write("nohup: missing operand\n")
            self.write("Try 'nohup --help' for more information.\n")
            return

        args = [a for a in self.args if a != "&"]
        al_fondo = "&" in self.args
        if not args:
            self.write("nohup: missing operand\n")
            return

        # El mensaje va SIEMPRE, y antes que nada, como hace el de verdad.
        if al_fondo:
            self.write("nohup: appending output to 'nohup.out'\n")
        else:
            self.write("nohup: ignoring input and appending output to "
                       "'nohup.out'\n")

        orden = args[0]
        if orden.startswith((".", "/")):
            existe = self.fs.exists(
                self.fs.resolve_path(orden, self.protocol.cwd))
        else:
            # Sin barra, nohup la busca en el PATH.
            existe = any(
                self.fs.exists("%s/%s" % (d, orden))
                for d in (self.environ.get("PATH", "") or "").split(":") if d)

        if not existe:
            self.errorWrite("nohup: failed to run command '%s': "
                            "No such file or directory\n" % orden)
            # 127, como cualquier orden que no se encuentra: medido.
            self.exit_code = 127
            return

        # Y AHORA LA OTRA MITAD, que faltaba entera: EJECUTAR la orden y
        # dejar su salida en nohup.out. Se anunciaba el fichero, se creaba
        # vacio... y la orden no llegaba a correr nunca. O sea que la ultima
        # linea de casi cualquier dropper ---"nohup ./x &"--- no hacia nada, y
        # el atacante se iba creyendo que su binario estaba en marcha.
        #
        # La salida NO va a la pantalla: va al fichero, que es justo lo que
        # nohup promete y lo que el atacante comprueba despues con un "cat
        # nohup.out".
        shell = (self.protocol.cmdstack[-2]
                 if len(self.protocol.cmdstack) >= 2 else None)
        salida = ""
        if shell is not None:
            try:
                salida = shell._execute_subshell_with_full_output(
                    " ".join(args))
                self.exit_code = getattr(shell, "_estado_subshell", 0)
            except Exception:                                  # noqa: BLE001
                salida = ""

        ruta = self.fs.resolve_path("nohup.out", self.protocol.cwd)
        anterior = b""
        if self.fs.exists(ruta):
            try:
                anterior = self.fs.file_contents(ruta) or b""
            except Exception:                                  # noqa: BLE001
                anterior = b""
        # 0600, que es como lo crea el de verdad, y ANEXANDO: dos nohup
        # seguidos dejan las dos salidas, no la ultima.
        from cowrie.commands.base import escribe_fichero

        escribe_fichero(self, ruta, anterior + salida.encode(),
                        modo=0o100600, uid=self.current_user["uid"],
                        gid=self.current_user["gid"])


commands["/usr/bin/nohup"] = Command_nohup
commands["nohup"] = Command_nohup
