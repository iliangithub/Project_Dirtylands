# SPDX-License-Identifier: BSD-3-Clause
"""
La ayuda de los comandos: "ls --help" y los otros cuarenta y cinco.

QUE PASABA. Se ejecutaron los 47 modulos con "--help" y de 111 nombres de
comando solo una decena contestaba algo parecido a una ayuda. La mayoria
IGNORABA la opcion y hacia su trabajo:

    $ ls --help
    repo-ignis-prv-main.zip  moi paroli.kdbx

    $ df --help         -> la tabla de sistemas de ficheros
    $ lscpu --help      -> el procesador
    $ systemctl --help  -> las unidades
    $ nproc --help      -> 12
    $ pwd --help        -> /root

Y otro punado daba un error que no es el suyo: "head --help" contestaba
"head: invalid option -- 'help'" cuando el de verdad saca la ayuda entera.

Un comando que trabaja como si nada cuando le piden ayuda no se parece a
ningun Linux, y "ls --help" lo teclea cualquiera.

DONDE SE ENGANCHA, y por que ahi. En runCommand de shell/honeypot.py, JUSTO
ANTES de instanciar el comando: si la orden trae "--help" y hay ayuda para
ella, se lanza en su lugar una clase sintetica que solo escribe el texto.
Se hace en un unico sitio a proposito ---en vez de una linea en cada uno de
los cuarenta y seis modulos--- porque asi no puede olvidarse ninguno; y se
hace ANTES de instanciar, y no dentro del comando, para que la ayuda pase por
la tuberia como cualquier otra salida: "ls --help | head -3" funciona.

LOS TEXTOS NO ESTAN AQUI. Viven en ayudas-comandos.json, que se monta igual
que el ps_command_output.json y el dpkg-packages.tsv: son datos medidos de
unos binarios, no codigo, y mezclarlos con el codigo hace ilegibles los dos.
El fichero lleva dentro con que version se midio cada cosa.

QUIEN NO ESTA, y por que:
  - nano, porque el senuelo declara GNU nano 8.4 y solo habia una 7.2 para
    medir. Una ayuda equivocada de una version que ANUNCIAMOS es peor que no
    tenerla: se puede contrastar.
  - ping y sudo, porque su "--help" no saca una ayuda ---ping contesta
    "invalid option -- '-'"--- y eso lo resuelve cada uno en su modulo.
  - Los builtins de bash. "echo --help" escribe "--help", no una ayuda, y
    para eso basta con no aparecer en el fichero.
"""

from __future__ import annotations

import json
import os

from cowrie.shell.command import HoneyPotCommand

# No exporta ningun comando: esto no es un comando, es el enganche.
commands: dict = {}

RUTA_AYUDAS = os.environ.get("DIRTYLAND_AYUDAS", "/opt/ayudas-comandos.json")

_cache: dict | None = None


def ayudas() -> dict:
    """El fichero, leido una vez. Si no esta, no se rompe nada: los comandos
    siguen comportandose como antes."""
    global _cache
    if _cache is None:
        try:
            with open(RUTA_AYUDAS, encoding="utf-8") as fh:
                _cache = json.load(fh)
        except Exception:                                  # noqa: BLE001
            _cache = {}
    return _cache


def _clase(texto: str, flujo: str, codigo: int):
    class Command_ayuda(HoneyPotCommand):
        def call(self) -> None:
            if flujo == "err":
                self.errorWrite(texto)
            else:
                self.write(texto)
            self.exit_code = codigo

    return Command_ayuda


def interceptar(nombre: str, args, clase):
    """La clase a ejecutar: la de la ayuda, o la de siempre.

    Solo se interpone si la orden trae "--help" TAL CUAL. Un "-h" no vale:
    en la mitad de estos comandos significa otra cosa ---"df -h" son unidades
    legibles, "ls -h" tambien--- y confundirlos seria cambiar un fallo por
    otro peor.
    """
    if not args or "--help" not in args:
        return clase
    entrada = ayudas().get(os.path.basename(nombre))
    if not isinstance(entrada, dict) or "texto" not in entrada:
        return clase
    return _clase(entrada["texto"], entrada.get("flujo", "out"),
                  int(entrada.get("codigo", 0)))
