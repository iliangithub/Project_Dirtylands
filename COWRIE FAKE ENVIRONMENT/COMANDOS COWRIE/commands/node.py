# SPDX-License-Identifier: BSD-3-Clause
"""
node --- el interprete de Node.js, emulado hasta donde llega la mentira.

POR QUE EXISTE. Es el mismo caso que psql y viene de la misma captura. El
senuelo se llama "pc-dev-003-ignis" y su cebo es una API en Node: hay un
"/home/admin/ignis api/" con su .env, su package.json y sus config/*.json. El
PACKAGES del generador instala "nodejs npm", asi que la maquina lo declara:

    $ which node            -> /usr/bin/node
    $ file /usr/bin/node    -> ELF 64-bit LSB pie executable, x86-64
    $ dpkg -l | grep nodejs -> ii  nodejs  20.19.2+dfsg-1 ...
    $ node --version        -> -bash: /usr/bin/node: No such file or directory

El atacante de la captura lo uso seis veces, y la mas interesante fue esta:

    node -e "try{require('pg')}catch(e){console.log('NO-PG')}"

O sea: despues de leer el .env, probar si la maquina trae el cliente de
PostgreSQL de Node para usar las credenciales. Es la misma pregunta que le hizo
a psql y a python3, por tercera via.

QUE CONTESTA. Lo que contestaria un node de verdad en esta maquina:

  - La version, sacada del "dpkg -l" para que no puedan contradecirse.
  - Un `require` de algo que no es de fabrica ---pg, mysql, redis, axios---
    falla con "Cannot find module", que es LA VERDAD en esta maquina: el
    node_modules de la API esta en "/home/admin/ignis api/", no en el camino de
    busqueda de un `node -e` lanzado desde otro sitio.
  - Un fichero que no existe, igual.

QUE NO HACE: ejecutar JavaScript. Un `node -e "console.log(1+1)"` no contesta
"2". Es el limite conocido de esta emulacion y esta escrito aqui para que
quien lo lea no crea otra cosa; lo mismo pasa con el python3 de al lado, que
tampoco evalua. La diferencia con no tener el comando es grande: sin el, la
maquina se contradecia en la orden siguiente a que el tio picara con el cebo.
"""
from __future__ import annotations

import re

from twisted.python import log

from cowrie.commands.dpkg import datos_de, leer_paquetes
from cowrie.shell.command import HoneyPotCommand

commands = {}

VERSION_POR_DEFECTO = "20.19.2+dfsg-1"

# Los modulos que trae Node dentro. Un `require` de estos SI funciona en una
# maquina pelada, asi que no puede contestar "Cannot find module": la lista es
# la de los builtin de Node 20, recortada a los que aparecen en guiones de
# ataque ---sockets, procesos, ficheros, cifrado---.
DE_FABRICA = {
    "assert", "buffer", "child_process", "cluster", "console", "crypto",
    "dgram", "dns", "events", "fs", "http", "http2", "https", "net", "os",
    "path", "process", "punycode", "querystring", "readline", "stream",
    "string_decoder", "timers", "tls", "tty", "url", "util", "v8", "vm",
    "worker_threads", "zlib",
}

_REQUIRE = re.compile(r"""require\(\s*["']([^"']+)["']\s*\)""")


def version_declarada() -> str:
    filas = leer_paquetes()
    version, _arch = datos_de(filas, "nodejs", (None, None))
    return version or VERSION_POR_DEFECTO


def version_corta(version_debian: str) -> str:
    """"20.19.2+dfsg-1" -> "20.19.2". El numero de Node, sin lo de Debian."""
    return version_debian.split("+")[0].split("-")[0]


def modulo_que_falta(guion: str) -> str | None:
    """El primer require() de algo que no viene de fabrica, o None."""
    for nombre in _REQUIRE.findall(guion):
        base = nombre.split("/")[0]
        if base.startswith("node:"):
            base = base[5:]
        if base in DE_FABRICA:
            continue
        if nombre.startswith(("./", "../", "/")):
            return nombre
        return nombre
    return None


class Command_node(HoneyPotCommand):
    interactive: bool = False

    def no_encuentra(self, que: str, desde: str) -> None:
        """El error de Node cuando un require no da con el modulo.

        Se copia la forma del de verdad, que es la que mira quien sabe: el
        "code: 'MODULE_NOT_FOUND'" del final y el requireStack, que es la lista
        de quien pidio que.
        """
        self.errorWrite("node:internal/modules/cjs/loader:1215\n")
        self.errorWrite("  throw err;\n")
        self.errorWrite("  ^\n\n")
        self.errorWrite("Error: Cannot find module '%s'\n" % que)
        self.errorWrite("Require stack:\n- %s\n" % desde)
        self.errorWrite(
            "    at Module._resolveFilename (node:internal/modules/cjs/"
            "loader:1212:15)\n")
        self.errorWrite(
            "    at Module._load (node:internal/modules/cjs/loader:1043:27)\n")
        self.errorWrite(
            "    at Module.require (node:internal/modules/cjs/loader:1298:19)\n")
        self.errorWrite("    at require (node:internal/modules/helpers:182:18)\n")
        self.errorWrite("    at [eval]:1:1\n")
        self.errorWrite("    at runScriptInThisContext (node:internal/vm:209:10)\n")
        self.errorWrite("  code: 'MODULE_NOT_FOUND',\n")
        self.errorWrite("  requireStack: [ '%s' ]\n" % desde)
        self.errorWrite("}\n\n")
        self.errorWrite("Node.js v%s\n" % version_corta(version_declarada()))
        self.exit_code = 1

    def call(self) -> None:
        args = list(self.args)

        if "-v" in args or "--version" in args:
            self.write("v%s\n" % version_corta(version_declarada()))
            return
        if "-h" in args or "--help" in args:
            self.write("Usage: node [options] [ script.js ] [arguments]\n")
            self.write("       node inspect [options] [ script.js | host:port ]"
                       " [arguments]\n\n")
            self.write("Options:\n")
            self.write("  -                                             "
                       "script read from stdin\n")
            self.write("  --                                            "
                       "indicate the end of node options\n")
            self.write("  -e, --eval=...                                "
                       "evaluate script\n")
            self.write("  -p, --print [arg]                             "
                       "evaluate script and print result\n")
            self.write("  -v, --version                                 "
                       "print Node.js version\n")
            return

        # -e / -p / --eval: el guion viene en la linea de ordenes.
        guion = None
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-e", "--eval", "-p", "--print") and i + 1 < len(args):
                guion = args[i + 1]
                break
            if a.startswith("--eval="):
                guion = a.split("=", 1)[1]
                break
            i += 1

        if guion is not None:
            log.msg(eventid="cowrie.command.input", realm="node", input=guion,
                    format="INPUT (%(realm)s): %(input)s")
            falta = modulo_que_falta(guion)
            if falta:
                self.no_encuentra(falta, "[eval]")
            # Sin require que falle, no se escribe nada: aqui no se evalua
            # JavaScript. Ver la cabecera.
            return

        # Un fichero. Node dice "Cannot find module" con la RUTA ENTERA, no
        # "no such file": es su forma de quejarse y es la que mira quien sabe.
        sueltos = [a for a in args if not a.startswith("-")]
        if sueltos:
            ruta = sueltos[0]
            if not ruta.startswith("/"):
                ruta = (self.protocol.cwd.rstrip("/") + "/" + ruta)
            if not self.fs.exists(ruta):
                self.no_encuentra(ruta, ".")
            return

        # Sin nada: la consola interactiva, igual que el python3 de al lado.
        self.interactive = True
        self.write("Welcome to Node.js v%s.\n"
                   % version_corta(version_declarada()))
        self.write('Type ".help" for more information.\n')
        self.write("> ")

    def lineReceived(self, line: str) -> None:
        log.msg(eventid="cowrie.command.input", realm="node", input=line,
                format="INPUT (%(realm)s): %(input)s")
        if not self.interactive:
            return
        if line.strip() in (".exit", "process.exit()"):
            self.exit()
            return
        # Aqui no se evalua nada: se saca otro prompt, como hace el python3.
        self.write("> ")

    def handle_CTRL_D(self) -> None:
        self.write("\n")
        self.exit()

    def eofReceived(self) -> None:
        self.exit()


commands["node"] = Command_node
commands["/usr/bin/node"] = Command_node
# Debian instala el binario como "nodejs" y deja "node" apuntando a el.
commands["nodejs"] = Command_node
commands["/usr/bin/nodejs"] = Command_node
