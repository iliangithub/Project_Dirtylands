# SPDX-License-Identifier: BSD-3-Clause
"""
psql --- el cliente de PostgreSQL, emulado hasta donde llega la mentira.

POR QUE EXISTE. El cebo del senuelo deja un .env en "/home/admin/ignis api/"
con esta linea dentro:

    DATABASE_URL=postgres://ignis_app:Xk7$vProd2025@db-internal.ignislabs.dev:5432/ignis_prod

En una captura de verdad se ve a un atacante encontrarlo, leerlo, y hacer lo
unico que se puede hacer con eso: usarlo. Once veces, de tres formas distintas.
Y hasta ahora se encontraba con esto:

    $ which psql          -> /usr/bin/psql
    $ ls -la /usr/bin/psql-> -rwxr-xr-x 1 root root ...
    $ dpkg -l | grep postg-> ii  postgresql-client-17 ...
    $ psql --version      -> -bash: /usr/bin/psql: No such file or directory

Cuatro ordenes diciendo que esta y la quinta diciendo que no. Esa contradiccion
no la tiene ningun Linux, y ademas llegaba en el peor momento posible: JUSTO
DESPUES de que el tio hubiera picado con el cebo. Todo el trabajo del honeyfs
---el .env, las claves de despliegue, los config/*.json--- se cae en la orden
siguiente.

QUE HACE Y QUE NO. No se conecta a ninguna parte y no ejecuta ni una consulta:
contesta lo que contestaria un psql de verdad cuando al otro lado no hay nadie.
Eso no es poco, porque es exactamente lo que el atacante iba a encontrar de
todas formas ---esa base de datos no existe--- y ademas le deja creyendo que la
maquina es real y que lo que falla es la RED.

DE DONDE SALE LA VERSION. Del mismo sitio que la del "dpkg -l": la tabla que
exporta build-dirtyland-fs.sh del contenedor de construccion. Escribirla aqui
a mano seria poner un numero que hay que acordarse de cambiar, y el dia que no
se cambie el senuelo se contradice solo: "dpkg -l" diria una version y
"psql --version" otra.

POR QUE "Connection refused" Y NO "Connection timed out". Las dos son creibles
---un puerto cerrado contesta lo primero, uno filtrado lo segundo--- pero el
timeout de verdad tarda unos dos minutos, que es lo que tarda el nucleo en
rendirse con los reintentos del SYN. Un "timed out" instantaneo seria la propia
mentira delatandose, y esperar dos minutos de verdad deja la sesion colgada. El
"refused" es instantaneo en un Linux de verdad, asi que aqui tambien.
"""
from __future__ import annotations

from cowrie.commands.dpkg import datos_de, leer_paquetes
from cowrie.commands.ping import es_ip, resuelve_nombre
from cowrie.shell.command import HoneyPotCommand

commands = {}

# Si no hay tabla de paquetes que consultar. No deberia pasar ---el compose la
# monta--- pero un psql que no sabe su propia version llama mas la atencion que
# uno que la dice.
VERSION_POR_DEFECTO = "17.6-0+deb13u1"

# El paquete que trae el binario, por orden de preferencia: Debian 13 instala
# postgresql-client-17 al pedir postgresql-client.
PAQUETES = ("postgresql-client-17", "postgresql-client", "postgresql-client-16")

PUERTO_POR_DEFECTO = 5432
SOCKET = "/var/run/postgresql/.s.PGSQL.%d"

AYUDA = """\
psql is the PostgreSQL interactive terminal.

Usage:
  psql [OPTION]... [DBNAME [USERNAME]]

General options:
  -c, --command=COMMAND    run only single command (SQL or internal) and exit
  -d, --dbname=DBNAME      database name to connect to
  -f, --file=FILENAME      execute commands from file, then exit
  -l, --list               list available databases, then exit
  -v, --set=, --variable=NAME=VALUE
                           set psql variable NAME to VALUE
                           (e.g., -v ON_ERROR_STOP=1)
  -V, --version            output version information, then exit
  -X, --no-psqlrc          do not read startup file (~/.psqlrc)
  -1 ("one"), --single-transaction
                           execute as a single transaction (if non-interactive)
  -?, --help[=options]     show this help, then exit
      --help=commands      list backslash commands, then exit
      --help=variables     list special variables, then exit

Connection options:
  -h, --host=HOSTNAME      database server host or socket directory
                           (default: "/var/run/postgresql")
  -p, --port=PORT          database server port (default: "5432")
  -U, --username=USERNAME  database user name (default: "root")
  -w, --no-password        never prompt for password
  -W, --password           force password prompt (should happen automatically)

For more information, type "\\?" (for internal commands) or "\\help" (for SQL
commands) from within psql, or consult the psql section in the PostgreSQL
documentation.

Report bugs to <pgsql-bugs@lists.postgresql.org>.
PostgreSQL home page: <https://www.postgresql.org/>
"""


def version_declarada() -> str:
    """La version del paquete, tal y como la declara el "dpkg -l"."""
    filas = leer_paquetes()
    for paquete in PAQUETES:
        version, _arch = datos_de(filas, paquete, (None, None))
        if version:
            return version
    return VERSION_POR_DEFECTO


def version_corta(version_debian: str) -> str:
    """"17.6-0+deb13u1" -> "17.6". El numero de PostgreSQL, sin lo de Debian."""
    return version_debian.split("-")[0].split("+")[0]


def parte_url(texto: str):
    """(host, puerto) de una URL de conexion, o None si no lo es.

    Se acepta postgres:// y postgresql://, que son las dos formas que entiende
    libpq. El usuario y la contrasena se ignoran a proposito: aqui no se
    autentica nadie, y lo unico que decide la respuesta es a donde se iba a
    conectar.
    """
    for esquema in ("postgres://", "postgresql://"):
        if not texto.startswith(esquema):
            continue
        resto = texto[len(esquema):]
        resto = resto.split("/", 1)[0].split("?", 1)[0]
        if "@" in resto:
            resto = resto.rsplit("@", 1)[1]
        if not resto:
            return "", PUERTO_POR_DEFECTO
        if resto.startswith("["):                       # IPv6 entre corchetes
            host, _, cola = resto.partition("]")
            host = host[1:]
            puerto = cola.lstrip(":")
        else:
            host, _, puerto = resto.partition(":")
        try:
            return host, int(puerto) if puerto else PUERTO_POR_DEFECTO
        except ValueError:
            return host, PUERTO_POR_DEFECTO
    return None


class Command_psql(HoneyPotCommand):
    def call(self) -> None:
        args = list(self.args)

        if "-V" in args or "--version" in args:
            declarada = version_declarada()
            self.write("psql (PostgreSQL) %s (Debian %s)\n"
                       % (version_corta(declarada), declarada))
            return
        if "-?" in args or "--help" in args or any(
                a.startswith("--help=") for a in args):
            self.write(AYUDA)
            return

        host, puerto = None, PUERTO_POR_DEFECTO
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-h", "--host") and i + 1 < len(args):
                host = args[i + 1]
                i += 1
            elif a.startswith("--host="):
                host = a.split("=", 1)[1]
            elif a == "-p" and i + 1 < len(args):
                puerto = self._puerto(args[i + 1], puerto)
                i += 1
            elif a.startswith("--port="):
                puerto = self._puerto(a.split("=", 1)[1], puerto)
            elif not a.startswith("-"):
                # Un argumento suelto es el nombre de la base... o una URL de
                # conexion entera, que es como la trae el .env del cebo.
                url = parte_url(a)
                if url is not None:
                    host, puerto = url[0] or host, url[1]
            i += 1

        # SIN -h NO HAY RED: un psql de verdad va al socket de unix, y si no
        # hay servidor local el error no habla de puertos ni de nombres.
        if not host:
            self.errorWrite(
                'psql: error: connection to server on socket "%s" failed: '
                "No such file or directory\n" % (SOCKET % puerto))
            self.errorWrite(
                "\tIs the server running locally and accepting connections on "
                "that socket?\n")
            self.exit_code = 2
            return

        # El mismo resolvedor que ping: ver resuelve_nombre(). Dos respuestas
        # distintas al mismo nombre es lo que delata a un senuelo.
        ip = resuelve_nombre(host, self.fs)
        if ip is None:
            self.errorWrite(
                'psql: error: could not translate host name "%s" to address: '
                "Name or service not known\n" % host)
            self.exit_code = 2
            return

        # Con un nombre, psql ensena las dos cosas: el nombre y la IP a la que
        # resolvio. Con una IP literal, solo la IP.
        donde = ('"%s"' % host if es_ip(host) else '"%s" (%s)' % (host, ip))
        self.errorWrite(
            "psql: error: connection to server at %s, port %d failed: "
            "Connection refused\n" % (donde, puerto))
        self.errorWrite(
            "\tIs the server running on that host and accepting TCP/IP "
            "connections?\n")
        self.exit_code = 2

    @staticmethod
    def _puerto(texto: str, actual: int) -> int:
        try:
            return int(texto)
        except ValueError:
            return actual


commands["psql"] = Command_psql
commands["/usr/bin/psql"] = Command_psql
# La ruta de verdad del binario en Debian: /usr/bin/psql es un enlace al
# envoltorio pg_wrapper, y el ejecutable vive bajo /usr/lib/postgresql/NN/bin.
# El atacante de la captura la tecleo entera, asi que tiene que contestar igual.
commands["/usr/lib/postgresql/17/bin/psql"] = Command_psql
