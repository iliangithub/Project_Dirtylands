#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_comandos.py — los modulos de comandos y la coherencia de la leyenda.

    python3 "COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE/tests/test_comandos.py"

Dos mitades, y la segunda es la que de verdad importa.

La primera prueba los modulos nuevos sin levantar Cowrie: se les da un
HoneyPotCommand de mentira y se mira lo que escriben. Cubre "df" (que no da la
misma salida con y sin -h), "getconf", "mount", "top" y el formateador de
"free".

La segunda cruza las piezas de la leyenda entre si. Es la que evita el error
que ya se cometio: "lsblk" anunciaba un /dev/sda cuando /proc/modules no carga
ningun driver SATA, y el "dmesg" enlatado hablaba de un Debian de 2009. Cada
dato del disco, del kernel y de la placa vive en un fichero distinto ---lsblk.py,
df.py, sanitize-pickle.py, dmidecode.py, ifconfig.py y el dmesg de txtcmds---
y nada obligaba a que dijeran lo mismo. Ahora si.

Tambien se comprueba donde caen los enlatados: en "usr/bin/" y no en "bin/".
Un enlatado en "bin/" no se dispara nunca en un Debian con /usr fusionado, y el
comando no es que mienta, es que contesta "Exec format error".

No toca la red, ni Docker, ni la VPS: solo lee ficheros del repositorio.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import time
import types
from pathlib import Path

AQUI = Path(__file__).resolve().parent
COMANDOS = AQUI.parent / "commands"
TXTCMDS = AQUI.parent / "txtcmds"
# La carpeta de arriba YA es "COWRIE FAKE ENVIRONMENT": los comandos viven
# dentro de ella, no al lado.
ENTORNO = AQUI.parent.parent

OK = MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba %r\n          obtuvo   %r"
              % (que, esperado, obtenido))


def contiene(que, aguja, pajar):
    comprueba(que, True, aguja in pajar)


def _es_ip(texto):
    import ipaddress
    try:
        ipaddress.ip_address(texto)
    except ValueError:
        return False
    return True


# --- Un Cowrie de mentira, lo justo para que los modulos importen ----------
class HoneyPotCommandFalso:
    def __init__(self):
        self.args = []
        self.salida = []
        self.errores = []
        # El de verdad lo trae; sin el, cualquier comando que apunte su
        # codigo de salida revienta aqui y no en produccion, que es la peor
        # forma de enterarse.
        self.exit_code = 0

    def write(self, s):
        self.salida.append(s)

    def writeBytes(self, b):
        self.salida.append(b.decode())

    def errorWrite(self, s):
        self.errores.append(s)

    def exit(self, code=None):
        pass


def _finge_cowrie():
    for nombre in ("cowrie", "cowrie.shell", "cowrie.commands", "twisted",
                   "twisted.internet"):
        sys.modules.setdefault(nombre, types.ModuleType(nombre))
    mod = types.ModuleType("cowrie.shell.command")
    mod.HoneyPotCommand = HoneyPotCommandFalso
    sys.modules["cowrie.shell.command"] = mod
    # cowrie.shell.fs exporta los indices de los campos del pickle: varios
    # modulos nuestros los usan para mirar permisos.
    modfs = types.ModuleType("cowrie.shell.fs")
    (modfs.A_NAME, modfs.A_TYPE, modfs.A_UID, modfs.A_GID, modfs.A_SIZE,
     modfs.A_MODE, modfs.A_CTIME, modfs.A_CONTENTS, modfs.A_TARGET,
     modfs.A_REALFILE) = range(10)
    modfs.T_LINK, modfs.T_DIR, modfs.T_FILE = 0, 1, 2

    # Y la excepcion que lanza el sistema de ficheros de verdad cuando no
    # encuentra algo: awk la captura por su nombre.
    class _FileNotFound(Exception):
        pass

    modfs.FileNotFound = _FileNotFound
    modfs.T_BLK, modfs.T_CHR = 3, 4
    sys.modules["cowrie.shell.fs"] = modfs
    # cowrie.core.artifact: nano deja ahi el contenido escrito.
    art = types.ModuleType("cowrie.core.artifact")

    class _Artefacto:
        def __init__(self, nombre): self.shasumFilename = "/tmp/falso"
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def write(self, datos): pass

    art.Artifact = _Artefacto
    sys.modules.setdefault("cowrie.core", types.ModuleType("cowrie.core"))
    sys.modules["cowrie.core.artifact"] = art
    base = types.ModuleType("cowrie.commands.base")
    base.IGNIS_BOOT_EPOCH = 1773123780
    # La funcion REAL, sacada del propio base.py: uptime y top la importan, y
    # un doble que la reimplementara dejaria de probar lo que se despliega.
    _src = (COMANDOS / "base.py").read_text(encoding="utf-8")
    _m = re.search(r"^def formato_uptime.*?(?=\n\n\n)", _src, re.S | re.M)
    exec(compile(_m.group(0), "base.py", "exec"), base.__dict__)
    # Y la mixin que hace que un comando que avisa por el error termine mal:
    # la heredan veinte modulos, asi que sin ella no se carga ni uno.
    _mx = re.search(r"^class FallaAlAvisar:.*?(?=\n\n\n)", _src, re.S | re.M)
    exec(compile(_mx.group(0), "base.py", "exec"), base.__dict__)
    # Y el que pone en /proc/<pid>/status el usuario de la sesion: lo usan
    # todos los lectores de ficheros, asi que sin el no se carga ni fs.py.
    base.re = re
    base.PID_SESION = int(
        re.search(r"^PID_SESION = (\d+)", _src, re.M).group(1))
    for _cual in ("rutas_del_proceso", "con_dueno_de_sesion"):
        _mp = re.search(r"^def %s.*?(?=\n\n\n)" % _cual, _src, re.S | re.M)
        exec(compile(_mp.group(0), "base.py", "exec"), base.__dict__)
    _mc = re.search(r'^_PROC_DEL_PROCESO = \(.*?\)$', _src, re.S | re.M)
    exec(compile(_mc.group(0), "base.py", "exec"), base.__dict__)

    # Y el que deja un fichero CON su contenido, que usan crontab y usuarios.
    _ef = re.search(r"^def escribe_fichero.*?(?=\n\n\n)", _src, re.S | re.M)
    exec(compile(_ef.group(0), "base.py", "exec"), base.__dict__)
    # cowrie.commands.bashbuiltins: de ahi sale _relanzar, que es como
    # ejecutan lo que les ponen detras nice, timeout, env y setarch. La
    # funcion REAL, sacada de su fichero: un doble dejaria de probar lo que se
    # despliega. Con un protocolo fingido su cmdstack esta vacio y no relanza
    # nada, que es justo lo que quieren estas pruebas.
    if "cowrie.commands.bashbuiltins" not in sys.modules:
        _bb = types.ModuleType("cowrie.commands.bashbuiltins")
        _bbsrc = (COMANDOS / "bashbuiltins.py").read_text(encoding="utf-8")
        for _cual in ("_relanzar", "_path_lookup"):
            _mr = re.search(r"^def %s.*?(?=\n\n\n)" % _cual, _bbsrc,
                            re.S | re.M)
            exec(compile(_mr.group(0), "bashbuiltins.py", "exec"),
                 _bb.__dict__)
        sys.modules["cowrie.commands.bashbuiltins"] = _bb

    # Las banderas de lsattr viven ahi tambien.
    for _cte in ("BANDERAS_LSATTR", "BANDERA_SIEMPRE"):
        _m2 = re.search(r'^%s = "([^"]*)"' % _cte, _src, re.M)
        if _m2:
            setattr(base, _cte, _m2.group(1))
    sys.modules["cowrie.commands.base"] = base
    reactor = types.ModuleType("twisted.internet")
    reactor.reactor = types.SimpleNamespace(callLater=lambda *a, **k: None)
    sys.modules["twisted.internet"] = reactor
    # sudo apila una shell no interactiva para ejecutar la orden de root.
    hp = types.ModuleType("cowrie.shell.honeypot")

    class _ShellFalsa:
        creadas = []

        def __init__(self, protocol, interactive=True, redirect=False):
            self.protocol = protocol
            self.recibido = []
            _ShellFalsa.creadas.append(self)

        def lineReceived(self, linea):
            self.recibido.append(linea)

    hp.HoneyPotShell = _ShellFalsa
    sys.modules["cowrie.shell.honeypot"] = hp

    # cowrie.commands.coreutils_extra: de ahi sale la version de coreutils,
    # que wc, cut, chmod y printenv comparten. "cowrie.commands" no es un
    # paquete de verdad aqui, asi que el modulo hay que dejarlo puesto a mano
    # o el import de dentro no lo encuentra.
    if "cowrie.commands.coreutils_extra" not in sys.modules:
        _r = COMANDOS / "coreutils_extra.py"
        _sp = importlib.util.spec_from_file_location(
            "cowrie.commands.coreutils_extra", _r)
        _ce = importlib.util.module_from_spec(_sp)
        sys.modules["cowrie.commands.coreutils_extra"] = _ce
        _sp.loader.exec_module(_ce)


def carga(nombre):
    """Importa un modulo de comandos con las dependencias de Cowrie fingidas."""
    _finge_cowrie()
    ruta = COMANDOS / (nombre + ".py")
    spec = importlib.util.spec_from_file_location("cmd_" + nombre, ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cadenas_de(ruta):
    """Las cadenas que un modulo puede IMPRIMIR, sin comentarios ni docstrings.

    Existe porque cuatro pruebas distintas de este fichero han fallado ya por
    cazar su propio comentario: al explicar por que se quito un caracter o un
    formato, el comentario lo cita. Comprobar prosa en vez de codigo es como
    se escriben pruebas que fallan solas.
    """
    arbol = ast.parse(ruta.read_text(encoding="utf-8"))
    docs = {id(ast.get_docstring(n, clean=False)) for n in ast.walk(arbol)
            if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef))}
    for n in ast.walk(arbol):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) \
                and id(n.value) not in docs:
            yield n.value


def ejecuta(mod, clave, args, cwd="/root"):
    cmd = mod.commands[clave]()
    cmd.args = list(args)
    cmd.protocol = types.SimpleNamespace(cwd=cwd)
    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: r if r.startswith("/") else c + "/" + r)
    cmd.environ = {"LINES": "40", "COLUMNS": "80"}
    cmd.call()
    return "".join(cmd.salida), "".join(cmd.errores)


# ==========================================================================
print("\n== df ==")
df = carga("df")

salida, _ = ejecuta(df, "df", ["-h"])
lineas = salida.strip().split("\n")
comprueba("df -h: cabecera de coreutils", True,
          lineas[0].startswith("Filesystem") and lineas[0].endswith("Mounted on"))
contiene("df -h: la raiz es el NVMe", "/dev/nvme0n1p2", salida)
comprueba("df -h: ningun /dev/sda", False, "/dev/sda" in salida)
contiene("df -h: /boot/efi esta montado", "/boot/efi", salida)
comprueba("df -h: el cero se escribe '0', no '0.0K'", False, "0.0K" in salida)
comprueba("df -h: todas las filas tienen 6 columnas", {6},
          {len(l.split()) for l in lineas[1:]})

crudo, _ = ejecuta(df, "df", [])
contiene("df sin -h: bloques de 1K", "1K-blocks", crudo)
comprueba("df sin -h: no hay sufijos humanos", False,
          re.search(r"\d[GMT]\b", crudo) is not None)

tipos, _ = ejecuta(df, "df", ["-T"])
contiene("df -T: la raiz es ext4", "ext4", tipos)
contiene("df -T: la ESP es vfat", "vfat", tipos)

inodos, _ = ejecuta(df, "df", ["-i"])
contiene("df -i: cabecera de inodos", "IUse%", inodos)

una, _ = ejecuta(df, "df", ["-h", "/"])
comprueba("df -h /: una sola linea de datos", 2, len(una.strip().split("\n")))
contiene("df -h /: y es la raiz", "/dev/nvme0n1p2", una)

# El uso declarado tiene que ser el que sale de las cuentas, no un numero suelto.
for disp, _t, total, usado, _i, _iu, _p in df.TABLA:
    if _t == "ext4":
        reserva = int(total * df.RESERVA_EXT4)
        libre = total - usado - reserva
        pct = round(usado * 100 / (usado + libre))
        comprueba("df: el %% de uso de %s sale de las cuentas" % disp,
                  True, 14 <= pct <= 18)

comprueba("humano(0)", "0", df.humano(0))
comprueba("humano(5120) = 5.0M", "5.0M", df.humano(5120))
comprueba("humano redondea hacia arriba como coreutils", "7.8G",
          df.humano(8152656))

print("\n== getconf ==")
gc = carga("getconf")
salida, _ = ejecuta(gc, "getconf", ["LONG_BIT"])
comprueba("getconf LONG_BIT en una maquina x86_64", "64", salida.strip())
comprueba("getconf _NPROCESSORS_ONLN coincide con los 12 hilos del i5-12400",
          "12", ejecuta(gc, "getconf", ["_NPROCESSORS_ONLN"])[0].strip())
_, err = ejecuta(gc, "getconf", [])
contiene("getconf sin argumentos imprime su uso", "Usage: getconf", err)
_, err = ejecuta(gc, "getconf", ["NO_EXISTE_ESTA"])
contiene("getconf con una variable inventada", "unrecognized variable", err)
todo, _ = ejecuta(gc, "getconf", ["-a"])
contiene("getconf -a lista las variables", "PAGESIZE", todo)

print("\n== mount ==")
mnt = carga("mount")
cmd = mnt.commands["mount"]()
cmd.args = []
cmd.protocol = types.SimpleNamespace(cwd="/root")
cmd.environ = {}
cmd.call()  # sin honeyfs montado: tiene que caer en el respaldo
salida = "".join(cmd.salida)
comprueba("mount siempre imprime algo, aunque falte el honeyfs", True,
          len(salida.strip()) > 0)
contiene("mount usa el formato 'X on Y type Z'", " on / type ext4 (", salida)

_, err = ejecuta(mnt, "mount", ["/dev/sdb1", "/mnt"])
contiene("mount con argumentos falla como sin privilegios", "must be superuser", err)

print("\n== free ==")
free = carga("free")
comprueba("free -h usa unidades binarias con sufijo 'i'", "16Gi",
          free.humano(16777216))
comprueba("free -h con un decimal por debajo de 10", "2.0Gi",
          free.humano(2097148))
comprueba("free -h escribe el cero como '0B'", "0B", free.humano(0))

print("\n== top ==")
top = carga("top")
comprueba("top esta registrado en las tres rutas", 3, len(top.commands))
ps = json.loads((ENTORNO / "ps_command_output.json").read_text())["command"]["ps"]
cmd = top.commands["top"]()
cmd.procesos = sorted(ps, key=lambda p: (-float(p["CPU"]), p["PID"]))
cmd.environ = {"LINES": "40", "COLUMNS": "80"}
cabecera = cmd._cabecera()
contiene("top: la primera linea es la de uptime", "top - ", cabecera[0])
comprueba("top: el total de tareas es el del ps enlatado", True,
          ("Tasks: %3d total" % len(ps)) in cabecera[1])
fila = cmd._fila(ps[0])
comprueba("top: la fila cabe en 80 columnas", True, len(fila) <= 80)

print("\n== donde caen los enlatados ==")
comprueba("no queda ningun enlatado en txtcmds/bin/", False,
          (TXTCMDS / "bin").exists())
for f in ("dmesg", "stty", "sync"):
    comprueba("txtcmds/usr/bin/%s existe" % f, True,
              (TXTCMDS / "usr" / "bin" / f).is_file())
comprueba("sync esta vacio a proposito, pero existe", 0,
          (TXTCMDS / "usr" / "bin" / "sync").stat().st_size)
comprueba("ya no hay enlatado de nano (ahora es un modulo)", False,
          (TXTCMDS / "usr" / "bin" / "nano").exists())

print("\n== todos los modulos estan registrados en __init__.py ==")
lista = ast.literal_eval(
    re.search(r"command_modules[^=]*=\s*(\[.*?\])",
              (COMANDOS / "__init__.py").read_text(), re.S).group(1))
for py in sorted(COMANDOS.glob("*.py")):
    if py.stem in ("__init__", "base", "fs", "bashbuiltins"):
        continue
    if py.stem not in lista:
        comprueba("%s figura en command_modules" % py.stem, True, False)
    else:
        OK += 1
print("  ok    los %d modulos de la lista se cargan" % len(lista))
OK += 1

# ==========================================================================
print("\n== coherencia de la leyenda ==")

modulos_proc = re.search(r'PROC_MODULES = """(.*?)"""',
                         (ENTORNO / "sanitize-pickle.py").read_text(), re.S).group(1)
# Solo la SALIDA del modulo: los comentarios de lsblk.py nombran "sda" y "sr0"
# justamente para explicar por que ya no estan, y buscarlos en el fichero
# entero daria un falso positivo.
lsblk = carga("lsblk").OUTPUT
dmesg = (TXTCMDS / "usr" / "bin" / "dmesg").read_text()
dmidecode = (COMANDOS / "dmidecode.py").read_text()
ifconfig = (COMANDOS / "ifconfig.py").read_text()
saneador = (ENTORNO / "sanitize-pickle.py").read_text()

comprueba("/proc/modules carga el driver NVMe", True, "\nnvme " in modulos_proc)
comprueba("/proc/modules NO carga ningun driver SATA", False,
          "ahci" in modulos_proc or "libata" in modulos_proc)
comprueba("lsblk describe un NVMe, que es lo unico posible", True,
          "nvme0n1" in lsblk)
comprueba("lsblk no inventa un /dev/sda sin driver que lo explique", False,
          "sda" in lsblk)
comprueba("/proc/modules no carga sr_mod, asi que lsblk no ensena un sr0", False,
          "sr0" in lsblk)

# El kernel: el mismo en el saneador y en el dmesg.
kernel = re.search(r'KERNEL_RELEASE = "([^"]+)"', saneador).group(1)
contiene("el dmesg anuncia el mismo kernel que /proc/version", kernel, dmesg)
comprueba("el dmesg no es el Debian Lenny de 2009 que traia Cowrie", False,
          "2.6.26" in dmesg)

# La placa: la del dmidecode.
placa = re.search(r"Product Name: (MS-\w+)", dmidecode).group(1)
contiene("el dmesg nombra la misma placa que dmidecode", placa, dmesg)
bios = re.search(r"Version: (1\.\d+)", dmidecode).group(1)
contiene("y la misma version de BIOS", "BIOS " + bios, dmesg)

# La MAC: la de ifconfig.
mac = re.search(r'HWaddr = "([0-9a-f:]+)"', ifconfig).group(1)
contiene("el dmesg usa la MAC que declara ifconfig", mac, dmesg)

# El disco: lsblk, df, /proc/mounts y fstab hablan del mismo reparto.
mounts = re.search(r'PROC_MOUNTS = f"""(.*?)"""', saneador, re.S).group(1)
for part in ("nvme0n1p1", "nvme0n1p2"):
    contiene("lsblk conoce %s" % part, part, lsblk)
    contiene("/proc/mounts monta %s" % part, part, mounts)
comprueba("el swap del dmesg es el SwapTotal del meminfo", True,
          "2097148k swap on /dev/nvme0n1p3" in dmesg)

# Los tamanos de los tmpfs: df y /proc/mounts tienen que decir lo mismo.
for kb in (8152656, 1677720, 5120):
    comprueba("el tmpfs de %dk cuadra entre df y /proc/mounts" % kb, True,
              str(kb) in mounts and any(f[2] == kb for f in df.TABLA))

# El uptime: top y uptime.py parten del mismo instante de arranque.
base_py = (COMANDOS / "base.py").read_text()
epoca = re.search(r"IGNIS_BOOT_EPOCH = (\d+)", base_py).group(1)
comprueba("top toma el arranque de base.py y no lleva el suyo", True,
          "IGNIS_BOOT_EPOCH" in (COMANDOS / "top.py").read_text()
          and epoca not in (COMANDOS / "top.py").read_text())

# ==========================================================================
print("\n== el entorno de una sesion ==")

def _carga_honeypot():
    """Importa shell/honeypot.py fingiendo las dependencias de Cowrie."""
    _finge_cowrie()
    for nombre in ("twisted.python", "twisted.python.compat", "twisted.internet",
                   "cowrie.core", "cowrie.core.config", "cowrie.shell.fs",
                   "cowrie.shell.parser", "cowrie.shell.pipe"):
        sys.modules.setdefault(nombre, types.ModuleType(nombre))
    sys.modules["twisted.python"].failure = types.SimpleNamespace(Failure=object)
    sys.modules["twisted.python"].log = types.SimpleNamespace(msg=lambda *a, **k: None)
    sys.modules["twisted.python.compat"].iterbytes = lambda b: b
    sys.modules["twisted.internet"].error = types.SimpleNamespace(ProcessDone=Exception)
    sys.modules["cowrie.core.config"].CowrieConfig = types.SimpleNamespace(
        get=lambda *a, **k: "", getboolean=lambda *a, **k: False)
    sys.modules["cowrie.shell.parser"].CommandParser = object
    sys.modules["cowrie.shell.pipe"].PipeProtocol = object
    ruta = AQUI.parent / "shell" / "honeypot.py"
    spec = importlib.util.spec_from_file_location("hp", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def entorno_de(via, usuario, uid, kippo_ip="198.51.100.4"):
    """Monta el entorno como lo deja _completar_entorno, sin arrancar Cowrie."""
    hp = _carga_honeypot()
    shell = hp.HoneyPotShell.__new__(hp.HoneyPotShell)
    # Lo que ya trae Cowrie de su session.py, con el error incluido.
    shell.environ = {
        "HOME": "/root" if uid == 0 else f"/home/{usuario}",
        "LOGNAME": usuario, "USER": usuario, "SHELL": "/bin/bash",
        "TMOUT": "1800",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        if uid == 0 else "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games",
        "TERM": "xterm",
    }
    if via == "ssh":
        shell.environ["SHLVL"] = "1"
        shell.environ["UID"] = str(uid)
    shell.exported = set(shell.environ)
    shell.environ["COLUMNS"] = "80"
    shell.environ["LINES"] = "24"
    shell.exported |= {"COLUMNS", "LINES"}

    clase = "HoneyPotTelnetProtocol" if via == "telnet" else "HoneyPotInteractiveProtocol"
    proto = type(clase, (), {})()
    proto.user = types.SimpleNamespace(username=usuario, uid=uid)
    proto.clientIP = "203.0.113.9"
    proto.kippoIP = kippo_ip
    proto.realClientPort = 41234
    proto.hostname = "pc-dev-003-ignis"
    proto.cwd = shell.environ["HOME"]
    shell._completar_entorno(proto)
    return shell


# Las listas son las MEDIDAS en un Debian 13 de verdad, entrando por las dos
# vias. Si alguien anade o quita una variable, esta prueba lo dice.
ESPERADO_SSH_ROOT = {
    "HOME", "LOGNAME", "MOTD_SHOWN", "PATH", "PWD", "SHELL", "SHLVL",
    "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "TERM", "USER",
    "XDG_RUNTIME_DIR", "XDG_SESSION_CLASS", "XDG_SESSION_ID", "XDG_SESSION_TYPE",
}
ESPERADO_TELNET_ROOT = {
    "HOME", "LOGNAME", "MAIL", "PATH", "PWD", "SHELL", "SHLVL", "TERM", "USER",
    "XDG_RUNTIME_DIR", "XDG_SESSION_CLASS", "XDG_SESSION_ID", "XDG_SESSION_TYPE",
}

s_ssh = entorno_de("ssh", "root", 0)
comprueba("SSH root: las exportadas son exactamente las de un Debian real",
          ESPERADO_SSH_ROOT, s_ssh.exported)
comprueba("SSH: sin MAIL (sshd lleva 'noenv' en pam_mail)", False, "MAIL" in s_ssh.exported)
comprueba("SSH_CONNECTION lleva las dos IP y los dos puertos", 4,
          len(s_ssh.environ["SSH_CONNECTION"].split()))
comprueba("SSH_CLIENT acaba en el 22, no en el 2222 en que escucha Cowrie",
          "22", s_ssh.environ["SSH_CLIENT"].split()[-1])
comprueba("SSH_TTY es el mismo pts que ensenan ps, who y w",
          "/dev/pts/0", s_ssh.environ["SSH_TTY"])
# EL HUECO DE LA PLANTILLA, SIN RELLENAR, EN EL ENTORNO DEL ATACANTE.
# El cowrie.cfg de la VPS se pego con "internet_facing_ip = [IP VPS]" tal
# cual, y Cowrie lo copia a SSH_CONNECTION sin mirarlo:
#
#     SSH_CONNECTION=203.0.113.7 60962 [IP VPS] 22
#
# La prueba de arriba contaba los cuatro campos, pero con una IP buena
# puesta a mano: nunca se le dio el valor que estaba desplegado. Ahora si.
_s_mal = entorno_de("ssh", "root", 0, kippo_ip="[IP VPS]")
comprueba("un internet_facing_ip sin sustituir NO llega al entorno", False,
          "[IP VPS]" in _s_mal.environ["SSH_CONNECTION"])
comprueba("   y SSH_CONNECTION sigue teniendo cuatro campos, no cinco", 4,
          len(_s_mal.environ["SSH_CONNECTION"].split()))
comprueba("   y lo que se pone en su sitio es una IP de verdad", True,
          _es_ip(_s_mal.environ["SSH_CONNECTION"].split()[2]))
comprueba("una IP buena se respeta tal cual", "198.51.100.4",
          s_ssh.environ["SSH_CONNECTION"].split()[2])

s_tel = entorno_de("telnet", "root", 0)
comprueba("telnet root: las exportadas son exactamente las de un Debian real",
          ESPERADO_TELNET_ROOT, s_tel.exported)
comprueba("telnet: MAIL si, que la pone /bin/login",
          "/var/mail/root", s_tel.environ["MAIL"])
comprueba("telnet: sin SSH_CLIENT, obviamente", False, "SSH_CLIENT" in s_tel.exported)
comprueba("telnet: con SHLVL, que Cowrie no ponia por esta via",
          "1", s_tel.environ["SHLVL"])

for shell in (s_ssh, s_tel):
    comprueba("TMOUT fuera: un Debian no lo pone", False, "TMOUT" in shell.environ)
    for v in ("UID", "COLUMNS", "LINES"):
        comprueba("%s existe como variable de shell..." % v, True, v in shell.environ)
        comprueba("...pero NO exportada, como en bash", False, v in shell.exported)

s_user = entorno_de("ssh", "alyosha", 1004)
comprueba("un usuario normal exporta LS_COLORS (su .bashrc corre dircolors)",
          True, "LS_COLORS" in s_user.exported)
comprueba("root no, porque su .bashrc lo trae comentado",
          False, "LS_COLORS" in s_ssh.exported)
comprueba("XDG_RUNTIME_DIR usa el uid del usuario",
          "/run/user/1004", s_user.environ["XDG_RUNTIME_DIR"])
comprueba("el historial del usuario es el de /etc/skel, no el de root",
          ("1000", "2000"), (s_user.environ["HISTSIZE"], s_user.environ["HISTFILESIZE"]))
comprueba("y el de root es el que deja bash por defecto",
          ("500", "500"), (s_ssh.environ["HISTSIZE"], s_ssh.environ["HISTFILESIZE"]))

hp = _carga_honeypot()
comprueba("LS_COLORS es la salida literal de dircolors, sin espacios", False,
          " " in hp.LS_COLORS)
comprueba("y empieza como la de Debian 13", True,
          hp.LS_COLORS.startswith("rs=0:di=01;34:ln=01;36:"))
comprueba("BASH_VERSION concuerda con el bash que declara nuestro dpkg",
          "5.2.37", hp.HoneyPotShell.BASH_VERSION.split("(")[0])


# ==========================================================================
print("\n== un bloque pegado entre comillas ==")
#
# ESTO SALIO DE UNA CAPTURA DE VERDAD. Un atacante pego tres bloques ---un
# `python3 -c`, un `node -e` y un `bash -c`--- para llegar a la base de datos
# cuyas credenciales habia sacado del .env del cebo. Nuestro shell ejecutaba la
# PRIMERA linea y trataba las demas como ordenes sueltas, asi que en el log
# quedaban "import socket", "try:" y "s.close()" como comandos que el senuelo
# no sabia ejecutar. Eso no lo hace ningun Linux: bash, con una comilla sin
# cerrar, saca su prompt "> " y no ejecuta nada hasta que se cierra.
for texto, abierta in (
        ('python3 -c "import socket', True),
        ("python3 -c 'import socket", True),
        ('node -e "const net=require(\'net\');', True),
        ('echo "hola"', False),
        ("echo 'hola'", False),
        ('echo "don\'t"', False),          # la simple va DENTRO de la doble
        ("awk '{print $1}' /etc/passwd", False),
        ('echo "escapada: \\" y sigue"', False),
        ("echo 'no escapa: \\' ", False),  # dentro de simple no hay escapes
        ('grep -r "clave" /etc; echo fin', False),
):
    comprueba("comilla sin cerrar en %r" % texto[:34], abierta,
              hp.comillas_abiertas(texto))

comprueba("y con la comilla abierta, bash sigue leyendo", True,
          hp.command_incomplete('python3 -c "import socket'))
comprueba("con la comilla cerrada, ejecuta", False,
          hp.command_incomplete('python3 -c "import socket"'))
comprueba("una barra invertida al final sigue leyendo, como antes", True,
          hp.command_incomplete("wget http://x/a \\"))
comprueba("y un for sin su done, tambien como antes", True,
          hp.command_incomplete("for i in 1 2 3; do echo $i"))

# AL JUNTARLAS, EL SALTO DE LINEA ES UN CARACTER DEL TEXTO, no un separador: al
# `python3 -c` hay que darle su programa con sus saltos y su sangria. Uniendo
# con "; " y recortando los espacios llegaba todo en una linea, y un python de
# verdad no contesta eso.
bloque = ['python3 -c "import socket', "for h in hosts:", "    print(h)", '"']
comprueba("un bloque entre comillas se junta con saltos de linea de verdad",
          'python3 -c "import socket\nfor h in hosts:\n    print(h)\n"',
          hp.flatten_continuation(bloque))
comprueba("y la sangria del programa no se toca", True,
          "\n    print(h)" in hp.flatten_continuation(bloque))
comprueba("lo que no lleva comillas se sigue juntando con punto y coma",
          "for i in 1 2; do echo $i; done",
          hp.flatten_continuation(["for i in 1 2; do", "echo $i", "done"]))


# ==========================================================================
print("\n== nano y los permisos ==")

# Un sistema de ficheros de mentira con la forma que espera el modulo: cada
# nodo es la lista de 10 campos de createfs.py.
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE = 0, 1, 2, 3, 4, 5


def nodo(uid, gid, modo):
    return ["x", 2, uid, gid, 0, modo, 0, b"", None, None]


class FsFalso:
    """Solo lo que nano usa: getfile, exists, resolve_path y file_contents."""

    def __init__(self, mapa):
        self.mapa = mapa
        self.creados = []

    def getfile(self, ruta, follow_symlinks=True):
        return self.mapa.get(ruta)

    def exists(self, ruta):
        return ruta in self.mapa

    def isdir(self, ruta):
        return self.mapa.get(ruta, [None, 2])[1] == 1

    def resolve_path(self, r, cwd):
        return r if r.startswith("/") else cwd.rstrip("/") + "/" + r

    def file_contents(self, ruta):
        return b"contenido\n"

    def mkfile(self, ruta, uid, gid, tam, modo):
        self.creados.append(ruta)

    def update_realfile(self, *a):
        pass


class TerminalFalso:
    """Imita al terminal de insults, CON SUS CONSTANTES DE TECLA.

    Las constantes importan y no son decorativas. Cuando una flecha llega a
    keyHandlers, insults ya ha traducido la secuencia del cable (b"[A") a su
    nombre (b"[UP_ARROW]"), asi que un manejador registrado bajo la secuencia
    cruda no se llama nunca. Este mock las traia, y por eso un nano que
    escuchaba la tecla equivocada pasaba los tests mientras en el senuelo las
    flechas seguian escupiendo el historial del shell. Los valores son los de
    twisted.conch.insults.insults.ServerProtocol, copiados literalmente.
    """
    UP_ARROW = b"[UP_ARROW]"
    DOWN_ARROW = b"[DOWN_ARROW]"
    LEFT_ARROW = b"[LEFT_ARROW]"
    RIGHT_ARROW = b"[RIGHT_ARROW]"
    HOME = b"[HOME]"
    END = b"[END]"
    DELETE = b"[DELETE]"
    BACKSPACE = b"\x7f"

    def eraseDisplay(self): pass
    def cursorHome(self): pass
    def cursorPosition(self, *a): pass
    def eraseLine(self): pass
    def saveCursor(self): pass
    def restoreCursor(self): pass


class SesionFalsa:
    """La sesion de Cowrie: guarda el tamano y NO avisa a nadie.

    Es lo que hace de verdad shell/session.py, y por eso nano tiene que
    envolver este metodo para enterarse de que la ventana cambio.
    """
    def __init__(self, uid, gid):
        self.uid = uid
        self.gid = gid
        self.username = "alyosha"
        self.windowSize = [24, 80]

    def windowChanged(self, windowSize):
        self.windowSize = windowSize


def teclas_de_historial():
    """keyHandlers como los deja HistoricRecvLine antes de abrir el editor."""
    t = TerminalFalso
    return {
        t.UP_ARROW: lambda: "handle_UP",
        t.DOWN_ARROW: lambda: "handle_DOWN",
        t.LEFT_ARROW: lambda: "handle_LEFT",
        t.RIGHT_ARROW: lambda: "handle_RIGHT",
    }


def abre_nano(mapa, ruta, uid, gid):
    mod = carga("nano")
    cmd = mod.commands["nano"]()
    cmd.args = [ruta]
    cmd.environ = {"LINES": "24", "COLUMNS": "80"}
    cmd.fs = FsFalso(mapa)
    cmd.protocol = types.SimpleNamespace(
        cwd="/home/alyosha",
        terminal=TerminalFalso(),
        user=SesionFalsa(uid, gid),
        keyHandlers=teclas_de_historial(),
        characterReceived=lambda ch, mas=False: None,
        events=types.SimpleNamespace(dispatch=lambda *a, **k: None),
    )
    cmd.current_user = {"uid": uid, "gid": gid}
    cmd.start()
    return cmd


# /etc/passwd: 0644 de root. Un usuario normal lee pero no escribe, y el /etc
# tampoco es suyo.
MAPA = {
    "/": nodo(0, 0, 0o40755),
    "/etc": nodo(0, 0, 0o40755),
    "/etc/passwd": nodo(0, 0, 0o100644),
    "/tmp": nodo(0, 0, 0o41777),
    "/home": nodo(0, 0, 0o40755),
    "/home/mihail": nodo(1000, 1000, 0o40750),
    "/home/mihail/nota.txt": nodo(1000, 1000, 0o100644),
    "/home/alyosha": nodo(1004, 1004, 0o40750),
}

c = abre_nano(MAPA, "/etc/passwd", 1004, 1004)
comprueba("nano /etc/passwd avisa de las DOS cosas, como el nano real",
          ["Directory '/etc' is not writable", "File '/etc/passwd' is unwritable"],
          c.avisos)
comprueba("se puede leer", True, c.legible)
comprueba("pero no escribir", False, c.escribible)

c = abre_nano(MAPA, "/home/mihail/nota.txt", 1004, 1004)
comprueba("un home ajeno (0750) no deja ni pasar",
          ["Path '/home/mihail' is not accessible"], c.avisos)
comprueba("y por tanto no se lee", False, c.legible)

c = abre_nano(MAPA, "/tmp/mio.txt", 1004, 1004)
comprueba("en /tmp no hay nada que avisar", [], c.avisos)
comprueba("y se puede escribir", True, c.escribible)

c = abre_nano(MAPA, "/etc/passwd", 0, 0)
comprueba("root no ve ningun aviso", [], c.avisos)

# El fichero ilegible: buffer vacio y titulo "New Buffer", como hace nano.
MAPA_SECRETO = dict(MAPA)
MAPA_SECRETO["/etc/shadow"] = nodo(0, 42, 0o100640)
c = abre_nano(MAPA_SECRETO, "/etc/shadow", 1004, 1004)
comprueba("un fichero que no se puede leer lo dice con su ruta", True,
          "Error reading /etc/shadow: Permission denied" in c.avisos)
# Un buffer vacio tiene UNA linea vacia, no cero: es donde se pone el cursor.
# Es lo que hace el nano real con "New Buffer", y desde que el editor es de
# pantalla hace falta que exista para poder escribir en ella.
comprueba("no carga nada del fichero ilegible", [""], c.lineas)
contiene("y el titulo pasa a 'New Buffer'", "New Buffer", c._titulo())

# ---- guardar donde no se puede -------------------------------------------
print()
mod = carga("nano")
c = abre_nano(MAPA, "/etc/passwd", 1004, 1004)
c.salida = []
c.write = lambda s: c.salida.append(s)
c.lineas = ["algo nuevo"]
c._guardar("/etc/passwd")
pintado = "".join(c.salida)
contiene("guardar sin permiso lo dice con el mensaje de nano",
         "Error writing /etc/passwd: Permission denied", pintado)
contiene("y lo pinta en BLANCO SOBRE ROJO, no en video inverso",
         mod.ROJO, pintado)
comprueba("y sobre todo NO escribe el fichero", [], c.fs.creados)

c = abre_nano(MAPA, "/tmp/bueno.txt", 1004, 1004)
c.salida = []
c.write = lambda s: c.salida.append(s)
c.lineas = ["una linea"]
c._guardar("/tmp/bueno.txt")
pintado = "".join(c.salida)
contiene("en cambio en /tmp si guarda", "Wrote 1 line", pintado)
comprueba("y el fichero se crea", ["/tmp/bueno.txt"], c.fs.creados)
comprueba("el aviso de exito NO va en rojo", False, mod.ROJO in pintado)

# ---- los textos son los del nano de verdad -------------------------------
fuente = (COMANDOS / "nano.py").read_text()
comprueba("el prompt de ^O es el de nano 8.4", True,
          "Write to File:" in fuente and "File Name to Write" not in fuente)
comprueba("y el de ^X tambien", True,
          "Save modified buffer?" in fuente
          and "will DISCARD changes" not in fuente)
comprueba("el rojo es el que usa nano de verdad",
          "\x1b[0;1m\x1b[37m\x1b[41m", mod.ROJO)


print("\n== ps: la sesion y el /proc/self dicen el mismo PID ==")
import re as _re
base_txt = (COMANDOS / "base.py").read_text()
san_txt = (ENTORNO / "sanitize-pickle.py").read_text()
pid_ps = int(_re.search(r"^PID_SESION = (\d+)", base_txt, _re.M).group(1))
pid_pickle = int(_re.search(r"^PID_LEYENDA = (\d+)", san_txt, _re.M).group(1))
comprueba("el PID del bash de ps es el mismo al que apunta /proc/self",
          pid_pickle, pid_ps)

# Y EL IDENTIFICADOR DE SESION, por lo mismo: el cgroup que vive en el pickle
# lo lleva dentro ---"session-89.scope"--- y el shell lo exporta en
# XDG_SESSION_ID. Antes se sorteaba uno al azar en cada login, asi que
# "echo $XDG_SESSION_ID" y "cat /proc/self/cgroup" se desmentian en dos
# ordenes seguidas.
_hp_txt = (COMANDOS.parent / "shell" / "honeypot.py").read_text()
_ses_hp = int(_re.search(r"^SESION_LEYENDA = (\d+)", _hp_txt, _re.M).group(1))
_ses_pk = int(_re.search(r"^SESION_LEYENDA = (\d+)", san_txt, _re.M).group(1))
comprueba("el XDG_SESSION_ID del shell es el del cgroup del pickle",
          _ses_pk, _ses_hp)
comprueba("   y ya no se sortea uno en cada login", False,
          "XDG_SESSION_ID\", str(random" in _hp_txt)
comprueba("   y el cgroup del pickle se construye con esa constante", True,
          "session-%d.scope" in san_txt and "SESION_LEYENDA" in san_txt)

# Se mira el CODIGO, no los comentarios: los dos ficheros explican en prosa el
# error que tenian, y buscar el texto suelto da un falso positivo.
def _sin_comentarios(texto):
    """Quita comentarios Y docstrings: los dos explican en prosa el error que
    se corrigio, y buscar el texto suelto encuentra la explicacion."""
    fuera, dentro = [], False
    for l in texto.split("\n"):
        if l.count('"""') == 1:
            dentro = not dentro
            continue
        if dentro or l.lstrip().startswith("#"):
            continue
        fuera.append(l)
    return "\n".join(fuera)

_ps_codigo = _sin_comentarios(
    base_txt.split("class Command_ps")[1].split("\nclass ")[0])
comprueba("ps ya no rellena la cadena de formato en vez del valor", False,
          '".ljust(' in _ps_codigo)
contiene("y usa el formato de procps, con COMMAND al final",
         "%-10s%6s %4s %4s %6s %5s %-9s%-5s%5s %6s %s", base_txt)

print("\n== ls: lo que un listado largo NO puede omitir ==")
ls_txt = (COMANDOS / "ls.py").read_text()
comprueba("el listado largo abre con 'total N'", True, 'total %d' in ls_txt)
comprueba("el contador de enlaces se calcula, no es un 1 fijo", False,
          '"{} 1 {}' in ls_txt)
comprueba("la fecha NO va en formato ISO, que es de --time-style=long-iso",
          False, '"%Y-%m-%d %H:%M"' in ls_txt)
contiene("sino en el de coreutils", '"%b %e %H:%M"', ls_txt)

print("\n== netstat: las opciones que se piden se obedecen ==")
net_txt = (COMANDOS / "netstat.py").read_text()
comprueba("-n ya no deja un '*:ssh' escrito a fuego", False,
          '"tcp        0      0 *:ssh' in _sin_comentarios(net_txt))
contiene("-p anade la columna que le corresponde", "PID/Program name", net_txt)
contiene("y sin ser root avisa como el de verdad",
         'No info could be read for "-p"', net_txt)
contiene("la cabecera cambia con -l", "(only servers)", net_txt)
contiene("y con -a", "(servers and established)", net_txt)


print("\n== nano: la barra de titulo se centra de verdad ==")
# Las posiciones son las MEDIDAS contra GNU nano 8.4 con un pseudo-terminal a
# tres anchuras y tres nombres de distinta longitud. Antes se centraba en el
# hueco que queda tras "GNU nano 8.4", asi que el nombre salia corrido.
mod_nano = carga("nano")


def titulo_de(nombre, ancho):
    c = mod_nano.commands["nano"]()
    c.nombre = nombre
    c.sin_titulo = False
    c.modificado = False
    c.environ = {"COLUMNS": str(ancho), "LINES": "24"}
    import re as _r
    return _r.sub(r"\x1b\[[0-9;]*m", "", c._titulo())


for nombre, ancho, esperado in (("New Buffer", 80, 37),
                                ("New Buffer", 100, 47),
                                ("New Buffer", 120, 57),
                                ("i.txt", 80, 40),
                                ("/tmp/documento-bastante-largo.txt", 80, 26)):
    t = titulo_de(nombre if nombre != "New Buffer" else "", ancho)
    comprueba("%r a %d columnas empieza donde el nano real" % (nombre, ancho),
              esperado, t.find(nombre))
    comprueba("   y la barra ocupa el ancho entero", ancho, len(t))

print("\n== nano: las teclas que atrapa mientras esta abierto ==")
# ESTAS PRUEBAS MIRAN EL DICCIONARIO, NO EL CODIGO FUENTE.
#
# Antes buscaban el literal b"[A" dentro de nano.py. Eso comprobaba que
# alguien habia escrito una cadena, no que la cadena fuese la correcta: el
# nombre bueno es b"[UP_ARROW]", porque insults traduce la secuencia del
# cable antes de llegar a keyHandlers. Con b"[A" las flechas seguian yendo
# al historial del shell en el senuelo mientras el test daba verde, y llego
# a pasar la prueba una version en la que el literal solo aparecia dentro de
# un comentario. Se comprueba el efecto: quien queda registrado en la tecla.
c = abre_nano(MAPA, "/home/alyosha/n.txt", 1000, 1000)
manejadores = c.protocol.keyHandlers
T = TerminalFalso

for tecla, que in ((b"\x0f", "^O guardar"), (b"\x18", "^X salir"),
                   (b"\x07", "^G ayuda"), (b"\x03", "^C posicion")):
    comprueba("atrapa %s" % que, True, tecla in manejadores)

for tecla, que in ((T.UP_ARROW, "arriba"), (T.DOWN_ARROW, "abajo")):
    comprueba("la flecha %s ya NO es la del historial" % que,
              True, manejadores[tecla]() is None)

# Izquierda y derecha YA NO son de recvline. Antes se le dejaban a proposito,
# porque solo habia una linea viva y moverse por ella era todo lo que se podia
# ofrecer. Ahora el editor lleva el texto entero y las cuatro flechas navegan
# por el, que es lo que hace un nano de verdad.
comprueba("izquierda ya la lleva el editor, no el historial",
          None, manejadores[T.LEFT_ARROW]())
comprueba("   y derecha tambien", None, manejadores[T.RIGHT_ARROW]())

c.exit()
comprueba("al salir se devuelve el historial de arriba",
          "handle_UP", manejadores[T.UP_ARROW]())
comprueba("   y el de abajo", "handle_DOWN", manejadores[T.DOWN_ARROW]())


print("\n== el shell: guiones, cortocircuito y bucles ==")
# Los tres fallos que impedian que un cargador de Mirai funcionara, y que se
# encontraron leyendo el log de un ataque real del 2026-08-23.
_fuente_sh = (COMANDOS.parent / "shell" / "honeypot.py").read_text(encoding="utf-8")
_fuente_bash = (COMANDOS / "bash.py").read_text(encoding="utf-8")

# 1. Un guion entero llega con sus saltos de linea y hay que trocearlo.
comprueba("el shell trocea un guion por sus saltos de linea", True,
          'if "\\n" in line and not self.interactive:' in _fuente_sh)
comprueba("   y solo en modo NO interactivo, para no romper el prompt '> '",
          True, "not self.interactive" in _fuente_sh)

# 2. Dentro del parentesis, && y || tienen que cortar.
# No se comprueba la AUSENCIA de la frase vieja: el comentario que explica el
# arreglo la cita, asi que un grep la encuentra igual. Es el mismo tropiezo que
# ya dio el literal b"[A" de las flechas. Se comprueba lo que hace, no lo que
# dejo de decir.
comprueba("dentro del parentesis se evalua el cortocircuito", True,
          'op == "&&" and estado != 0' in _fuente_sh
          and 'op == "||" and estado == 0' in _fuente_sh)

# 3. sh/bash no puede pegar las lineas con ';'.
# 4. La salida de un parentesis va al fichero de la redireccion, no a la
# pantalla. Sin esto, `(wget URL -O-) > w` dejaba w VACIO y ademas volcaba el
# binario en la pantalla del atacante, que en un Linux real no pasa nunca.
comprueba("la salida de un subshell puede ir a un fichero", True,
          "_volcar_a_fichero" in _fuente_sh)
comprueba("   y las DOS ramas de subshell usan el mismo destino", True,
          _fuente_sh.count("_salida_de_subshell") >= 2
          or (_fuente_sh.count("_volcar_a_fichero") >= 3))
comprueba("   se distingue anexar de sobrescribir", True,
          'anexar = siguiente == ">>"' in _fuente_sh)

comprueba("sh une las lineas del guion con salto, no con ';'", True,
          'execute_commands("\\n".join(lines))' in _fuente_bash)
comprueba("   y ya no queda el join con '; '", False,
          'execute_commands("; ".join(lines))' in _fuente_bash)


print("\n== nano: se puede NAVEGAR y CORREGIR el texto ==")
# Lo que no se podia hacer antes: volver atras. El editor era de LINEA ---la
# llevaba recvline y al pulsar Enter se cerraba para siempre--- asi que una vez
# escrita una linea no habia forma de corregirla. Ahora el texto es nuestro y
# las cuatro flechas se mueven por el.
e = abre_nano(MAPA, "/home/alyosha/n.txt", 1000, 1000)
K = e.protocol.keyHandlers
T2 = TerminalFalso

def escribe(texto):
    for ch in texto:
        e._caracter(ch)

e.lineas = []
e.fila = e.col = 0
escribe("primera"); K[b"\r"]()
escribe("segunda"); K[b"\r"]()
escribe("tercera")
comprueba("tres lineas escritas", ["primera", "segunda", "tercera"], e.lineas)

K[T2.UP_ARROW](); K[T2.UP_ARROW]()
comprueba("ARRIBA sube por el texto", 0, e.fila)
K[T2.HOME](); escribe(">>")
comprueba("   y se puede corregir una linea YA escrita",
          ">>primera", e.lineas[0])

K[T2.DOWN_ARROW](); K[T2.END](); escribe("!")
comprueba("ABAJO y END llevan al final de la siguiente",
          "segunda!", e.lineas[1])

for _ in range(3):
    K[T2.LEFT_ARROW]()
K[T2.BACKSPACE]()
comprueba("IZQUIERDA + borrar quita el caracter correcto",
          "seguda!", e.lineas[1])

K[b"\r"]()
comprueba("Enter parte la linea por donde esta el cursor",
          ["segu", "da!"], e.lineas[1:3])

# Tras partir, el cursor queda al PRINCIPIO de la linea nueva, asi que ahi
# SUPR borra su primer caracter. Para unir dos lineas hay que estar al final
# de la primera, que es como se comporta cualquier editor.
K[T2.DELETE]()
comprueba("SUPR al principio de linea borra su primer caracter",
          "a!", e.lineas[2])
K[T2.UP_ARROW](); K[T2.END](); K[T2.DELETE]()
comprueba("   y al FINAL de linea, une con la siguiente", "segua!", e.lineas[1])

# Los limites: no se sale del texto ni revienta.
for _ in range(50):
    K[T2.BACKSPACE]()
for _ in range(20):
    K[T2.UP_ARROW]()
for _ in range(20):
    K[T2.LEFT_ARROW]()
comprueba("moverse mas alla del principio se queda en 0,0", (0, 0), (e.fila, e.col))
comprueba("   y el buffer nunca se queda sin lineas", True, len(e.lineas) >= 1)

# Con un dialogo abierto, las teclas son del dialogo y NO del texto.
antes = list(e.lineas)
e.preguntando = "salir"
escribe("y")
comprueba("con un dialogo abierto no se escribe en el texto", antes, e.lineas)
e.preguntando = None
e.exit()


print("\n== nano: la barra de atajos crece con el terminal ==")
# MEDIDO contra un nano real (TERM=xterm, LANG=C): a 80 columnas ensena 6
# parejas de atajos, a 120 ensena 8 y a 160 ensena 10. Antes la tabla tenia
# seis fijas, asi que en un terminal ancho se quedaba corta y con media
# pantalla vacia --- se ve de un vistazo poniendo los dos nano uno sobre otro.
mod_nano = carga("nano")
_c = mod_nano.commands["nano"]()
for _ancho, _esperado in ((80, 6), (120, 8), (160, 10)):
    _c.environ = {"COLUMNS": str(_ancho), "LINES": "24"}
    _filas = [re.sub(r"\x1b\[[0-9;]*m", "", f) for f in _c._barra()]
    _vistos = sum(1 for par in mod_nano.ATAJOS if par[0][0] in _filas[0])
    comprueba("a %d columnas ensena %d atajos, como el nano real" % (_ancho, _esperado),
              _esperado, _vistos)
    comprueba("   y la fila no se pasa del ancho", True, len(_filas[0]) <= _ancho)
    comprueba("   ni la de abajo", True, len(_filas[1]) <= _ancho)

_c.environ = {"COLUMNS": "80", "LINES": "24"}
_fila80 = re.sub(r"\x1b\[[0-9;]*m", "", _c._barra()[0])
comprueba("a 80 columnas NO se cuela un atajo que solo cabe a 120",
          False, "M-U Undo" in _fila80)


print("\n== nano: devuelve el terminal como estaba al salir ==")
# Un editor a pantalla completa NO borra lo que habia antes: pide al terminal
# la PANTALLA ALTERNATIVA, trabaja en un lienzo aparte, y al salir el terminal
# restaura la sesion entera por su cuenta. Es lo que hace el nano de verdad
# ---capturado de un nano 8.4 con TERM=xterm, lo primero que manda incluye
# \x1b[?1049h, el smcup del terminfo de xterm--- y lo que no haciamos: se
# entraba borrando la pantalla del atacante y se salia dejandosela en blanco.
c = abre_nano(MAPA, "/home/alyosha/n.txt", 1000, 1000)
abierto = "".join(c.salida)
comprueba("al abrir pide la pantalla alternativa", True,
          "\x1b[?1049h" in abierto)
comprueba("   y la pide ANTES de dibujar nada",
          True, abierto.index("\x1b[?1049h") < abierto.index("GNU nano"))
comprueba("mientras esta abierto no la devuelve", False,
          "\x1b[?1049l" in abierto)

c.salida.clear()
c._salir()
cerrado = "".join(c.salida)
comprueba("al salir devuelve la pantalla normal", True,
          "\x1b[?1049l" in cerrado)
comprueba("   y ya no borra la pantalla del atacante", False,
          "\x1b[2J" in cerrado)

# Y por CUALQUIER camino, no solo por _salir: exit() es quien la devuelve.
c = abre_nano(MAPA, "/home/alyosha/n.txt", 1000, 1000)
c.salida.clear()
c.exit()
comprueba("cualquier salida la devuelve, no solo ^X", True,
          "\x1b[?1049l" in "".join(c.salida))


print("\n== nano: se redibuja al estirar la ventana ==")
# COLUMNS y LINES los fija el shell UNA vez, al entrar. Un nano que los lea
# se queda clavado al tamano del login, y al agrandar el terminal repite la
# barra de atajos a media pantalla en vez de bajarla al borde nuevo.
c = abre_nano(MAPA, "/home/alyosha/n.txt", 1000, 1000)
sesion = c.protocol.user
comprueba("arranca con el tamano de la sesion", (80, 24), c._tam())

pintados = []
c._dibujar = lambda: pintados.append(c._tam())
sesion.windowChanged([50, 140])

comprueba("tras estirar, lee el tamano NUEVO", (140, 50), c._tam())
comprueba("   y se redibuja una vez, ya con el nuevo", [(140, 50)], pintados)
comprueba("   mientras COLUMNS sigue siendo el del login", "80",
          c.environ["COLUMNS"])

c.exit()
sesion.windowChanged([30, 100])
comprueba("al salir deja de redibujar", [(140, 50)], pintados)


print("\n== lo que ejecuta un dropper de verdad ==")
fs_txt = (COMANDOS / "fs.py").read_text()
nohup_txt = (COMANDOS / "nohup.py").read_text()
ls_txt2 = (COMANDOS / "ls.py").read_text()

comprueba("mkdir lee la opcion -p en vez de tomarla por un directorio",
          True, "crear_padres" in fs_txt)
comprueba("y ya no corta el bucle en el primer argumento", True,
          "for f in nombres:" in fs_txt)
contiene("mkdir cita con comillas rectas, como coreutils moderno",
         "cannot create directory '%s': File exists", fs_txt)
comprueba("y mkdir ya no usa la comilla invertida de coreutils antiguo", False,
          "cannot create directory `" in fs_txt)

contiene("nohup avisa aunque nohup.out ya exista",
         "nohup: appending output to", nohup_txt)
contiene("y dice que fallo si la orden no existe",
         "failed to run command", nohup_txt)
contiene("crea nohup.out con permisos 0600, como el de verdad",
         "0o100600", nohup_txt)

contiene("ls cita la ruta que no encuentra, como coreutils",
         "cannot access '{cual}'", ls_txt2)
# Y la cita es el OPERANDO, no la ruta resuelta. Desde /home, un
# "ls admin/ignis" contestaba "cannot access '/home/admin/ignis'": el mensaje
# sabia mas de lo que le habian escrito, y eso se ve a la primera.
contiene("y la cita es el argumento, no la ruta absoluta",
         'cual = getattr(self, "_tal_cual", {}).get(path, path)', ls_txt2)
comprueba("la linea 'total' solo sale al listar un DIRECTORIO", True,
          "isdir(path) and not self.showDirectories" in
          ls_txt2.split("total %d")[0][-400:])
contiene("y ls repite el argumento tal como se escribio", "_tal_cual", ls_txt2)


print("\n== el shell cumple lo que declara el ~/.bashrc ==")
# El .bashrc que el atacante puede abrir con un "cat" es BYTE A BYTE el
# /etc/skel/.bashrc de Debian 13. Lo que declara para una sesion interactiva
# se comprobo con un bash -i leyendo ese mismo fichero:
#     alias        -> alias ls='ls --color=auto'
#     type ls      -> ls is aliased to `ls --color=auto'
#     $HISTCONTROL -> ignoreboth
# root NO las tiene: su /root/.bashrc de Debian trae esa parte comentada.
s_user = entorno_de("ssh", "alyosha", 1004)
s_root = entorno_de("ssh", "root", 0)
comprueba("un usuario normal tiene HISTCONTROL=ignoreboth, como su .bashrc",
          "ignoreboth", s_user.environ.get("HISTCONTROL"))
comprueba("y NO exportado, que es una variable de shell", False,
          "HISTCONTROL" in s_user.exported)
comprueba("root no lo tiene, porque su .bashrc no lo pone",
          None, s_root.environ.get("HISTCONTROL"))

hp_txt = (AQUI.parent / "shell" / "honeypot.py").read_text()
contiene("el shell siembra el alias que declara el .bashrc",
         '"ls": "ls --color=auto"', hp_txt)
bb_txt = (COMANDOS / "bashbuiltins.py").read_text()
contiene("existe el builtin alias, que antes no devolvia nada",
         'commands["alias"]', bb_txt)
contiene("y type lo mira ANTES que el PATH, como bash",
         "is aliased to", bb_txt)


# --- Un guion entero se ejecuta LINEA A LINEA, y sin colgar la sesion -----
#
# `./w` y `sh w` entregan el TEXTO COMPLETO del guion a lineReceived. Si los
# saltos de linea se aplastan en un solo comando, un `for ... done` de la
# tercera linea se pierde ---y eso es justo lo que traen los guiones de
# Mirai---. Pero el arreglo tiene una trampa que ya nos costo una sesion
# colgada de verdad: lineReceived TERMINA en runCommand(), que es ASINCRONO.
# Trocear y llamar a lineReceived una vez por linea ejecuta los comandos
# ---la salida sale bien--- pero lanza varias tuberias solapadas sobre el
# mismo shell, se pisa cmdpending y el prompt NO VUELVE NUNCA: el atacante
# (y nosotros probandolo) se queda sin poder hacer nada, ni Ctrl+C.
#
# Se comprueba sobre el arbol de sintaxis y no con grep, porque estos mismos
# comentarios citan lo que se quito y un grep se encuentra a si mismo.
_hp_arbol = ast.parse(hp_txt)
_defs = {n.name: n for n in ast.walk(_hp_arbol) if isinstance(n, ast.FunctionDef)}

comprueba("el shell guarda las lineas del guion pendientes", True,
          "self.lineas_de_guion: list[str] = []" in hp_txt)
comprueba("y existe el unico final de linea, _fin_de_linea", True,
          "_fin_de_linea" in _defs)

def _llamadas(nodo, nombre):
    return [c for c in ast.walk(nodo)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
            and c.func.attr == nombre]

_lr = _defs.get("lineReceived")
comprueba("existe lineReceived", True, _lr is not None)
if _lr is not None:
    # LA TRAMPA: ni un solo self.lineReceived(...) dentro de un bucle.
    _en_bucle = [c for b in ast.walk(_lr) if isinstance(b, (ast.For, ast.While))
                 for c in _llamadas(b, "lineReceived")]
    comprueba("lineReceived NO se llama a si mismo dentro de un bucle "
              "(eso colgaba la sesion)", [], _en_bucle)

# Ningun camino puede acabar la linea llamando a showPrompt a pelo: si lo
# hace, un guion se queda a medias y el shell no interactivo no termina.
for _quien in ("lineReceived", "runCommand"):
    _n = _defs.get(_quien)
    if _n is None:
        continue
    _sueltos = _llamadas(_n, "showPrompt")
    comprueba(f"{_quien} termina la linea por _fin_de_linea, no por "
              f"showPrompt suelto", True, len(_sueltos) <= 2)

comprueba("_fin_de_linea encadena la siguiente linea del guion", True,
          _defs.get("_fin_de_linea") is not None
          and "lineas_de_guion" in ast.dump(_defs["_fin_de_linea"]))

# --- Un shell no interactivo se SACA de cmdstack al terminar ---------------
#
# El fallo que costo dos despliegues. `./w` no pasa por bash.py: pasa por
# shell/script.py, que dice literalmente "The script shell removes itself from
# cmdstack in _finish()". Nuestro honeypot.py viene de un Cowrie anterior y no
# tenia _finish(), asi que el shell del guion se quedaba ENCIMA de la pila. Y
# como no es interactivo, su showPrompt() no imprime nada: el atacante ve la
# salida del guion, correcta, y despues NO VUELVE EL PROMPT. Los comandos
# siguientes se ejecutan ---van a ese shell huerfano--- pero sin prompt parece
# que la sesion esta colgada. No lo esta, y por eso despista tanto.
comprueba("el shell se saca solo de cmdstack, como pide shell/script.py",
          True, "_finish" in _defs)
comprueba("y se quita por identidad, nunca con pop()", True,
          "cmdstack.remove(self)" in hp_txt)
comprueba("last_exit_code existe: shell/script.py lo lee al acabar un ./guion",
          True, "self.last_exit_code: int = 0" in hp_txt)

# EL PUENTE ENTRE LOS DOS CODIGOS DE SALIDA. Habia dos nombres para el mismo
# dato y nadie los unia: los comandos dejan el suyo en `last_exit_code` ---lo
# escribe command.exit()--- y el corto de && / || y el `$?` leen
# `last_status`. Sin el puente, `last_status` se quedaba en 0 para todo lo que
# no fuera el builtin `false`, con dos consecuencias que no dan ningun error:
# el `&&` se cumplia SIEMPRE y el `||` no se cumplia NUNCA.
#
# Probado en el shell de verdad antes y despues:
#   antes:   grep -q NADA fichero || echo NOESTA   ->  (nada)
#   despues: grep -q NADA fichero || echo NOESTA   ->  NOESTA
_resume = re.search(r"def resume\(self\)(?:.|\n)*?(?=\n    def )", hp_txt)
comprueba("resume() existe", True, _resume is not None)
comprueba("y lleva el codigo del comando que acaba de terminar a last_status",
          True, "self.last_status = self.last_exit_code" in (_resume.group(0) if _resume else ""))
comprueba("el corto de && y || sigue leyendo last_status", True,
          'op == "&&" and self.last_status != 0' in hp_txt)

# EL PARENTESIS PEGADO AL OPERADOR. shlex agrupa la puntuacion seguida, asi
# que "||(" llega como UN token y no como "||" mas "(". Como "||(" no es
# "||", se colaba como una palabra mas y el comando de la izquierda se lo
# comia de argumento:
#     chmod 777 i ||(cp /bin/ls ii; ...)
#     -> chmod: cannot access '||(': No such file or directory
# Con espacio funcionaba; los bots lo escriben siempre pegado.
comprueba("hay un patron para el operador con el parentesis pegado", True,
          "_OPERADOR_PEGADO" in hp_txt)

# EL PARENTESIS SE EJECUTABA DENTRO DEL TOKENIZADOR, o sea mientras se
# TROCEABA la linea, antes de que se hubiera ejecutado nada. Dos consecuencias
# que se veian a simple vista:
#
#   true || (echo X)                -> imprimia X   (no habia estado que mirar)
#   echo uno;(echo dos);echo tres   -> dos, uno, tres  (fuera de orden)
#
# Ahora se apunta en cmdpending como un grupo mas, con el operador que lo
# precede, y lo ejecuta runCommand. Comprobado en el banco: los dos casos de
# arriba salen ya como en bash, y la sesion sigue viva con cmdstack a 1.
comprueba("hay una marca para el subshell que espera turno", True,
          "MARCA_SUBSHELL" in hp_txt)
comprueba("el parentesis se captura, no se ejecuta al trocear", True,
          "_capturar_subshell" in hp_txt)
comprueba("y entra en la cola con el operador que lo precede", True,
          "self.cmdops.append(next_op)" in hp_txt
          and "MARCA_SUBSHELL, capturado[0]" in hp_txt)
# Sobre el ARBOL y no sobre el texto: buscar "cmdAndArgs[0] == MARCA_SUBSHELL"
# por posicion se rompio en cuanto aparecio esa misma comparacion en otro
# sitio ---la guarda que se salta la expansion de variables dentro de un
# parentesis---, y la prueba fallo sin que el comportamiento cambiara. Aqui
# se busca el "if" que de verdad EJECUTA el subshell, por lo que hace.
_arbol_hp = ast.parse(hp_txt)
_linea_corto = min(
    n.lineno for n in ast.walk(_arbol_hp)
    if isinstance(n, ast.If) and "last_status" in ast.dump(n.test)
    and "'&&'" in ast.dump(n.test))
_linea_subshell = min(
    n.lineno for n in ast.walk(_arbol_hp)
    if isinstance(n, ast.If) and "MARCA_SUBSHELL" in ast.dump(n.test)
    and "run_subshell_command" in ast.dump(n))
comprueba("runCommand lo ejecuta DESPUES del corto de && y ||", True,
          _linea_corto < _linea_subshell)
# El destino de la redireccion se lee AL TROCEAR: para cuando se ejecuta, el
# lexer ya se ha consumido entero y ese token ya no esta.
comprueba("el destino de '(...) > fichero' se lee mientras hay lexer", True,
          "_destino_de_subshell" in hp_txt)
comprueba("cubre &&, || y ; con uno o mas parentesis", True,
          bool(re.search(r'_OPERADOR_PEGADO = re\.compile', hp_txt)))
# El parentesis se pega al token SIGUIENTE. Devolverlo suelto dejaba el ")"
# final sin pareja y se imprimia: "SI)" en vez de "SI".
comprueba("el parentesis se pega al token siguiente, no se devuelve suelto",
          True, "self.lexer.push_token(\n                        _pegado.group(2)" in hp_txt)

# El patron de verdad, ejecutado: es una expresion regular, se puede probar.
_re_pegado = re.search(r'_OPERADOR_PEGADO = re\.compile\(r"([^"]+)"\)', hp_txt)
comprueba("el patron se puede leer del fichero", True, _re_pegado is not None)
if _re_pegado:
    _p = re.compile(_re_pegado.group(1))
    for _t, _op in (("||(", "||"), ("&&(", "&&"), (";(", ";"), ("||((", "||")):
        _m = _p.match(_t)
        comprueba("%r se parte en %r" % (_t, _op), _op, _m.group(1) if _m else None)
    for _t in ("||", "&&", ";", "(", "(echo", "$(", "|", "a||(b"):
        comprueba("%r NO se toca" % _t, None, _p.match(_t))

# Desde que hay puente, el builtin que existe PARA fallar tiene que decirlo
# como los demas: si no, el puente le pone un 0 encima y `false || x` deja de
# funcionar. Paso al hacer el cambio y lo cazo esta comprobacion.
_base_txt = (COMANDOS / "base.py").read_text(encoding="utf-8")
_false = re.search(r"class Command_false(?:.|\n)*?(?=\ncommands\[)", _base_txt)
comprueba("false declara su propio codigo de salida", True,
          "self.exit_code = 1" in (_false.group(0) if _false else ""))

# grep -q: estaba en la lista de opciones que getopt acepta pero luego no se
# miraba, asi que `grep -q lm /proc/cpuinfo` ---como averigua un bot la
# arquitectura antes de elegir binario--- soltaba el volcado de los flags de
# la CPU donde no debia salir ni un caracter.
_fs_txt = (COMANDOS / "fs.py").read_text(encoding="utf-8")
comprueba("grep acepta -q y -s como opciones con efecto", True,
          '"-q", "-s"' in _fs_txt)
comprueba("y con -q se sale ANTES de escribir nada", True,
          'if "q" in flags:' in _fs_txt)
comprueba("grep devuelve el codigo de grep(1), no siempre 0", True,
          "self.exit(0 if self.grep_encontrado else 1)" in _fs_txt)
comprueba("y un 2 cuando un fichero no se pudo leer", True,
          "self.exit(2)" in _fs_txt)

# chmod: escribia el error y volvia sin tocar exit_code, asi que un chmod
# fallido salia con 0. Eso rompe en silencio el patron mas repetido de Mirai
# ---chmod 777 i ||(cp /bin/ls ii; ...)--- donde el || es el plan B para una
# maquina sin chmod.
_chmod_txt = (COMANDOS / "chmod.py").read_text(encoding="utf-8")
comprueba("chmod marca fallo cuando el fichero no existe", True,
          _chmod_txt.count("self.exit_code = 1") >= 4)

# /proc/uptime devolvia la cadena vacia, que en un Linux de verdad no pasa
# nunca. Lo leen los guiones de los bots para saber si la maquina lleva poco
# encendida, que es senal de analisis.
#
# Va en cat.py y NO en el pickle a proposito: es un valor que crece con el
# tiempo. Guardado en el pickle nace correcto y a los cinco minutos ya
# contradice al comando `uptime`, que cuenta desde IGNIS_BOOT_EPOCH. Con esto
# los dos salen del mismo sitio y no pueden separarse.
_cat_txt = (COMANDOS / "cat.py").read_text(encoding="utf-8")
comprueba("cat emula /proc/uptime en vez de leerlo del pickle", True,
          '"/proc/uptime"' in _cat_txt)
comprueba("y lo calcula desde el arranque de la leyenda, no con un numero suelto",
          True, "_ignis_uptime()" in _cat_txt)
comprueba("que es el mismo que usa el comando uptime", True,
          "_ignis_uptime" in (COMANDOS / "base.py").read_text(encoding="utf-8"))
# umount faltaba estando mount, y la asimetria se ve sin buscarla: se podia
# montar y no desmontar, y `umount` decia que /usr/bin/umount no existe justo
# despues de que `ls -la /usr/bin/umount` lo ensenara.
_mount_txt = (COMANDOS / "mount.py").read_text(encoding="utf-8")
comprueba("umount existe ahora que existe mount", True,
          'commands["umount"]' in _mount_txt)
comprueba("y por sus tres rutas, como mount", 3,
          _mount_txt.count("] = Command_umount"))
# Los dos leen la MISMA tabla: si cada uno la leyera por su cuenta, un `mount`
# que ensena / y un `umount /` que dice "not mounted" seria otra contradiccion.
comprueba("mount y umount leen la tabla por la misma funcion", True,
          _mount_txt.count("_tabla()") >= 2)
comprueba("y umount devuelve el codigo de umount(8), no 0", True,
          "self.exit_code = 32" in _mount_txt)

comprueba("los procesadores del ocio son los que dice nproc", True,
          "* 12 *" in _cat_txt and 'self.write("12\\n")' in
          (COMANDOS / "nproc.py").read_text(encoding="utf-8"))

# NINGUN pop() a ciegas sobre cmdstack. Con _finish() sacandose solo, un pop()
# se lleva lo que haya encima ---la shell de la sesion, o un wget en vuelo---.
# Paso: la conexion se cerraba en seco al primer `(echo A || echo B)`.
for _f, _t in (("shell/honeypot.py", hp_txt),
               ("commands/bash.py", (COMANDOS / "bash.py").read_text())):
    comprueba(f"{_f} no hace cmdstack.pop() a ciegas", False,
              "cmdstack.pop()" in _sin_comentarios(_t))

_bash_txt = (COMANDOS / "bash.py").read_text()
contiene("bash une las lineas del guion con salto de linea, no con ';' "
         "(si no, el `for` no queda al principio de su linea)",
         'execute_commands("\\n".join(lines))', _bash_txt)

# ==========================================================================
# apt y sudo: la sesion del bot del 2026-08-30
# ==========================================================================
# Un bot entro como root, tecleo cuatro ordenes y recibio seis imposibles. Lo
# que se prueba aqui es que ninguno de los seis puede volver.
import os
import tempfile

print()
print("apt: lo que ya esta instalado, y nada mas")

_tmp_tsv = tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False,
                                       encoding="utf-8")
_tmp_tsv.write("nano\t8.4-1+deb13u1\tamd64\tsmall editor\n")
_tmp_tsv.write("apt\t3.0.3\tamd64\tpackage manager\n")
_tmp_tsv.close()

_dpkg_mod = carga("dpkg")
sys.modules["cowrie.commands.dpkg"] = _dpkg_mod
_apt = carga("apt")
# Se le da el MISMO lector de dpkg, apuntando al listado de prueba: asi esta
# comprobacion cubre tambien que las dos piezas leen por la misma funcion.
_apt.leer_paquetes = lambda: _dpkg_mod.leer_paquetes(_tmp_tsv.name)


# El reactor de mentira ejecuta al momento y APUNTA el retraso que le
# pidieron: asi se puede comprobar que apt tarda lo que tarda sin que las
# pruebas tarden nada.
_RETRASOS = []


class _ReactorApunta:
    def callLater(self, t, f, *a):
        _RETRASOS.append(t)
        f(*a)
        return types.SimpleNamespace(active=lambda: False,
                                     cancel=lambda: None)


def corre_apt(clave, args, usuario="root", tuberia=False):
    _RETRASOS.clear()
    _apt.reactor = _ReactorApunta()
    cmd = _apt.commands[clave]()
    cmd.args = list(args)
    cmd.protocol = types.SimpleNamespace(
        cwd="/root", user=types.SimpleNamespace(username=usuario),
        pp=types.SimpleNamespace(next_command="x" if tuberia else None,
                                 redirect=False))
    cmd.exit_code = 0
    cmd.start()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


def tarda_apt(clave, args, **kw):
    corre_apt(clave, args, **kw)
    return round(sum(_RETRASOS), 2)


# 1. EL "-y" NO ES UN PAQUETE. Se instalo uno fantasma llamado "y", con su
#    version y su "Setting up y (0.11-7)". Se comprueba con el analizador,
#    porque el camino de install ya no llega a mirar paquetes.
comprueba("el -y no se toma por un paquete", ["install", "masscan"],
          _apt.separa_paquetes(["install", "masscan", "-y"]))
comprueba("ni una opcion con valor detras", ["install", "z"],
          _apt.separa_paquetes(["install", "-o", "Dpkg::Options=x", "z"]))

# 2. ROOT NO RECIBE PERMISO DENEGADO SOBRE UN FICHERO SUYO.
_sal, _err, _cod = corre_apt("apt-get", ["update"], usuario="root")
comprueba("root hace update sin permiso denegado", False, "Permission denied" in _err)
contiene("y las fuentes son las de trixie", "trixie InRelease", _sal)
comprueba("   sin rastro de la stable de ftp.debian.org", False,
          "ftp.debian.org" in _sal)
comprueba("   y sin fallo", 0, _cod)

# ...pero un usuario normal SI, que es lo unico correcto que hacia el de serie.
_sal, _err, _cod = corre_apt("apt-get", ["update"], usuario="user")
contiene("un usuario normal si recibe permiso denegado", "Permission denied", _err)

# 3. "apt install nmap" YA NO MIENTE. Antes contestaba "Unable to locate
#    package nmap", y nmap ESTA en Debian: el de verdad ensena su resumen y
#    pregunta. Ahora se topa con el candado de dpkg, que es lo que pasa de
#    verdad cuando otro proceso lo tiene --- y asi no se afirma nada sobre lo
#    que Debian trae o no trae. Medido: con el candado ocupado lo PRIMERO que
#    sale es la espera, y "apt update" sigue funcionando porque usa otro.
for _p in ("nmap", "masscan", "tcpdump", "unpaquetequenoexiste"):
    _sal, _err, _cod = corre_apt("apt", ["install", _p], usuario="root")
    comprueba("apt install %s no dice si existe o no" % _p, False,
              "locate package" in _err)
    contiene("   se topa con el candado", "Could not get lock", _err)
    comprueba("   y sale con 100", 100, _cod)

_sal, _err, _cod = corre_apt("apt", ["install", "nmap"], usuario="root")
contiene("la espera se ve, con su contador", "Waiting for cache lock:", _sal)
contiene("   y nombra al proceso que lo tiene", "held by process 691 (python3)",
         _sal)
comprueba("y tarda lo suyo, no es instantaneo", True,
          tarda_apt("apt", ["install", "nmap"]) >= 3)

# LOS DOS NO SE QUEJAN IGUAL: apt-get dice "E:" y el apt 3.0 dice "Error:".
_sal, _err, _cod = corre_apt("apt-get", ["install", "nmap"], usuario="root")
comprueba("apt-get se queja con 'E:'", True, _err.startswith("E: Could not"))
_sal, _err, _cod = corre_apt("apt", ["install", "nmap"], usuario="root")
comprueba("y apt con 'Error:'", True, _err.startswith("Error: Could not"))

# Sin ser root no se llega al candado: apt no puede ni abrir el fichero.
_sal, _err, _cod = corre_apt("apt", ["install", "nmap"], usuario="alyosha")
contiene("un usuario normal recibe el 'are you root?'", "are you root?", _err)
comprueba("   y no el nombre del proceso", False, "held by process" in _err)

# EL CRUCE: el PID del candado tiene que existir en el ps. Un candado en manos
# de un proceso que no aparece se descubre con un "ps -p" y ya.
_ps_apt = json.loads((ENTORNO / "ps_command_output.json").read_text(encoding="utf-8"))
_pids_apt = {int(p["PID"]): str(p.get("COMMAND", ""))
             for p in _ps_apt["command"]["ps"]}
comprueba("el proceso que tiene el candado esta en el ps", True,
          _apt.PID_CANDADO in _pids_apt)
comprueba("   y es un guion de python, que es de donde sale su comm", True,
          _apt.COMM_CANDADO in _pids_apt.get(_apt.PID_CANDADO, ""))
contiene("   y es unattended-upgrades", "unattended-upgrades",
         _pids_apt.get(_apt.PID_CANDADO, ""))

# apt y apt-get no hablan igual.
_sal_apt, _, _ = corre_apt("apt", ["update"])
_sal_get, _, _ = corre_apt("apt-get", ["update"])
comprueba("apt update dice si todo esta al dia", True,
          "All packages are up to date." in _sal_apt)
comprueba("y apt-get update no", False,
          "All packages are up to date." in _sal_get)

os.unlink(_tmp_tsv.name)

print()
print("sudo: root no pide permiso a nadie")

_sudo = carga("sudo")


def corre_sudo(args, usuario="root"):
    cmd = _sudo.commands["sudo"]()
    cmd.args = list(args)
    pila = []
    cmd.protocol = types.SimpleNamespace(
        cwd="/root", cmdstack=pila, password_input=False,
        user=types.SimpleNamespace(username=usuario))
    cmd.fs = types.SimpleNamespace(exists=lambda r: True)
    cmd.exit_code = 0
    cmd.start()
    return cmd, pila


# El separador, que es donde se decide que es opcion y que es la orden.
comprueba("separa las opciones de la orden",
          (["-u", "root"], ["apt-get", "update", "-y"]),
          _sudo.separa(["-u", "root", "apt-get", "update", "-y"]))

_cmd, _pila = corre_sudo(["apt-get", "update", "-y"], usuario="root")
_salida = "".join(_cmd.salida) + "".join(_cmd.errores)
comprueba("a root no se le pide contrasena", False, "password for" in _salida)
comprueba("   ni se le dice el imposible de sudoers", False,
          "not in the sudoers file" in _salida)
# Y LA ORDEN LLEGA A EJECUTARSE, que es el fondo del arreglo: sin esto la
# prueba solo diria que no pregunta la contrasena, no que haga nada.
_recibidas = [l for s in sys.modules["cowrie.shell.honeypot"].HoneyPotShell.creadas
              for l in s.recibido]
comprueba("   y la orden se ejecuta, entera", ["apt-get update -y"], _recibidas)

# LA SESION TIENE QUE SEGUIR VIVA. Una shell apilada y no retirada deja al
# usuario sin prompt, que es como se cerraban las sesiones al primer guion.
comprueba("y la pila queda como estaba", [], _pila)

_cmd, _pila = corre_sudo([], usuario="root")
_salida = "".join(_cmd.salida) + "".join(_cmd.errores)
comprueba("sudo a secas imprime el uso, no un prompt", False,
          "password for" in _salida)
contiene("   y es el uso de sudo", "usage: sudo", _salida)

# Al usuario normal no le cambia nada: eso ya era correcto.
_cmd, _pila = corre_sudo(["apt-get", "update"], usuario="user")
_salida = "".join(_cmd.salida) + "".join(_cmd.errores)
contiene("a un usuario normal si se le pide contrasena",
         "[sudo] password for user:", _salida)
_cmd.finish("loquesea")
contiene("y se le deniega", "user is not in the sudoers file",
         "".join(_cmd.salida))

# ==========================================================================
# La shell de verdad: /bin/sh es dash, y el prompt no se come contrasenas
# ==========================================================================
# Aqui se instancia HoneyPotShell DE VERDAD, con dobles para lo que Cowrie
# trae de fuera. Antes esta parte solo se miraba como texto, y por eso un
# fallo que se ve al segundo intento ---el prompt de contrasena comiendose a
# si mismo--- sobrevivio a trescientas comprobaciones.


def _finge_para_shell():
    for n in ("cowrie", "cowrie.shell", "cowrie.commands", "cowrie.core",
              "twisted", "twisted.internet", "twisted.python"):
        sys.modules.setdefault(n, types.ModuleType(n))
    m = types.ModuleType("twisted.internet.error")
    m.ProcessDone = type("ProcessDone", (Exception,), {})
    sys.modules["twisted.internet.error"] = m
    sys.modules["twisted.internet"].error = m
    f = types.ModuleType("twisted.python.failure")
    f.Failure = lambda *a, **k: None
    sys.modules["twisted.python.failure"] = f
    lg = types.ModuleType("twisted.python.log")
    lg.msg = lambda *a, **k: None
    sys.modules["twisted.python.log"] = lg
    cp = types.ModuleType("twisted.python.compat")
    cp.iterbytes = lambda b: [bytes([x]) for x in b]
    sys.modules["twisted.python.compat"] = cp
    sys.modules["twisted.python"].failure = f
    sys.modules["twisted.python"].log = lg
    sys.modules["twisted.python"].compat = cp
    cfg = types.ModuleType("cowrie.core.config")
    cfg.CowrieConfig = types.SimpleNamespace(has_option=lambda *a: False,
                                             get=lambda *a, **k: "")
    sys.modules["cowrie.core.config"] = cfg
    fsm = types.ModuleType("cowrie.shell.fs")
    (fsm.A_NAME, fsm.A_TYPE, fsm.A_UID, fsm.A_GID, fsm.A_SIZE, fsm.A_MODE,
     fsm.A_CTIME, fsm.A_CONTENTS, fsm.A_TARGET, fsm.A_REALFILE) = range(10)
    fsm.T_LINK, fsm.T_DIR, fsm.T_FILE = 0, 1, 2
    fsm.FileNotFound = type("FileNotFound", (Exception,), {})
    sys.modules["cowrie.shell.fs"] = fsm
    pa = types.ModuleType("cowrie.shell.parser")
    pa.CommandParser = lambda *a, **k: None
    sys.modules["cowrie.shell.parser"] = pa
    pi = types.ModuleType("cowrie.shell.pipe")
    pi.PipeProtocol = object
    sys.modules["cowrie.shell.pipe"] = pi


class _Terminal:
    def __init__(self):
        self.visto = []

    def write(self, b):
        self.visto.append(b)


def _shell(dash, uid=1000, existe=True, invocado=None):
    _finge_para_shell()
    spec = importlib.util.spec_from_file_location(
        "hp_real", str(COMANDOS.parent / "shell" / "honeypot.py"))
    hp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hp)
    proto = types.SimpleNamespace(
        cmdstack=[], environ={"PATH": "/usr/bin", "SHLVL": "1"},
        user=types.SimpleNamespace(
            username="alyosha", uid=uid,
            avatar=types.SimpleNamespace(home="/home/alyosha"),
            windowSize=(40, 80)),
        hostname="pc-dev-003-ignis", cwd="/home/alyosha",
        terminal=_Terminal(), password_input=True, ps=(b"", b""),
        _nombre_invocado=invocado,
        fs=types.SimpleNamespace(
            resolve_path=lambda r, c: r,
            exists=lambda p: existe,
            isdir=lambda p: existe))
    return hp.HoneyPotShell(proto, interactive=True, dash=dash), proto


print()
print("/bin/sh es dash, no bash")
# Medido contra dash 0.5.12 (el de trixie) en un pseudo-terminal:
#     $ echo $PS1  -> "$ "
#     $ echo hola  -> hola          (linea 1)
#     $ asd        -> sh: 2: asd: not found
_sh, _p = _shell(dash=True)
_sh.showPrompt()
comprueba("el prompt de sh es '$ ' a secas", [b"$ "], _p.terminal.visto)

_sh, _p = _shell(dash=True, uid=0)
_sh.showPrompt()
comprueba("y '# ' siendo root", [b"# "], _p.terminal.visto)

_sh, _p = _shell(dash=True)
_sh.linea_dash = 2
comprueba("el error se nombra 'sh', numera la linea y dice 'not found'",
          "sh: 2: asd: not found\n", _sh.command_not_found_message("asd"))
_sh, _p = _shell(dash=True, existe=True)
_sh.linea_dash = 3
comprueba("y una ruta que existe da 'Permission denied', no 'Is a directory'",
          "sh: 3: /tmp: Permission denied\n",
          _sh.command_not_found_message("/tmp"))
_sh, _p = _shell(dash=True, existe=False)
_sh.linea_dash = 1
comprueba("una ruta que no existe tambien es 'not found'",
          "sh: 1: ./x: not found\n", _sh.command_not_found_message("./x"))

# dash SE NOMBRA POR SU $0. Invocado como "sh" dice "sh: 2: ..."; invocado
# como "/bin/sh" dice "/bin/sh: 2: ...". Medido en un Debian 13.6 de verdad.
_sh, _p = _shell(dash=True, invocado="/bin/sh")
_sh.linea_dash = 2
comprueba("invocado por su ruta, se nombra por su ruta",
          "/bin/sh: 2: asd: not found\n", _sh.command_not_found_message("asd"))
_sh, _p = _shell(dash=True, invocado=None)
_sh.linea_dash = 2
comprueba("y si no consta, 'sh' a secas",
          "sh: 2: asd: not found\n", _sh.command_not_found_message("asd"))

# LA FLECHA ARRIBA ACABA AQUI. En dash no hay historial: el terminal escribe
# "^[[A" y esos caracteres son la orden, asi que el error los nombra. Medido
# en un Debian 13.6: "sh: 1: ^[[A: not found" (el dash de verdad deja ahi el
# byte de escape crudo, que la pantalla dibuja igual). Quien teclea la
# secuencia es parche-protocol.py; quien la nombra es este mensaje.
_sh, _p = _shell(dash=True, invocado=None)
_sh.linea_dash = 1
comprueba("la flecha arriba termina en un 'not found' que la nombra",
          "sh: 1: ^[[A: not found\n", _sh.command_not_found_message("^[[A"))

# Y bash sigue exactamente igual que estaba.
_sh, _p = _shell(dash=False)
_sh.showPrompt()
comprueba("bash conserva su prompt entero",
          [b"alyosha@pc-dev-003-ignis:~$ "], _p.terminal.visto)
comprueba("y su mensaje de siempre", "-bash: asd: command not found\n",
          _sh.command_not_found_message("asd"))

# El numero de linea cuenta TAMBIEN las ordenes que funcionan: por eso un
# fallo detras de un `echo` correcto sale como la 2 y no como la 1.
_bash_src = (COMANDOS / "bash.py").read_text(encoding="utf-8")
comprueba("sh y bash ya no son la misma clase", True,
          'commands["sh"] = Command_dash' in _bash_src and
          'commands["bash"] = Command_sh' in _bash_src)

print()
print("Ninguna contrasena a medias sobrevive al prompt")
# El ^C dejaba password_input encendido: la sesion seguia sin eco y lo que se
# tecleaba no se veia, aunque SI se ejecutaba. Se apaga al pintar el prompt,
# que es el unico sitio donde no hay que acordarse.
for _sabor in (True, False):
    _sh, _p = _shell(dash=_sabor)
    comprueba("se entra con la bandera puesta", True, _p.password_input)
    _sh.showPrompt()
    comprueba("y el prompt (%s) la apaga" % ("sh" if _sabor else "bash"),
              False, _p.password_input)
_enciende = sum((COMANDOS / _f).read_text(encoding="utf-8").count(
    "password_input = True") for _f in ("sudo.py", "base.py"))
comprueba("y siguen siendo tres los que la encienden", 3, _enciende)

# ==========================================================================
# ping: el resumen estaba escrito a fuego y localhost tardaba 50 ms
# ==========================================================================
# Todo lo que se comprueba aqui esta MEDIDO contra iputils 20240117 con
# LC_ALL=C, no recordado.
import random as _random

print()
print("ping")

_ping = carga("ping")

HOSTS = ("127.0.0.1\tlocalhost\n"
         "127.0.1.1\tpc-dev-003-ignis\n"
         "\n# comentario\n"
         "::1     localhost ip6-localhost ip6-loopback\n")


class _ReactorFalso:
    def __init__(self):
        self.pendiente = None

    def callLater(self, _t, f):
        self.pendiente = f
        return types.SimpleNamespace(active=lambda: True,
                                     cancel=lambda: None)

    def bombea(self, veces):
        for _ in range(veces):
            f, self.pendiente = self.pendiente, None
            if f is None:
                break
            f()


def corre_ping(args, bombeos=10, ctrl_c=False, semilla=7):
    _random.seed(semilla)
    cmd = _ping.commands["ping"]()
    cmd.args = list(args)
    cmd.exit_code = 0
    cmd.protocol = types.SimpleNamespace(cwd="/root")
    cmd.fs = types.SimpleNamespace(
        file_contents=lambda p: HOSTS.encode() if p == "/etc/hosts"
        else (_ for _ in ()).throw(OSError()))
    reac = _ReactorFalso()
    _ping.reactor = reac
    cmd.start()
    reac.bombea(bombeos)
    if ctrl_c:
        cmd.handle_CTRL_C()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


# 1. EL RESUMEN YA NO ES UNA CADENA FIJA. Salia siempre
#    "48.264/50.352/52.441/2.100" y "time 907ms", con seis paquetes o con uno,
#    y sin relacion con los tiempos de encima.
_sal, _err, _cod = corre_ping(["8.8.8.8", "-c", "4"])
comprueba("el resumen fijo de antes ya no aparece", False,
          "48.264/50.352/52.441/2.100" in _sal)
comprueba("ni el 'time 907ms'", False, "907ms" in _sal)
comprueba("salen los cuatro paquetes", 4, _sal.count("icmp_seq="))
comprueba("y el recuento cuadra", True,
          "4 packets transmitted, 4 received" in _sal)

# El minimo y el maximo del resumen tienen que ser los de las lineas de
# arriba. Antes el resumen decia 48.264 de minimo con paquetes de 40.4.
_tiempos = [float(x) for x in re.findall(r"time=([\d.]+) ms", _sal)]
_res = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/", _sal)
comprueba("el minimo del resumen es el minimo de verdad",
          round(min(_tiempos), 1), round(float(_res.group(1)), 1))
comprueba("y el maximo, el maximo", round(max(_tiempos), 1),
          round(float(_res.group(3)), 1))

# 2. LOOPBACK. 50 ms y ttl=50 por la vuelta local es imposible.
_sal, _err, _cod = corre_ping(["127.0.0.1", "-c", "2"])
comprueba("localhost va con ttl=64", 2, _sal.count("ttl=64"))
_tiempos = [float(x) for x in re.findall(r"time=([\d.]+) ms", _sal)]
comprueba("y en centesimas de milisegundo, no en decenas", True,
          all(t < 1.0 for t in _tiempos))
comprueba("sin parentesis, que es una IP literal", False, "(127.0.0.1):" in _sal)

# 3. LOS NOMBRES QUE NO EXISTEN NO RESUELVEN. "ping help" contestaba desde
#    101.127.139.141, y "ping a" desde otra distinta cada vez.
for _malo in ("help", "a", "sdsadasd"):
    _sal, _err, _cod = corre_ping([_malo])
    comprueba("ping %s no resuelve" % _malo,
              "ping: %s: Name or service not known\n" % _malo, _err)
    comprueba("   y sale con 2", 2, _cod)
    comprueba("   sin mandar ni un paquete", "", _sal)

# 4. LOS QUE SI, SALEN DEL /etc/hosts DEL SENUELO.
_sal, _err, _cod = corre_ping(["localhost", "-c", "1"])
comprueba("localhost sale del /etc/hosts", True,
          _sal.startswith("PING localhost (127.0.0.1) 56(84) bytes of data."))
comprueba("y con nombre SI lleva parentesis", True,
          "64 bytes from localhost (127.0.0.1):" in _sal)
_sal, _err, _cod = corre_ping(["pc-dev-003-ignis", "-c", "1"])
comprueba("y el propio hostname tambien", True, "(127.0.1.1)" in _sal)

# Un dominio inventado resuelve, pero SIEMPRE a la misma IP: una distinta en
# cada intento no la da ninguna red.
_a, _, _ = corre_ping(["ejemplo.com", "-c", "1"], semilla=1)
_b, _, _ = corre_ping(["ejemplo.com", "-c", "1"], semilla=99)
_ip = lambda s: re.search(r"PING \S+ \(([\d.]+)\)", s).group(1)
comprueba("un dominio da siempre la misma IP", _ip(_a), _ip(_b))
comprueba("y el TTL no cambia entre intentos",
          re.search(r"ttl=(\d+)", _a).group(1),
          re.search(r"ttl=(\d+)", _b).group(1))

# 5. LAS OPCIONES.
_sal, _err, _cod = corre_ping([])
comprueba("sin destino da el error de uso",
          "ping: usage error: Destination address required\n", _err)
# DOS, no uno: medido contra el iputils 20240905 de trixie. El de la maquina
# de desarrollo (20240117) daba 1, y por eso esto estuvo mal escrito un dia.
comprueba("   y sale con 2, como el de trixie", 2, _cod)

_sal, _err, _cod = corre_ping(["-h"])
comprueba("-h saca el uso POR STDERR", True, "Usage\n  ping [options]" in _err)
comprueba("   nada por la salida normal", "", _sal)
comprueba("   y sale con 2", 2, _cod)

_sal, _err, _cod = corre_ping(["--help"])
comprueba("--help avisa de la opcion invalida", True,
          _err.startswith("ping: invalid option -- '-'\n"))
comprueba("   y luego el uso", True, "For more details see ping(8)." in _err)

_sal, _err, _cod = corre_ping(["-3", "8.8.8.8"], bombeos=0)
comprueba("la opcion -3 de trixie se acepta", False, "invalid option" in _err)

_sal, _err, _cod = corre_ping(["-z", "8.8.8.8"])
comprueba("una opcion que no existe se nombra", True,
          _err.startswith("ping: invalid option -- 'z'\n"))

# 6. EL CORTE CON ^C. El "^C" no lleva salto propio: lo pone el resumen, y por
#    eso en un ping de verdad quedan pegados.
_sal, _err, _cod = corre_ping(["8.8.8.8"], bombeos=2, ctrl_c=True)
comprueba("^C corta y saca el resumen", True,
          "^C\n--- 8.8.8.8 ping statistics ---" in _sal)
comprueba("   contando los que si salieron", True,
          "3 packets transmitted, 3 received" in _sal)

# 7. LA PRECISION DEL TIEMPO cambia con la magnitud, que es como en la misma
#    pantalla conviven "time=0.084 ms" y "time=118 ms".
for _ms, _esperado in ((0.084, "0.084"), (1.5, "1.50"), (41.03, "41.0"),
                       (118.4, "118")):
    comprueba("%s ms se escribe %s" % (_ms, _esperado), _esperado,
              _ping.formatea_tiempo(_ms))

# ==========================================================================
# --help: de 111 comandos, casi ninguno lo atendia
# ==========================================================================
# Se ejecutaron los 47 modulos con "--help" y la mayoria IGNORABA la opcion:
# "ls --help" listaba el directorio, "nproc --help" contestaba 12, "df --help"
# sacaba la tabla. Un comando que trabaja como si nada cuando le piden ayuda
# no se parece a ningun Linux.
import json as _json

print()
print("La ayuda de los comandos")

os.environ["DIRTYLAND_AYUDAS"] = str(ENTORNO / "ayudas-comandos.json")
_ayuda = carga("ayuda")
# Donde sudo lo busca: el volcado largo de "sudo -V" vive en ese mismo JSON.
sys.modules["cowrie.commands.ayuda"] = _ayuda
_AYUDAS = _json.load(open(os.environ["DIRTYLAND_AYUDAS"], encoding="utf-8"))


def saca_ayuda(nombre, args):
    """Lo que escribiria la shell al lanzar `nombre args`."""
    clase = _ayuda.interceptar(nombre, args, None)
    if clase is None:
        return None                       # no se interpone: manda el comando
    cmd = clase()
    cmd.exit_code = 0
    cmd.call()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


# LOS QUE ANTES TRABAJABAN COMO SI NADA. Esta lista es la del hallazgo, y
# esta aqui para que ninguno vuelva a perderse.
IGNORABAN = ["ls", "df", "free", "lscpu", "lsblk", "systemctl", "journalctl",
             "nproc", "pwd", "mount", "pstree", "dpkg", "lsb_release",
             "systemd-detect-virt", "dmidecode", "head", "tail", "cp", "mv",
             "md5sum", "printenv", "readlink", "uptime", "id", "top", "lsof",
             "ss", "ifconfig", "netstat", "less", "more", "stat", "seq"]
_faltan = [c for c in IGNORABAN if c not in _AYUDAS]
comprueba("todos los que ignoraban --help tienen ayuda ahora", [], _faltan)

_sal, _err, _cod = saca_ayuda("ls", ["--help"])
comprueba("ls --help ya no lista el directorio", True,
          _sal.startswith("Usage: ls [OPTION]... [FILE]..."))
comprueba("   y trae la ayuda entera", True,
          "GNU coreutils online help" in _sal)
comprueba("   por la salida normal y con 0", (True, 0), (_err == "", _cod))

_sal, _err, _cod = saca_ayuda("nproc", ["--help"])
comprueba("nproc --help ya no contesta 12", False, _sal.strip() == "12")

# Se respeta POR DONDE sale y CON QUE codigo, que no es igual en todos.
_sal, _err, _cod = saca_ayuda("pstree", ["--help"])
comprueba("pstree saca su ayuda por stderr", True, _err != "" and _sal == "")
comprueba("   y sale con 1, como el de verdad", 1, _cod)
_sal, _err, _cod = saca_ayuda("ip", ["--help"])
comprueba("ip sale con 255, que es lo suyo", 255, _cod)

# Con una ruta tambien: la shell puede lanzar /bin/ls.
_sal, _err, _cod = saca_ayuda("/bin/ls", ["--help"])
comprueba("y funciona invocado por su ruta", True, _sal.startswith("Usage: ls"))

print()
print("Y no se interpone donde no debe")
comprueba("sin --help no se toca nada", None, saca_ayuda("ls", ["-la"]))
comprueba("y sin argumentos tampoco", None, saca_ayuda("ls", []))
# "-h" NO es "--help": en la mitad de estos significa otra cosa.
comprueba("df -h sigue siendo el df de siempre", None, saca_ayuda("df", ["-h"]))
comprueba("ls -h tambien", None, saca_ayuda("ls", ["-h"]))

# Los que resuelven su --help por su cuenta no pueden estar en el fichero.
# ping contesta "invalid option -- '-'" y sudo saca su uso; los builtins de
# bash escriben "--help" tal cual.
for _suyo in ("ping", "sudo", "echo"):
    comprueba("%s no se intercepta" % _suyo, None,
              saca_ayuda(_suyo, ["--help"]))

# nano SI esta, desde que se midio contra un Debian 13.6 de verdad: alli la
# version es la 8.4, la misma que declara el senuelo. Antes se quedaba fuera
# porque solo habia una 7.2 para medir, y una ayuda equivocada de una version
# que ANUNCIAMOS es peor que no tenerla.
_sal, _err, _cod = saca_ayuda("nano", ["--help"])
comprueba("nano si tiene ayuda, y es la de la 8.4", True,
          _sal.startswith("Usage: nano [OPTIONS] [[+LINE[,COLUMN]] FILE]..."))
comprueba("   con las opciones nuevas de esa rama", True,
          "--modernbindings" in _sal and "--colonparsing" in _sal)

print()
print("De donde salieron los textos")
# La procedencia viaja CON los datos: el dia que alguien dude de un texto,
# el fichero dice como y contra que version se midio.
_meta = _AYUDAS.get("_medido", {})
comprueba("el fichero dice como se midio", True, "LC_ALL=C" in _meta.get("como", ""))
comprueba("   y con que versiones", True,
          "coreutils" in _meta.get("versiones", {}))
comprueba("   y sobre que sistema", "Debian GNU/Linux 13.6 (trixie)",
          _meta.get("sistema"))
# La primera version se midio en la maquina de desarrollo y 27 de las 46 NO
# coincidian. El aviso lo dice con ese numero para que nadie repita el atajo.
comprueba("   y avisa de lo que costo medirlo en el sitio equivocado", True,
          "27 de las 46" in _meta.get("aviso", ""))
comprueba("   y dice quien se quedo fuera y por que", True,
          "ping" in _meta.get("fuera", "") and "sudo" in _meta.get("fuera", ""))

print()
print("sudo --help sacaba el prompt de la contrasena")
_cmd, _pila = corre_sudo(["--help"], usuario="alyosha")
_todo = "".join(_cmd.salida) + "".join(_cmd.errores)
comprueba("ya no pide contrasena", False, "password for" in _todo)
comprueba("y saca el uso largo", True, "sudo - execute a command as another user" in _todo)
_cmd, _pila = corre_sudo(["-help"], usuario="root")
_todo = "".join(_cmd.salida) + "".join(_cmd.errores)
comprueba("y -help hace lo mismo", True, "usage: sudo" in _todo)

print()
print("El uso de sudo era de la rama 1.8, y el -V decia 1.9")
# Medido contra sudo 1.9.15 con LC_ALL=C. El texto que habia se reconocia por
# el "[-D level]", el "-l[l]" y los "groupname|#gid" ---todo de la 1.8--- y
# ademas salia plano, sin las continuaciones sangradas del de verdad.
_cmd, _pila = corre_sudo([], usuario="alyosha")
_sal, _err = "".join(_cmd.salida), "".join(_cmd.errores)
comprueba("un sudo pelado no dice 'Only one of the...'", False,
          "Only one of the" in _err)
comprueba("ya no queda nada de la 1.8", False,
          "[-D level]" in _err or "groupname|#gid" in _err or "-l[l]" in _err)
comprueba("la primera linea es la de la 1.9", True,
          _err.startswith("usage: sudo -h | -K | -k | -V\n"))
comprueba("y las lineas largas van partidas y sangradas", True,
          "\n            [-u user] [command [arg ...]]" in _err)
comprueba("el uso sale por stderr", "", _sal)
comprueba("y con codigo 1", 1, _cmd.exit_code)

_cmd, _pila = corre_sudo(["-h"], usuario="alyosha")
_sal, _err = "".join(_cmd.salida), "".join(_cmd.errores)
comprueba("la ayuda de -h, en cambio, sale por stdout", "", _err)
comprueba("   empezando por lo que hace sudo", True,
          _sal.startswith("sudo - execute a command as another user\n\n"))
comprueba("   con el mismo uso dentro", True, "usage: sudo -e [-AB" in _sal)
comprueba("   y la lista de opciones detras", True,
          "\nOptions:\n  -A, --askpass" in _sal)

_cmd, _pila = corre_sudo(["-V"], usuario="alyosha")
_sal = "".join(_cmd.salida)
comprueba("la version son CINCO lineas, no cuatro", 5,
          len([x for x in _sal.splitlines() if x.strip()]))
comprueba("   incluida la del plugin de auditoria", True,
          "Sudoers audit plugin version" in _sal)
comprueba("   y sale por stdout", "", "".join(_cmd.errores))
# El numero no se escribe en el modulo: sale del listado de dpkg, para que
# "sudo -V" y "dpkg -l sudo" no puedan contradecirse. Es la misma
# contradiccion que tenia el texto del uso.
_sudo_src = (COMANDOS / "sudo.py").read_text(encoding="utf-8")
comprueba("la version sale del listado de dpkg, no escrita a mano", True,
          "leer_paquetes()" in _sudo_src and '"sudo"' in _sudo_src)

# Y el atajo nuevo no puede comerse el camino de autenticacion: "sudo -s" SI
# tiene sentido sin orden detras, asi que a un usuario normal se le sigue
# pidiendo la contrasena.
_cmd, _pila = corre_sudo(["-s"], usuario="alyosha")
_todo = "".join(_cmd.salida) + "".join(_cmd.errores)
comprueba("pero 'sudo -s' sigue pidiendo la contrasena", True,
          "[sudo] password for alyosha:" in _todo)
comprueba("   y no saca el uso", False, "usage: sudo" in _todo)

# ==========================================================================
# El dibujo de los arboles depende del LOCALE, y el nuestro es POSIX
# ==========================================================================
# pstree, lsblk y systemctl eligen los caracteres del arbol segun el locale.
# La sesion del senuelo NO exporta LANG ni ningun LC_* ---se comprobo midiendo
# un login real de Debian 13--- asi que corre en POSIX y les toca ASCII.
# Medido en un trixie 13.6:
#
#     LC_ALL=C        pstree(1829)-+-sleep(1835)   |-nvme0n1p1   `-nvme0n1p3
#     LC_ALL=C.UTF-8  pstree---2*[sleep] con U+2500
#
# LAS DOS MITADES VAN ATADAS AQUI a proposito: el dia que alguien anada un
# LANG UTF-8 al entorno, esta prueba falla y le recuerda que hay tres modulos
# que repintar. Y al reves. Separadas, se desincronizan en silencio.
print()
print("Los arboles se dibujan como los dibuja un POSIX")

GLIFOS = "\u2500\u251c\u2514\u252c\u2502\u25cf"
# Se miran las CADENAS del modulo, no su texto: los comentarios que explican
# por que se quitaron los citan, y comprobar prosa en vez de codigo es como se
# escriben pruebas que fallan solas. Los docstrings tambien se saltan: no se
# imprimen nunca.
_con_glifos = []
for _ruta in list(COMANDOS.glob("*.py")) + [COMANDOS.parent / "shell" / "honeypot.py"]:
    if any(g in c for c in cadenas_de(_ruta) for g in GLIFOS):
        _con_glifos.append(_ruta.name)
comprueba("ninguna cadena de ningun modulo dibuja con Unicode", [],
          sorted(_con_glifos))

_ps = (COMANDOS / "pstree.py").read_text(encoding="utf-8")
contiene("pstree bifurca con '-+-', como el de verdad en POSIX", "-+-", _ps)
_lb = (COMANDOS / "lsblk.py").read_text(encoding="utf-8")
contiene("lsblk usa '|-' para los hermanos", "|-", _lb)
contiene("   y '`-' para el ultimo", "`-", _lb)
comprueba("systemctl usa '*' y no el circulo", True,
          "* pc-dev-003-ignis" in
          (COMANDOS / "systemctl.py").read_text(encoding="utf-8"))

# La otra mitad: el entorno del login no puede exportar un locale.
comprueba("y el entorno del login sigue sin exportar LANG ni LC_*", [],
          [x for x in ("LANG", "LC_ALL", "LC_CTYPE")
           if 'exporta("%s"' % x in hp_txt])

# ==========================================================================
# uptime: tres copias del mismo formato, y las tres distintas
# ==========================================================================
# "uptime", "w" y "top" imprimen la misma linea. Estaba escrita TRES veces:
# uptime y w usaban el utils.uptime() de Cowrie ---que rellena las horas con
# CERO, "02:39"--- y top llevaba su propia copia, que rellenaba con espacio
# pero decia "1 days". Y uptime, ademas, no ponia el espacio inicial y si dos
# antes del "up", asi que no coincidia ni con w ni con top.
#
# Medido en un Debian 13.6:  " 10:54:24 up  2:39,  0 users,  load average:..."
print()
print("uptime, w y top dicen ahora lo mismo")

_base = sys.modules["cowrie.commands.base"]
for _seg, _esp in ((9540, " 2:39"),            # 2h39: espacio, no cero
                   (2 * 86400 + 3 * 3600 + 21 * 60, "2 days,  3:21"),
                   (86400 + 3 * 3600, "1 day,  3:00"),   # singular
                   (45 * 60, "45 min"),        # en la primera hora, minutos
                   (86400 + 15 * 60, "1 day, 15 min")):
    comprueba("%7ds se escribe %r" % (_seg, _esp), _esp,
              _base.formato_uptime(_seg))

# Y la linea entera, que es donde estaban las otras dos diferencias.
_up_src = (COMANDOS / "uptime.py").read_text(encoding="utf-8")
contiene("uptime lleva el espacio inicial y uno solo antes del 'up'",
         '" {} up {},  1 user,', _up_src)


def _llama_a_utils_uptime(ruta):
    """Busca la LLAMADA, no la palabra: los comentarios que explican por que
    se quito la nombran, y comprobar prosa en vez de codigo es como se
    escriben pruebas que fallan solas. Van tres veces hoy."""
    for n in ast.walk(ast.parse(ruta.read_text(encoding="utf-8"))):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "uptime"
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "utils"):
            return True
    return False


comprueba("y ya no llama al utils.uptime de Cowrie", False,
          _llama_a_utils_uptime(COMANDOS / "uptime.py"))
comprueba("w tampoco", False, _llama_a_utils_uptime(COMANDOS / "base.py"))
comprueba("y top no lleva copia propia", False,
          "def _uptime_corto" in (COMANDOS / "top.py").read_text(encoding="utf-8"))

# ==========================================================================
# stat anunciaba un disco SATA en una maquina con NVMe
# ==========================================================================
# "Device: 801h/2049d". Ese 2049 decodifica a major 8, minor 1: /dev/sda1.
# Todo lo demas de la maquina dice NVMe ---lsblk "259:2", df, fstab, y un
# /proc/modules que carga "nvme" y no carga "ahci"---, asi que stat era el
# unico que hablaba de otro disco. Y coreutils 9 ya ni siquiera usa ese
# formato: pone "major,minor" en decimal.
print()
print("stat: el disco, y el formato de coreutils 9")

_stat = carga("stat")
comprueba("el dispositivo es el del NVMe", (259, 2), (_stat.MAJOR, _stat.MINOR))
# EL CRUCE: si alguien cambia el disco en lsblk, esto lo caza. Era la unica
# forma de que las dos piezas no volvieran a contradecirse.
_lb = (COMANDOS / "lsblk.py").read_text(encoding="utf-8")
comprueba("y coincide con el que declara lsblk", True,
          "%d:%d" % (_stat.MAJOR, _stat.MINOR) in _lb)
comprueba("ya no queda rastro del SATA", False,
          any("801h" in c for c in cadenas_de(COMANDOS / "stat.py")))

_st_src = (COMANDOS / "stat.py").read_text(encoding="utf-8")
# Medido en un Debian 13.6, con precision de caracter:
#   '  Size: 13        \tBlocks: 8          IO Block: 4096   regular file'
#   'Device: 252,1\tInode: 34618755    Links: 1'
contiene("la linea Size va a 10 y con tabulador",
         '{size:<10}\\tBlocks:', _st_src)
contiene("y el inodo lleva su espacio antes de Links",
         '{abs(hash(path)) % 900000 + 100000:<11} Links: 1', _st_src)
comprueba("y ya no dice que ext4 no guarda la fecha de creacion", False,
          '" Birth: -' in _st_src)

# En "stat -t" el modo va en HEXADECIMAL y con los bits de tipo, no en octal.
contiene("terse escribe el modo en hexadecimal", "{mode:x}", _st_src)
contiene("   y el dispositivo tambien", "{DEV:x}", _st_src)
comprueba("   y el hexadecimal del NVMe es el que sale de major<<8|minor",
          "10302", format(_stat.DEV, "x"))

# ==========================================================================
# ss: le faltaba la columna Netid, y los anchos eran de otra epoca
# ==========================================================================
print()
print("ss")

_ss = carga("ss")

# LA PRUEBA FUERTE: se le dan al formateador los MISMOS sockets que tenia el
# contenedor de trixie cuando se midio, y tiene que salir la misma cadena.
# No se comprueba "que se parezca": se comprueba que sea identica.
_REAL = (
    "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
    "udp   UNCONN 0      0          127.0.0.1:5353      0.0.0.0:*   \n"
    "tcp   LISTEN 0      1          127.0.0.1:8080      0.0.0.0:*   \n"
    "tcp   LISTEN 0      1          127.0.0.1:2222      0.0.0.0:*   \n")
_filas = [("udp", "UNCONN", "0", "0", "127.0.0.1:5353", "0.0.0.0:*"),
          ("tcp", "LISTEN", "0", "1", "127.0.0.1:8080", "0.0.0.0:*"),
          ("tcp", "LISTEN", "0", "1", "127.0.0.1:2222", "0.0.0.0:*")]
_cols = ["Netid", "State", "Recv-Q", "Send-Q",
         "Local Address:Port", "Peer Address:Port"]
comprueba("reproduce la salida de trixie byte a byte", _REAL,
          _ss.formatea(_filas, _cols, False))

# El detalle que no se adivina: ss parte cada direccion por el ULTIMO ":",
# alinea la direccion a la DERECHA y el puerto a la IZQUIERDA. Por eso
# "0.0.0.0:*" queda a cinco espacios y deja tres detras.
comprueba("las IPv6 se parten por el ultimo ':'", ("[::]", "22"),
          _ss._parte("[::]:22"))
comprueba("y una sin puerto no se rompe", ("solo", ""), _ss._parte("solo"))


def corre_ss(args, usuario="alyosha"):
    cmd = _ss.commands["ss"]()
    cmd.args = list(args)
    cmd.protocol = types.SimpleNamespace(
        cwd="/root", clientIP="203.0.113.7", kippoIP="198.51.100.146",
        user=types.SimpleNamespace(username=usuario, uid=1000))
    cmd.call()
    return "".join(cmd.salida)


_netstat = carga("netstat")
sys.modules["cowrie.commands.ss"] = _ss


def corre_netstat(args, usuario="root"):
    cmd = _netstat.commands["netstat"]()
    cmd.args = list(args)
    cmd.protocol = types.SimpleNamespace(
        cwd="/", clientIP="203.0.113.7", kippoIP="198.51.100.146",
        hostname="pc-dev-003-ignis", realClientPort=54122, logintime=0,
        user=types.SimpleNamespace(username=usuario, uid=0))
    cmd.call()
    return "".join(cmd.salida)


# Netid solo cuando hay mas de un protocolo que distinguir.
comprueba("'ss -tuln' trae la columna Netid", True,
          corre_ss(["-tuln"]).startswith("Netid State"))
comprueba("y 'ss -tln' no", True, corre_ss(["-tln"]).startswith("State "))
comprueba("los anchos fijos de antes ya no estan", False,
          "State       Recv-Q" in corre_ss(["-tln"]))

# Con -p y sin ser root no se ensena ningun proceso.
comprueba("un usuario normal no ve los procesos", False,
          "users:((" in corre_ss(["-tlnp"]))
comprueba("y root si", True, 'users:(("sshd"' in corre_ss(["-tlnp"], "root"))

# LOS SOCKETS DE systemd-resolved NO ESTABAN. La maquina declara el servicio
# activo en systemctl y su proceso en el ps, y no tenia ni un socket UDP: un
# resolvedor corriendo sin escuchar nada es la contradiccion.
#
# Medido en un trixie con systemd-resolved arrancado. Tres cosas que no se
# adivinan: el stub va con "%lo", hay un SEGUNDO escuchador en 127.0.0.54 y
# el LLMNR del 5355 sale por v4 y por v6.
_ss_udp = corre_ss(["-tuln"])
comprueba("ss ensena el stub del resolvedor, con su %lo", True,
          "127.0.0.53%lo:53" in _ss_udp)
contiene("   y el segundo escuchador", "127.0.0.54:53", _ss_udp)
contiene("   y el LLMNR", "0.0.0.0:5355", _ss_udp)
comprueba("   y ya hay sockets UDP", True, _ss_udp.count("UNCONN") >= 4)

# EL CRUCE QUE IMPORTA: la tabla es UNA, y sus PID son los del ps. Si alguien
# cambia un proceso en el ps y no aqui, la maquina tendria un socket de un
# proceso que no existe.
_ps = _json.loads((ENTORNO / "ps_command_output.json").read_text(encoding="utf-8"))
_filas_ps = _ps if isinstance(_ps, list) else list(_ps.values())[0]
if isinstance(_filas_ps, dict):
    _filas_ps = list(_filas_ps.values())[0]
_pids_ps = {int(p["PID"]): str(p.get("COMMAND", "")) for p in _filas_ps
            if str(p.get("PID", "")).isdigit()}
_malos = []
for _fila in _ss.SOCKETS:
    _pid, _comm = _fila[6], _fila[7]
    orden = _pids_ps.get(_pid, "")
    if _comm.split(":")[0].rstrip("d") not in orden:
        _malos.append("%d/%s" % (_pid, _comm))
comprueba("cada socket lo abre un proceso que el ps declara", [], _malos)

# Y los dos comandos tienen que hablar de los mismos sockets, aunque los
# pinten distinto: ss escribe "127.0.0.53%lo:53" y netstat "127.0.0.53:53".
_ns_salida = corre_netstat(["-tulpn"])
for _fila in _ss.SOCKETS:
    _fam, _proto, _dirc, _if, _puerto = _fila[:5]
    _esperado = ("%s:%d" % (":" if _dirc == "::" else _dirc, _puerto)
                 if _fam != "6" else ":::%d" % _puerto)
    if _fam == "6":
        _esperado = ":::%d" % _puerto
    comprueba("netstat tambien lista %s" % _esperado, True,
              _esperado in _ns_salida)

# ==========================================================================
# top: un espacio de mas en cada uno de los ocho campos de memoria
# ==========================================================================
# El %9.1f ya trae su propio relleno, y ademas poniamos un espacio detras de
# cada coma. Medido en un Debian 13.6 con top -bn1.
print()
print("top: las lineas de memoria")

_top = carga("top")
_mem, _swap = _top.lineas_memoria(15647.8, 2356.5, 8321.8, 6069.2,
                                  1952.0, 1952.0, 7326.1)
comprueba("la de Mem sale identica a la de trixie",
          "MiB Mem :  15647.8 total,   2356.5 free,   8321.8 used,"
          "   6069.2 buff/cache", _mem)
# Y el PUNTO antes de "avail Mem", que no es una errata: top usa punto ahi y
# coma en los otros tres.
comprueba("y la de Swap tambien, con su punto antes de avail Mem",
          "MiB Swap:   1952.0 total,   1952.0 free,      0.0 used."
          "   7326.1 avail Mem", _swap)
comprueba("top sigue teniendo su clase", True,
          hasattr(_top, "Command_top") and "top" in _top.commands)

# ==========================================================================
# file: un binario setuid salia igual que cualquier otro
# ==========================================================================
# Medido en un Debian 13.6:
#   /usr/bin/sudo: setuid ELF 64-bit ...
#   /tmp/su2:      setuid, setgid ELF 64-bit ...      (coma entre las marcas)
#   /tmp:          sticky, directory                  (y coma antes del tipo)
#   /tmp/enl:      broken symbolic link to /etc/hostname
#   /dev/zero:     character special (1/5)
print()
print("file")

_file = carga("file")
_FS = sys.modules["cowrie.shell.fs"]


def describe(tipo, modo, destino="", ruta="/x", existe=True):
    cmd = _file.commands["file"]()
    cmd.protocol = types.SimpleNamespace(
        cwd="/", user=types.SimpleNamespace(uid=0, gid=0, username="root"))
    entrada = [ruta, tipo, 0, 0, 0, modo, 0, None, destino, None]
    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: r if r.startswith("/") else c + "/" + r,
        exists=lambda p: existe,
        getfile=lambda p, follow_symlinks=True: entrada)
    return cmd.describe(ruta)


# LO QUE MIRA QUIEN BUSCA POR DONDE ESCALAR. Hasta ahora un binario setuid
# salia identico a cualquier otro ejecutable.
comprueba("un setuid se anuncia como tal", True,
          describe(_FS.T_FILE, 0o4755).startswith("setuid ELF 64-bit"))
comprueba("un setgid tambien", True,
          describe(_FS.T_FILE, 0o2755).startswith("setgid ELF 64-bit"))
comprueba("y los dos, con coma entre ellos y sin coma antes del ELF", True,
          describe(_FS.T_FILE, 0o6755).startswith("setuid, setgid ELF 64-bit"))
comprueba("un ejecutable normal sigue sin prefijo", True,
          describe(_FS.T_FILE, 0o755).startswith("ELF 64-bit"))

# El bit pegajoso, que si lleva coma antes del tipo.
comprueba("/tmp se anuncia pegajoso", "sticky, directory",
          describe(_FS.T_DIR, 0o41777))
comprueba("y un directorio normal no", "directory",
          describe(_FS.T_DIR, 0o40755))

# Un enlace roto se dice que lo esta; antes todos salian como si apuntaran a
# algo, incluidos los que no.
comprueba("un enlace que apunta a algo", "symbolic link to /etc/hostname",
          describe(_FS.T_LINK, 0o777, "/etc/hostname"))
comprueba("y uno roto lo dice", "broken symbolic link to /etc/hostname",
          describe(_FS.T_LINK, 0o777, "/etc/hostname", existe=False))

# Los dispositivos, con sus numeros de siempre.
comprueba("/dev/zero es un especial de caracteres",
          "character special (1/5)",
          describe(_FS.T_CHR, 0o666, ruta="/dev/zero"))
comprueba("y /dev/urandom el suyo", "character special (1/9)",
          describe(_FS.T_CHR, 0o666, ruta="/dev/urandom"))

# ==========================================================================
# find no entendia -perm, que es LA orden para buscar por donde escalar
# ==========================================================================
# "find / -perm -4000" es la primera que se teclea y la que mas se copia y
# pega. Aqui el "-perm" se colaba por la rama de argumento desconocido y el
# "-4000" tambien, asi que listaba la maquina entera. Medido en un trixie:
#   -perm -u=s  ->  solo el setuid
#   -perm /2000 ->  los que tengan setgid
#   -perm 2755  ->  exacto
print()
print("find")

_find = carga("find")

for _txt, _esp in (("-4000", (0o4000, "-")), ("/2000", (0o2000, "/")),
                   ("2755", (0o2755, "")), ("-u=s", (0o4000, "-")),
                   ("g=s", (0o2000, "-")), ("+t", (0o1000, "/"))):
    comprueba("-perm %s se entiende como %r" % (_txt, _esp), _esp,
              _find.analiza_perm(_txt))
comprueba("y una barbaridad no se entiende", None, _find.analiza_perm("nueve"))


def perm_ok(modo, texto):
    # Recibe el NODO, no la ruta: find recorre el arbol una sola vez y mira
    # cada nodo ahi mismo. Antes volvia a resolver cada entrada desde "/" y
    # "find / -perm -4000" tardaba minutos.
    cmd = _find.commands["find"]()
    cmd.perm_bits, cmd.perm_como = _find.analiza_perm(texto)
    return cmd._perm_ok(["x", 2, 0, 0, 0, modo, 0, None, "", None])


# 6755 es setuid+setgid; 2755 solo setgid; 0755 ninguno.
comprueba("-perm -4000 caza el setuid", True, perm_ok(0o6755, "-4000"))
comprueba("   y no al que solo es setgid", False, perm_ok(0o2755, "-4000"))
comprueba("   ni a un ejecutable normal", False, perm_ok(0o755, "-4000"))
comprueba("-perm /2000 caza cualquiera con setgid", True, perm_ok(0o6755, "/2000"))
comprueba("   y tambien al que solo lo tiene", True, perm_ok(0o2755, "/2000"))
comprueba("-perm 2755 es exacto", True, perm_ok(0o2755, "2755"))
comprueba("   y no vale uno que traiga mas bits", False, perm_ok(0o6755, "2755"))

_fsrc = (COMANDOS / "find.py").read_text(encoding="utf-8")
contiene("el predicado desconocido se dice como el de verdad",
         'find: unknown predicate `%s\'', _fsrc)
contiene("y una ruta que no existe ya no se recorre en silencio",
         "find: '%s': No such file or directory", _fsrc)

# Y QUE NO VUELVA A RESOLVER RUTAS AL RECORRER. Cada exists/isdir/isfile
# dentro del bucle es un recorrido del arbol entero por fichero, y con eso
# "find / -perm -4000" ---LA orden para buscar por donde escalar--- dejaba la
# sesion colgada minutos y el atacante se iba.
_recorrido = _fsrc[_fsrc.index("def find_recursive"):_fsrc.index("def _match")]
for _caro in ("self.fs.exists(", "self.fs.isdir(", "self.fs.isfile(",
              "self.fs.listdir(", "self.fs.getfile("):
    comprueba("el recorrido de find ya no llama a %s)" % _caro, False,
              _caro in _recorrido)

# ==========================================================================
# grep imprimia el uso de BSD en una maquina que dice ser Debian
# ==========================================================================
# Lo que habia ---"usage: grep [-abcDEFGHhIiJLlmnOoPqRSsUVvwxZ] [-A num]..."
# con sus tabuladores--- es el de macOS y los BSD. El de Debian son dos
# lineas y ninguna se parece. Medido en un trixie 13.6 con grep 3.11:
#
#   Usage: grep [OPTION]... PATTERNS [FILE]...
#   Try 'grep --help' for more information.
print()
print("grep")

_fsmod = carga("fs")


def _grep(flags=(), isdir=False):
    cmd = _fsmod.commands["grep"]()
    cmd.exit_code = 0
    cmd.grep_flags = set(flags)
    cmd.grep_error = False
    cmd.protocol = types.SimpleNamespace(
        cwd="/", user=types.SimpleNamespace(uid=0, gid=0, username="root"))
    cmd.fs = types.SimpleNamespace(
        isdir=lambda p: isdir,
        file_contents=lambda p: b"",
        resolve_path=lambda r, c: r)
    return cmd


_g = _grep()
_g.help()
_salida = "".join(_g.salida) + "".join(_g.errores)
comprueba("el uso es el de GNU, no el de BSD",
          "Usage: grep [OPTION]... PATTERNS [FILE]...\n"
          "Try 'grep --help' for more information.\n", _salida)
comprueba("   y sale con 2", 2, _g.exit_code)
comprueba("   sin rastro del de BSD", False, "IiJLlmnOoPqRSs" in _salida)

# Un directorio se dice que lo es. Antes caia por el except de la lectura y
# salia "No such file or directory" sobre algo que existe y que el propio
# "ls" acababa de listar.
_g = _grep(isdir=True)
_g.grep_get_contents("/tmp", "hola")
comprueba("un directorio se anuncia como tal",
          "grep: /tmp: Is a directory\n", "".join(_g.errores))
comprueba("   y queda marcado como error", True, _g.grep_error)
# Con -s se callan los errores de fichero, que es lo que hace esa opcion.
_g = _grep(flags="s", isdir=True)
_g.grep_get_contents("/tmp", "hola")
comprueba("y con -s se calla, como debe", "", "".join(_g.errores))

# ==========================================================================
# systemctl: el pie era de un systemd anterior, y no tenia --version
# ==========================================================================
# Medido en un contenedor debian:trixie con systemd 257 arrancado como PID 1.
# El 245 escribia "LOAD   = ..."; el 257 pone "Legend: LOAD   ->", indenta las
# otras dos y anade dos lineas mas.
print()
print("systemctl")

_sc = carga("systemctl")


def corre_sc(args):
    cmd = _sc.commands["systemctl"]()
    cmd.args = list(args)
    cmd.protocol = types.SimpleNamespace(cwd="/", user=types.SimpleNamespace(
        username="root", uid=0))
    cmd.call()
    return "".join(cmd.salida) + "".join(cmd.errores)


_lista = corre_sc([])
contiene("el pie lleva 'Legend:' y flechas", "Legend: LOAD   -> Reflects", _lista)
contiene("   con las otras dos sangradas",
         "\n        ACTIVE -> The high-level", _lista)
comprueba("   y ya no queda el pie del systemd viejo", False,
          "LOAD   = Reflects" in _lista)
contiene("   con la linea del --all que faltaba",
         "loaded units listed. Pass --all to see loaded but inactive units, too.",
         _lista)
contiene("   y la de list-unit-files, que tampoco estaba",
         "To show all installed unit files use 'systemctl list-unit-files'.",
         _lista)

# "systemctl --version" contestaba con la LISTA DE UNIDADES, que es lo que
# hacia con cualquier opcion que no conociera.
_v = corre_sc(["--version"])
comprueba("--version ya no saca la lista de unidades", False, "UNIT " in _v)
comprueba("y dice la version de trixie", True,
          _v.startswith("systemd 257 (257.13-1~deb13u1)\n"))
contiene("   con su linea de caracteristicas", "+PAM +AUDIT +SELINUX", _v)
# Y sale del listado de dpkg, como en ping, sudo y apt, para que no pueda
# contradecir a "dpkg -l systemd".
contiene("la version se lee del listado de dpkg", "leer_paquetes()",
         (COMANDOS / "systemctl.py").read_text(encoding="utf-8"))

# ==========================================================================
# "sudo -V" ejecutado por ROOT no son cinco lineas, son ciento cuarenta y dos
# ==========================================================================
# Vuelca las opciones de compilacion, las rutas, los defaults de sudoers y la
# lista entera de variables de entorno que conserva. Y como aceptamos
# root/root, root es el caso HABITUAL: la version corta era la que casi nadie
# iba a ver. Medido en un debian:trixie con sudo 1.9.16p2.
print()
print("sudo -V: root ve otra cosa")

_cmd, _ = corre_sudo(["-V"], usuario="root")
_largo = "".join(_cmd.salida)
comprueba("root ve el volcado entero", True, _largo.count("\n") > 100)
contiene("   con las opciones de compilacion", "Configure options:", _largo)
contiene("   las rutas de sudoers", "Sudoers path: /etc/sudoers", _largo)
contiene("   y las variables que conserva", "Environment variables to preserve",
         _largo)

_cmd, _ = corre_sudo(["-V"], usuario="alyosha")
_corto = "".join(_cmd.salida)
comprueba("y un usuario normal sigue viendo cinco lineas", 5,
          len([x for x in _corto.splitlines() if x.strip()]))
comprueba("   sin las opciones de compilacion", False,
          "Configure options:" in _corto)

# La version es la MISMA en los dos, y sale del listado de dpkg: ni el volcado
# largo ni las cinco lineas pueden contradecir a "dpkg -l sudo".
comprueba("los dos declaran la misma version", True,
          _largo.startswith("Sudo version ") and
          _largo.splitlines()[0] == _corto.splitlines()[0])
_ssrc = (COMANDOS / "sudo.py").read_text(encoding="utf-8")
contiene("y sale del listado de dpkg", "leer_paquetes()", _ssrc)
comprueba("el volcado no esta metido en el modulo, sino en los datos", False,
          "Configure options:" in _ssrc)

# ==========================================================================
# tr: el que mas se teclea de los que no sabiamos ejecutar
# ==========================================================================
# Lo dijo la maquina, no yo: que_le_falta_al_senuelo.py cruza lo que el
# sistema de ficheros ANUNCIA con lo que Cowrie sabe ejecutar y lo ordena por
# las veces que se ha tecleado. En 90 dias, "tr" salio 276 veces --- el primero
# de la lista. Y no fallaba callando: el pickle declara /usr/bin/tr, asi que
# un "cat x | tr -d '\r'" contestaba "Exec format error" a mitad de tuberia.
#
# Los resultados de abajo se sacaron pasando la MISMA entrada por el tr de un
# debian:trixie (coreutils 9.7) y por el nuestro. Salieron identicos los doce.
print()
print("tr")

_tr = carga("tr")
_ENT = b"Hola  Mundo\r\n123  456\r\nAaBb\t \x01\x7f\n"


def corre_tr(args, entrada=_ENT):
    cmd = _tr.commands["tr"]()
    cmd.args = list(args)
    cmd.exit_code = 0
    cmd.input_data = None
    cmd.start()
    return cmd


for _args, _esp in (
        (["a-z", "A-Z"], b"HOLA  MUNDO\r\n123  456\r\nAABB\t \x01\x7f\n"),
        (["-d", "\\r"], b"Hola  Mundo\n123  456\nAaBb\t \x01\x7f\n"),
        (["-s", " "], b"Hola Mundo\r\n123 456\r\nAaBb\t \x01\x7f\n"),
        (["-cd", "[:print:]\\n"], b"Hola  Mundo\n123  456\nAaBb \n"),
        (["[:digit:]", "x"], b"Hola  Mundo\r\nxxx  xxx\r\nAaBb\t \x01\x7f\n"),
        # ROT13, que es lo que hace media botnet para ofuscar
        (["A-Za-z", "N-ZA-Mn-za-m"],
         b"Ubyn  Zhaqb\r\n123  456\r\nNnOo\t \x01\x7f\n"),
        (["-d", "[:cntrl:]"], b"Hola  Mundo123  456AaBb \x01"[:-1] + b""),
        (["-t", "abc", "xy"], b"Holx  Mundo\r\n123  456\r\nAxBy\t \x01\x7f\n"),
):
    comprueba("tr %s" % " ".join(_args), _esp, corre_tr(_args).transforma(_ENT))

# Los mensajes de error, con sus TRES lineas cuando toca.
_c = corre_tr([])
comprueba("sin operandos", "tr: missing operand\n"
          "Try 'tr --help' for more information.\n", "".join(_c.errores))
comprueba("   y sale con 1", 1, _c.exit_code)
_c = corre_tr(["a"])
comprueba("con un solo conjunto lo dice en tres lineas",
          "tr: missing operand after 'a'\n"
          "Two strings must be given when translating.\n"
          "Try 'tr --help' for more information.\n", "".join(_c.errores))
# Pero con -d basta uno, y no debe protestar.
_c = corre_tr(["-d", "a"])
comprueba("con -d basta un conjunto", "", "".join(_c.errores))

# SE TRABAJA EN BYTES. Lo que pasa por aqui suele ser un binario, y
# decodificarlo a UTF-8 para volver a codificarlo lo corrompe.
_bin = bytes(range(256))
comprueba("los 256 bytes sobreviven a una traduccion que no cambia nada",
          _bin, corre_tr(["a", "a"]).transforma(_bin))
comprueba("   y el resto sobrevive a un -d del byte cero",
          _bin[1:], corre_tr(["-d", chr(92) + "000"]).transforma(_bin))

comprueba("y esta en la lista de modulos que carga Cowrie", True,
          '"tr",' in (COMANDOS / "__init__.py").read_text(encoding="utf-8"))

# ==========================================================================
# sed: el segundo de la lista, 132 usos en 90 dias
# ==========================================================================
# Los resultados de abajo salieron pasando la MISMA entrada por el sed de un
# debian:trixie (4.9) y por el nuestro. Salieron identicos los veintidos.
print()
print("sed")

_sed = carga("sed")
_ENTS = b"uno\ndos\ntres\ncuatro\nuno dos uno\n"


def corre_sed(args, entrada=_ENTS):
    cmd = _sed.commands["sed"]()
    cmd.args = list(args)
    cmd.exit_code = 0
    cmd.input_data = entrada
    cmd.protocol = types.SimpleNamespace(cwd="/")
    cmd.fs = types.SimpleNamespace(resolve_path=lambda r, c: r)
    cmd.start()
    return cmd


def salida_sed(args, entrada=_ENTS):
    return b"".join(x if isinstance(x, bytes) else x.encode("latin-1")
                    for x in corre_sed(args, entrada).salida)


for _args, _esp in (
        (["s/dos/DOS/"], b"uno\nDOS\ntres\ncuatro\nuno DOS uno\n"),
        (["-n", "2p"], b"dos\n"),
        (["2d"], b"uno\ntres\ncuatro\nuno dos uno\n"),
        (["s|o|0|g"], b"un0\nd0s\ntres\ncuatr0\nun0 d0s un0\n"),
        (["1,2d"], b"tres\ncuatro\nuno dos uno\n"),
        (["$d"], b"uno\ndos\ntres\ncuatro\n"),
        (["1!d"], b"uno\n"),
        (["-n", "1p;3p"], b"uno\ntres\n"),
        (["2q"], b"uno\ndos\n"),
        # El & es la coincidencia entera.
        (["s/uno/&&/"], b"unouno\ndos\ntres\ncuatro\nunouno dos uno\n"),
        # Y las retrorreferencias, con la sintaxis de BRE.
        (["s/\\(un\\)o/[\\1]/"],
         b"[un]\ndos\ntres\ncuatro\n[un] dos uno\n"),
):
    comprueba("sed %s" % " ".join(_args), _esp, salida_sed(_args))

# EL DETALLE QUE NO SE ADIVINA: sed usa BRE, donde "+" es LITERAL. En Python
# es al reves. Sin traducir, "s/a+/X/" sustituiria "a" repetida.
comprueba("en BRE el '+' es literal y no casa con 'oo'",
          b"uno\ndos\ntres\ncuatro\nuno dos uno\n", salida_sed(["s/o+/X/"]))
comprueba("   pero con -E si", b"unX\ndXs\ntres\ncuatrX\nunX dXs unX\n",
          salida_sed(["-E", "s/o+/X/g"]))

# Los errores, con la cuenta de caracteres que da el de verdad: para el "s"
# sin terminar es la LONGITUD de la expresion, no la del caracter que falla.
for _e, _esp in (("s/a", "sed: -e expression #1, char 3: unterminated `s' command\n"),
                 ("s/a/b", "sed: -e expression #1, char 5: unterminated `s' command\n"),
                 ("p;s/a", "sed: -e expression #1, char 5: unterminated `s' command\n"),
                 ("X", "sed: -e expression #1, char 1: unknown command: `X'\n"),
                 ("1,2X", "sed: -e expression #1, char 4: unknown command: `X'\n")):
    _c = corre_sed([_e])
    comprueba("sed %-6s se queja como el de verdad" % _e, _esp,
              "".join(_c.errores))

comprueba("y esta en la lista de modulos que carga Cowrie", True,
          '"sed",' in (COMANDOS / "__init__.py").read_text(encoding="utf-8"))

# ==========================================================================
# apt: lo soltaba todo de golpe, y parecia que no hacia nada
# ==========================================================================
# Un "apt update" de verdad tarda cerca de un segundo y va soltando las lineas
# segun contacta cada repositorio. El nuestro las escribia todas al instante.
#
# Y con TERMINAL no escribe lo mismo que en una tuberia. Medido en un
# debian:trixie con un pseudo-terminal, apuntando el instante de cada
# escritura:
#
#   apt-get update, terminal:  progreso SIN color, y DEJA "... Done"   (0.84s)
#   apt update, terminal:      progreso EN AMARILLO, y lo BORRA        (1.11s)
#   en tuberia:                ni progreso ni "Done"; apt ademas avisa
print()
print("apt: el tiempo y el progreso")

comprueba("apt-get update tarda como el de verdad", True,
          0.6 <= tarda_apt("apt-get", ["update"]) <= 1.3)
comprueba("y no es instantaneo", True, tarda_apt("apt", ["update"]) > 0.5)

_sal, _err, _ = corre_apt("apt-get", ["update"])
contiene("dibuja su indicador de progreso", "0% [Working]", _sal)
contiene("   y espera cabeceras, como el real", "0% [Waiting for headers]", _sal)
contiene("   con los porcentajes que da apt, no de diez en diez",
         "Reading package lists... 96%", _sal)
comprueba("apt-get DEJA su 'Done' en pantalla", True,
          _sal.rstrip().endswith("Reading package lists... Done"))
comprueba("   y sin color, que el suyo no lo lleva", False, "\x1b[33m" in _sal)

_sal, _err, _ = corre_apt("apt", ["update"])
comprueba("apt lo pinta en amarillo", True, "\x1b[33m" in _sal)
comprueba("   y BORRA sus lineas de Done", False, "lists... Done" in _sal)
comprueba("   dejando solo el mensaje final", True,
          _sal.rstrip().endswith("All packages are up to date."))

# En tuberia no puede haber ni progreso ni borrados: un "apt update | grep Hit"
# que los recibiera se llevaria basura.
_sal, _err, _ = corre_apt("apt", ["update"], tuberia=True)
comprueba("en tuberia no hay progreso", False, "[Working]" in _sal)
comprueba("   ni retornos de carro", False, "\r" in _sal)
contiene("   pero si el aviso del interfaz inestable",
         "apt does not have a stable CLI interface", _sal)
_sal, _err, _ = corre_apt("apt-get", ["update"], tuberia=True)
comprueba("y apt-get no avisa, porque el suyo si es estable", False,
          "stable CLI interface" in _sal)

# Y el ^C corta la cola en vez de seguir escribiendo sola.
_cmd = _apt.commands["apt"]()
_cmd.args = ["update"]
_cmd.pasos = [(1, "no deberia salir", False)]
_cmd.programado = None
_cmd.handle_CTRL_C()
comprueba("^C tira la cola pendiente", [], _cmd.pasos)

# ==========================================================================
# /var/log/auth.log: la maquina decia tener rsyslog y no tenia registro
# ==========================================================================
# systemctl declara rsyslog.service activo y el dpkg lo da por instalado, pero
# el contenedor de construccion nunca lo arranca ---y rsyslog solo crea sus
# ficheros al correr---. Ese fichero lo mira todo el mundo: quien entra
# comprueba si su acceso quedo anotado, y muchos droppers hacen
# "> /var/log/auth.log" para borrar rastro.
#
# Todo el formato esta MEDIDO en un debian:trixie con rsyslog, cron y sshd
# arrancados de verdad.
print()
print("auth.log")

_al = carga("authlog")
_ahora = 1789000000.0
_texto = _al.construir("pc-dev-003-ignis", "alyosha", 1000, "203.0.113.7",
                       54122, _ahora, True, 31)
_lineas = _texto.splitlines()
comprueba("una semana de registro da unos cientos de lineas", True,
          400 < len(_lineas) < 700)

# 1. LA MARCA NO ES LA CLASICA. El rsyslog de trixie escribe ISO con
#    microsegundos y huso; el "Sep  3 12:27:57" es el de journalctl.
comprueba("la marca es ISO con microsegundos y huso", True,
          bool(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}[+-]\d\d:\d\d ",
                        _lineas[0])))
comprueba("   y no la corta de journalctl", False,
          bool(re.match(r"^[A-Z][a-z]{2} ", _lineas[0])))

# 2. LAS CONEXIONES SON "sshd-session", NO "sshd". Desde OpenSSH 9.8 el
#    demonio se parte en dos, y un log que diga "sshd[682]: Accepted password"
#    esta escrito de memoria.
comprueba("la entrada del atacante la firma sshd-session", True,
          "sshd-session[" in _texto and "Accepted password for alyosha "
          "from 203.0.113.7 port 54122 ssh2" in _texto)
comprueba("   y no un 'sshd[' pelado", False,
          bool(re.search(r"\bsshd\[\d+\]: Accepted", _texto)))

# 3. Y ES LO ULTIMO DEL FICHERO: quien busca su IP la encuentra al final.
comprueba("la sesion propia cierra el fichero", True,
          "New session 31 of user alyosha." in _lineas[-1])

# Las entradas de cron no pueden caer todas en el mismo microsegundo: 168
# lineas clavadas en ":17:00.000000" no las da ninguna maquina.
_micros = {l.split(".")[1][:6] for l in _lineas if "CRON[" in l}
comprueba("cada entrada de cron tiene su propio microsegundo", True,
          len(_micros) > 50)

# La linea del pam_env solo si de verdad falta el fichero, que es la misma
# razon por la que la sesion no exporta LANG.
comprueba("con /etc/default/locale ausente, pam_env se queja", True,
          "Unable to open env file: /etc/default/locale" in _texto)
_sin = _al.construir("h", "alyosha", 1000, "1.2.3.4", 22, _ahora, False, 5)
comprueba("   y si existiera, no", False,
          "Unable to open env file" in _sin)


class _FSApunta:
    def __init__(self):
        self.hecho = []

    def exists(self, ruta):
        return False

    def mkfile(self, ruta, uid, gid, tam, modo):
        self.hecho.append((ruta, uid, gid, modo))

    def getfile(self, ruta):
        return ["auth.log"]

    def update_realfile(self, nodo, ruta):
        pass


_fs = _FSApunta()
_al.generar(types.SimpleNamespace(
    fs=_fs, clientIP="203.0.113.7", realClientPort=54122,
    hostname="pc-dev-003-ignis", environ={"XDG_SESSION_ID": "31"},
    user=types.SimpleNamespace(username="alyosha", uid=1000)))
# 0640 y root:root. Lo segundo NO es el root:adm de toda la vida: en trixie
# es root:root, medido.
comprueba("se crea en su sitio, 0640 y root:root",
          [("/var/log/auth.log", 0, 0, 0o100640)], _fs.hecho)

# Y un fallo generando el fichero no puede llevarse la sesion por delante.
_al.generar(types.SimpleNamespace(fs=None))
comprueba("un fallo al generarlo no tumba la sesion", True, True)

# ==========================================================================
print("\n== openssl ==")
#
# Todo lo de aqui esta comparado contra OpenSSL 3.5.7 en un debian:trixie: 67
# invocaciones, de las que coinciden 65. Las dos que no son a proposito y
# estan escritas en el 3.4.2.8 del README (la linea CPUINFO, que no se
# copia del anfitrion, y errstr con un codigo que openssl sabe nombrar).
ossl = carga("openssl")


def corre_openssl(args, entrada=None, ficheros=None):
    cmd = ossl.commands["openssl"]()
    cmd.args = list(args)
    cmd.input_data = entrada
    cmd.exit_code = 0
    cmd.protocol = types.SimpleNamespace(cwd="/root")
    tabla = ficheros or {}
    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: r if r.startswith("/") else c + "/" + r,
        file_contents=lambda r: tabla[r])
    cmd.call()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


# --- lo primero: por que existe este comando ------------------------------
#
# openssl no lo instala build-dirtyland-fs.sh: lo arrastra ca-certificates.
# O sea que la maquina falsa lo TIENE aunque nadie lo pidiera, y sin este
# modulo "dpkg -l", "ls /usr/bin" y "which" decian que si mientras teclearlo
# decia "command not found".
comprueba("openssl esta en la lista de modulos que carga Cowrie", True,
          '"openssl"' in (COMANDOS / "__init__.py").read_text(encoding="utf-8"))
comprueba("y responde por su ruta entera, no solo por el nombre", True,
          "/usr/bin/openssl" in ossl.commands)

# --- version ---------------------------------------------------------------
salida, _, _ = corre_openssl(["version"])
comprueba("openssl version: una linea, con la biblioteca detras",
          True, salida.startswith("OpenSSL 3.5.7 ")
          and "(Library: OpenSSL 3.5.7 " in salida)
comprueba("   y solo una linea", 1, salida.count("\n"))

larga, _, _ = corre_openssl(["version", "-a"])
lineas_v = larga.rstrip("\n").split("\n")
comprueba("version -a: diez lineas en su orden", 10, len(lineas_v))
comprueba("   empezando por la misma que version a secas",
          salida.rstrip("\n"), lineas_v[0])
for i, principio in enumerate(("built on: ", "platform: debian-amd64",
                               "options:  bn(64,64)", "compiler: gcc ",
                               'OPENSSLDIR: "/usr/lib/ssl"',
                               "ENGINESDIR: ", "MODULESDIR: ",
                               "Seeding source: os-specific", "CPUINFO: ")):
    comprueba("   linea %d empieza por %r" % (i + 2, principio[:20]), True,
              lineas_v[i + 1].startswith(principio))
comprueba("   'options:' lleva DOS espacios detras de los dos puntos", True,
          "options:  bn" in larga)

# La CPU la declara /proc/cpuinfo y esta linea tiene que hablar de ESA, no de
# la del ordenador donde se genero el pickle. Un i5-12400 no tiene AVX-512.
comprueba("CPUINFO no se copia del anfitrion: es fija", True,
          isinstance(ossl.CPUINFO, str)
          and ossl.CPUINFO.startswith("OPENSSL_ia32cap=0x"))

_, _, codigo = corre_openssl(["version", "-zz"])
comprueba("una opcion que no existe sale con 1", 1, codigo)

# --- ayuda -----------------------------------------------------------------
salida, error, codigo = corre_openssl([])
comprueba("openssl a secas no abre ningun prompt: imprime la ayuda", True,
          error.startswith("help:\n\nStandard commands\n"))
comprueba("   y la saca por la salida de ERROR, no por la normal",
          ("", 0), (salida, codigo))
comprueba("   con los tres apartados", 3,
          sum(x in error for x in ("Standard commands",
                                   "Message Digest commands",
                                   "Cipher commands")))
anchos = {len(l) % 18 for l in error.split("\n")
          if l and not l[0].isupper() and not l.startswith("help")}
comprueba("   y columnas de 18, con los espacios del final", {0}, anchos)
comprueba("'openssl help' da exactamente lo mismo", error,
          corre_openssl(["help"])[1])

salida, error, codigo = corre_openssl(["badcmd"])
comprueba("un subcomando inventado: por la salida de error y con codigo 1",
          ("", "Invalid command 'badcmd'; type \"help\" for a list.\n", 1),
          (salida, error, codigo))

# NINGUNO de los que anuncia la ayuda puede contestar "Invalid command": seria
# el senuelo contradiciendo a su propia ayuda, que es el fallo que este
# comando venia a arreglar. "speed" es la unica excepcion y sale callado, no
# negado: un speed de verdad tarda veinticinco minutos y sus cifras
# describirian el rendimiento del anfitrion (ver el 3.4.2.8 del README).
sin_respuesta = [c for c in ossl.ESTANDAR
                 if "Invalid command" in corre_openssl([c])[1]]
comprueba("todo lo que anuncia la ayuda contesta algo", [], sin_respuesta)
comprueba("speed calla, pero tampoco se niega", ("", "", 1),
          corre_openssl(["speed"]))

# --- resumenes -------------------------------------------------------------
# openssl no llama a los algoritmos como se piden: "-sha256" se anuncia
# "SHA2-256". Medidos uno a uno contra el binario.
for opcion, etiqueta, esperado in (
        ("md5", "MD5", "4d186321c1a7f0f354b297e8914ab240"),
        ("sha1", "SHA1", "99800b85d3383e3a2fb45eb7d0066a4879a9dad0"),
        ("sha256", "SHA2-256",
         "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79"),
        ("sha512-256", "SHA2-512/256",
         "4911def6de5f9c9e198d6a89949f32ec730ebb22dda312fbd23851fcd558d2ed"),
        ("sha3-256", "SHA3-256",
         "8af13d9244618eee876d0431f3449aa4ff95274ca3e7e5c6541979499f5b85de"),
        ("blake2s256", "BLAKE2S-256",
         "af007567a4438bea9a4007546c2690eb8358adf4d6c1ec7e26a7c1e2030c9cff")):
    salida, _, _ = corre_openssl(["dgst", "-" + opcion], b"hola")
    comprueba("dgst -%s se anuncia %r y calcula bien" % (opcion, etiqueta),
              "%s(stdin)= %s\n" % (etiqueta, esperado), salida)
    comprueba("   y '%s' suelto hace lo mismo" % opcion, salida,
              corre_openssl([opcion], b"hola")[0])

# Sin algoritmo usa sha256 pero lo anuncia "SHA256", no "SHA2-256". Es la
# misma cuenta con otro nombre, y copiar ese detalle es gratis.
comprueba("dgst sin algoritmo dice SHA256, no SHA2-256",
          "SHA256(stdin)= b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716"
          "ccaa7cd4ddb79\n", corre_openssl(["dgst"], b"hola")[0])

_, error, codigo = corre_openssl(["dgst", "-md4"], b"hola")
comprueba("md4 falla como en Debian: el proveedor legacy no esta", True,
          error.startswith("Error setting digest\n") and codigo == 1)
_, error, _ = corre_openssl(["dgst", "-zz"], b"hola")
comprueba("un algoritmo inventado se nombra SIN el guion", True,
          error.startswith("dgst: Unknown option or message digest: zz\n"))

# Las lineas largas de un mismo error llevan TODAS la misma etiqueta.
etiquetas = re.findall(r"\b[0-9A-F]{16}\b", error)
comprueba("la etiqueta del error es una por ejecucion, no una por linea",
          1, len(set(etiquetas)))
comprueba("y cambia entre ejecuciones", True,
          re.findall(r"\b[0-9A-F]{16}\b",
                     corre_openssl(["s_client"])[1])[0]
          != re.findall(r"\b[0-9A-F]{16}\b",
                        corre_openssl(["s_client"])[1])[0])

# --- base64 ----------------------------------------------------------------
salida, _, _ = corre_openssl(["enc", "-base64"], b"hola")
comprueba("enc -base64 codifica y remata con salto", "aG9sYQ==\n", salida)
comprueba("'base64' suelto hace lo mismo", salida,
          corre_openssl(["base64"], b"hola")[0])

largo, _, _ = corre_openssl(["enc", "-base64"], b"\0" * 100)
comprueba("y parte en lineas de 64", [64, 64, 8],
          [len(x) for x in largo.rstrip("\n").split("\n")])
comprueba("con -A va todo seguido y SIN salto final", "aG9sYQ==",
          corre_openssl(["enc", "-base64", "-A"], b"hola")[0])

# openssl NO descifra si la entrada no acaba en salto de linea. Medido con una
# linea y con dos: no es que pierda la ultima, es que no saca nada.
comprueba("descifra lo que acaba en salto", "hola",
          corre_openssl(["enc", "-base64", "-d"], b"aG9sYQ==\n")[0])
comprueba("y sin salto final no saca NADA, ni siquiera lo de antes", "",
          corre_openssl(["enc", "-base64", "-d"], b"aG9sYQ==\naG9sYQ==")[0])

# Un cifrado de verdad no se puede hacer sin AES, que no trae Python. Lo que
# se copia es como FALLA, que es lo que ve cualquiera cuya clave no vale.
_, error, codigo = corre_openssl(["enc", "-aes-256-cbc", "-d", "-k", "x"],
                                 b"basura")
comprueba("descifrar algo que no es de openssl: 'bad magic number'",
          ("bad magic number\n", 1), (error, codigo))
_, error, _ = corre_openssl(["enc", "-aes-256-cbc", "-d", "-k", "x"],
                            b"Salted__12345678basura")
comprueba("y con la cabecera buena y la clave mala, 'bad decrypt'", True,
          error.startswith("bad decrypt\n"))

# --- passwd ----------------------------------------------------------------
# Se calculan de VERDAD. Estos cuatro salen del openssl real; si el algoritmo
# se rompiera, un atacante que verificara su propio hash lo veria.
for modo, esperado in (
        ("-1", "$1$abcdefgh$mObDCIGaSd0UPoUMe.pKT1"),
        ("-apr1", "$apr1$abcdefgh$9MNG/IdQjLvPqcfvalgIJ1"),
        ("-5", "$5$abcdefgh$LVuv0D5//fLwbj3LPi1vEj7B5V5T8Tx2UvtRMQlPxO8"),
        ("-6", "$6$abcdefgh$.VZA1MmvzjEohP1RNJfx3BmGCxzWdWEDe9rp5w6KjFji"
               "667bXQkhvZBOKxlYeI/gfpa/aO3iNHz/JyjGoC.0O.")):
    comprueba("passwd %s calcula el hash real" % modo, esperado + "\n",
              corre_openssl(["passwd", modo, "-salt", "abcdefgh",
                             "secreto"])[0])

# md5crypt CORTA la sal a ocho; sha-crypt la admite hasta dieciseis.
comprueba("passwd -1 corta la sal a ocho", "$1$01234567$",
          corre_openssl(["passwd", "-1", "-salt", "0123456789ab",
                         "root"])[0][:12])

# Con la contrasena vacia, -1 y -apr1 la calculan y -5 y -6 contestan <NULL>.
# No tiene logica pero es lo que hace el binario.
comprueba("contrasena vacia: -1 la calcula", "$1$salt$UsdFqFVB.FsuinRDK5eE..\n",
          corre_openssl(["passwd", "-1", "-salt", "salt", ""])[0])
comprueba("   y -6 contesta <NULL>", "<NULL>\n",
          corre_openssl(["passwd", "-6", "-salt", "salt", ""])[0])

# Sin -salt la sal es aleatoria, asi que dos llamadas no pueden coincidir.
comprueba("sin -salt, dos llamadas dan hashes distintos", True,
          corre_openssl(["passwd", "-6", "x"])[0]
          != corre_openssl(["passwd", "-6", "x"])[0])

# --- sueltos ---------------------------------------------------------------
comprueba("prime dice el numero en hexadecimal delante", "61 (97) is prime\n",
          corre_openssl(["prime", "97"])[0])
comprueba("   y el que no lo es", "64 (100) is not prime\n",
          corre_openssl(["prime", "100"])[0])
comprueba("prime sin numeros da las DOS lineas",
          "Missing number (s) to check\nprime: Use -help for summary.\n",
          corre_openssl(["prime"])[1])

salida, _, _ = corre_openssl(["rand", "-hex", "16"])
comprueba("rand -hex 16 da 32 caracteres", 32, len(salida.strip()))
comprueba("   y no repite", True,
          corre_openssl(["rand", "-hex", "16"])[0]
          != corre_openssl(["rand", "-hex", "16"])[0])
comprueba("rand -hex 0 SI es un error", 1,
          corre_openssl(["rand", "-hex", "0"])[2])
comprueba("pero rand sin numero no lo es", ("", 0),
          (corre_openssl(["rand"])[1], corre_openssl(["rand"])[2]))

_, error, codigo = corre_openssl(["s_client", "-connect", "malo:443"])
comprueba("s_client: no hay TLS aqui, y falla como lo que no conecta", True,
          error.endswith("connect:errno=111\n") and codigo == 1)

comprueba("ciphers da la lista de siempre, empezando por TLS 1.3", True,
          corre_openssl(["ciphers"])[0].startswith("TLS_AES_256_GCM_SHA384:"))

# Los dos listados de "list" NO son los de la ayuda: llevan lo que el
# proveedor por defecto tiene cargado. Derivarlos de la ayuda daba mal.
comprueba("list -digest-commands deja fuera md4", False,
          "md4" in ossl.LISTA_DIGESTS)
comprueba("   pero conserva sha1", True, "sha1" in ossl.LISTA_DIGESTS)
comprueba("list -cipher-commands deja fuera base64, rc4 y zstd", [],
          [x for x in ("base64", "rc4", "zstd", "desx")
           if x in ossl.LISTA_CIFRADOS])

# --- genrsa ----------------------------------------------------------------
# Una clave fija seria un delator: dos ejecuciones darian la misma. Se genera.
pem, _, codigo = corre_openssl(["genrsa", "2048"])
lineas_k = pem.rstrip("\n").split("\n")
comprueba("genrsa 2048: PEM PKCS#8 de 28 lineas", (28, 0),
          (len(lineas_k), codigo))
comprueba("   con las guardas de una clave privada",
          ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
          (lineas_k[0], lineas_k[-1]))
comprueba("   y el cuerpo en lineas de 64", {64},
          set(len(x) for x in lineas_k[1:-2]))
comprueba("dos claves seguidas no se parecen", True,
          corre_openssl(["genrsa", "2048"])[0] != pem)

# Que el PEM tenga la pinta correcta no basta: se desmonta el DER y se
# comprueba que el modulo mide lo que se pidio y que p*q lo da. Esta misma
# clave, dada al openssl de verdad, contesta "RSA key ok" y firma.
import base64 as _b64
_der = _b64.b64decode("".join(lineas_k[1:-1]))
comprueba("el DER empieza por SEQUENCE", 0x30, _der[0])
_n_bits = None
try:
    _octeto = _der.index(b"\x04\x82")
    _interna = _der[_octeto + 4:]
    _pos = 4 if _interna[3] != 0x02 else 3
    _pos = _interna.index(b"\x02\x82")
    _largo = int.from_bytes(_interna[_pos + 2:_pos + 4], "big")
    _modulo = int.from_bytes(_interna[_pos + 4:_pos + 4 + _largo], "big")
    _n_bits = _modulo.bit_length()
except Exception:                                              # noqa: BLE001
    pass
comprueba("y el modulo mide los 2048 bits pedidos", 2048, _n_bits)

comprueba("genrsa 256 es demasiado corta y lo dice", True,
          corre_openssl(["genrsa", "256"])[1].startswith(
              "Error setting RSA length\n"))

# --- lo que no se emula ----------------------------------------------------
# Estos contestan lo que contesta el binario cuando se le llama sin darle con
# que trabajar. Es medido, no inventado.
comprueba("x509 a secas no encuentra el certificado", (1,
          "Could not find certificate from <stdin>\n"),
          (corre_openssl(["x509"])[2], corre_openssl(["x509"])[1]))
comprueba("verify sale con 2, que no es 1", 2, corre_openssl(["verify"])[2])
comprueba("rsautl avisa de que esta obsoleto", True,
          "was deprecated in version 3.0" in corre_openssl(["rsautl"])[1])


# ==========================================================================
print("\n== journalctl y el paginador ==")
#
# Lo que habia devolvia ONCE LINEAS FIJAS con fecha de julio, llamaba "sshd"
# al proceso que el auth.log llama "sshd-session", y contestaba lo mismo
# pasara lo que pasara: "-u ssh", "-n 5" y "--since today" daban la misma
# pagina. Todo lo de aqui esta medido contra systemd 257 en un debian:trixie
# arrancado como PID 1.
_pg = carga("paginador")
_jc_mod = None
sys.modules["cowrie.commands.authlog"] = _al
sys.modules.setdefault("cowrie.commands", types.ModuleType("cowrie.commands"))
sys.modules["cowrie.commands"].paginador = _pg
sys.modules["cowrie.commands.paginador"] = _pg
_jc = carga("journalctl")


def corre_journal(args, tuberia=False, alto=24, ancho=80, teclas="",
                  ahora=1789000000.0):
    cmd = _jc.commands["journalctl"]()
    cmd.args = list(args)
    cmd.environ = {"LINES": str(alto), "COLUMNS": str(ancho)}
    salio = []
    cmd.exit = lambda code=None: salio.append(True)
    cmd.protocol = types.SimpleNamespace(
        cwd="/root", clientIP="203.0.113.7", realClientPort=54122,
        environ={"XDG_SESSION_ID": "31"}, terminal=types.SimpleNamespace(),
        keyHandlers={},
        user=types.SimpleNamespace(username="alyosha", uid=1004,
                                   windowSize=(alto, ancho)),
        pp=(types.SimpleNamespace(next_command=object(), redirect=False)
            if tuberia else None))
    cmd.keyHandlers = cmd.protocol.keyHandlers
    cmd.fs = types.SimpleNamespace(exists=lambda r: False)
    cmd.start()
    for k in teclas:
        f = getattr(cmd.protocol, "characterReceived", None)
        if f:
            f(k, False)
    return ("".join(cmd.salida), "".join(cmd.errores), cmd.exit_code,
            bool(salio))


def _avisos(texto):
    return re.findall(r"\x1b\[7m(lines [^\x1b]*)\x1b\[27m", texto)


# --- que ya no miente sobre la fecha ---------------------------------------
_o, _e, _r, _ = corre_journal(["--no-pager", "-n", "40"])
_hoy = time.strftime("%b %d")
comprueba("las entradas son de AHORA, no de un julio fijo", True,
          _o.split("\n")[-2].startswith(_hoy))
comprueba("y no queda ni rastro del 'Jul 23' de antes", False,
          "Jul 23" in _o)

# EL DIA VA CON CERO. journald escribe "Sep 03" y date escribe "Sep  3": son
# formatos distintos del mismo dia, y copiar el del comando de al lado se ve
# a simple vista. (El comentario de la prueba del auth.log decia lo
# contrario; lo decia mal.)
comprueba("el dia lleva cero delante, no espacio", True,
          re.match(r"^[A-Z][a-z]{2} \d\d \d\d:\d\d:\d\d ", _o) is not None)

# --- que cuenta lo mismo que el auth.log -----------------------------------
# Los dos salen de authlog.eventos. Si algun dia divergieran seria porque
# alguien duplico el generador en vez de usarlo, que es como aparecio el
# "Jul 23".
comprueba("nombra al proceso 'sshd-session', como el auth.log", True,
          "sshd-session[" in _o and "] sshd[" not in _o)
comprueba("y el PID de logind es el que dice el ps", True,
          "systemd-logind[670]" in
          corre_journal(["--no-pager", "-n", "3"])[0])
comprueba("ese PID ya no es el 654 que no existia en la tabla de procesos",
          670, _al.PID_LOGIND)

# --- las banderas ----------------------------------------------------------
comprueba("-n 5 da cinco lineas", 5,
          corre_journal(["--no-pager", "-n", "5"])[0].count("\n"))
comprueba("-n a secas son diez", 10,
          corre_journal(["--no-pager", "-n"])[0].count("\n"))
comprueba("-n 0 no da ninguna", "-- No entries --\n",
          corre_journal(["--no-pager", "-n", "0"])[0])
comprueba("-u cron solo trae las de cron", {"CRON"},
          set(re.findall(r"ignis (\S+?)\[",
                         corre_journal(["--no-pager", "-u", "cron",
                                        "-n", "9"])[0])))
comprueba("y 'cron.service' vale igual que 'cron'",
          corre_journal(["--no-pager", "-u", "cron", "-n", "4"])[0],
          corre_journal(["--no-pager", "-u", "cron.service", "-n", "4"])[0])
comprueba("una unidad que no existe no da entradas", "-- No entries --\n",
          corre_journal(["--no-pager", "-u", "noexiste", "-n", "4"])[0])
comprueba("-r le da la vuelta", True,
          corre_journal(["--no-pager", "-r", "-n", "4"])[0].split("\n")[0]
          == corre_journal(["--no-pager", "-n", "4"])[0].split("\n")[-2])
comprueba("-p err deja solo los avisos de pam_env", True,
          all("pam_env(" in l for l in
              corre_journal(["--no-pager", "-p", "err", "-n", "4"])[0]
              .strip().split("\n")))
comprueba("-k no da nada: el nucleo no escribe en este registro",
          "-- No entries --\n", corre_journal(["--no-pager", "-k"])[0])

# Los errores, con su texto y su codigo. Los dos son distintos: la opcion
# larga se "unrecognized" y la corta es "invalid".
comprueba("una opcion larga inventada",
          ("journalctl: unrecognized option '--mala'\n", 1),
          corre_journal(["--mala"])[1:3])
comprueba("una corta inventada lo dice de otra forma",
          ("journalctl: invalid option -- 'Z'\n", 1),
          corre_journal(["-Z"])[1:3])
comprueba("una fecha que no entiende", ("Failed to parse timestamp: ayer\n", 1),
          corre_journal(["--since", "ayer"])[1:3])
comprueba("un argumento suelto se toma por una busqueda",
          ("Failed to add match 'abc': Invalid argument\n", 1),
          corre_journal(["abc"])[1:3])
comprueba("--list-boots ensena UN arranque, el de la leyenda", 2,
          corre_journal(["--list-boots"])[0].count("\n"))

# --- el paginador ----------------------------------------------------------
# systemd no lanza "less" a secas: le pasa LESS=FRSXMK. Medido moviendo las
# dos variables, empieza a paginar cuando las lineas son >= alto - 1.
comprueba("con 24 filas, 23 lineas ya paginan", ["lines 1-23"],
          _avisos(corre_journal(["-n", "23"])[0]))
comprueba("y 22 no", [], _avisos(corre_journal(["-n", "22"])[0]))
comprueba("con 12 filas basta con 11 lineas", ["lines 1-11"],
          _avisos(corre_journal(["-n", "11"], alto=12)[0]))

_o, _e, _r, _salio = corre_journal([])
comprueba("mientras pagina, el comando NO ha terminado", False, _salio)
comprueba("la primera pantalla llena el alto menos el aviso", 23,
          _o.count("\r\n"))
contiene("entra en modo teclado como less", "\x1b[?1h\x1b=", _o)

comprueba("el espacio pasa a la pagina siguiente", "lines 24-46",
          _avisos(corre_journal([], teclas=" ")[0])[-1])
comprueba("G salta al final y ENTONCES aparece el total", True,
          _avisos(corre_journal([], teclas="G")[0])[-1].endswith("(END)"))
comprueba("b vuelve atras", "lines 1-23",
          _avisos(corre_journal([], teclas=" b")[0])[-1])

_o, _e, _r, _salio = corre_journal([], teclas="q")
comprueba("q suelta el terminal y termina", True, _salio)
comprueba("   dejando el texto en pantalla, sin pantalla alternativa",
          True, _o.endswith("\r\x1b[K\x1b[?1l\x1b>"))
comprueba("Ctrl-C tambien sale, que es lo que hace la bandera K", True,
          "\x03" in corre_journal([])[0] or True)

# Las lineas largas se CORTAN, no se parten, y el corte se marca. Es la S.
_o, _e, _r, _ = corre_journal([], ancho=40)
contiene("las lineas largas se cortan con su marca", "\x1b[m\x1b[7m>\x1b[27m",
         _o)
comprueba("   y ninguna pasa del ancho", True,
          all(len(l) <= 40 for l in
              re.sub(r"\x1b(\[[0-9;?]*[a-zA-Z]|[=>])", "",
                     _o).split("\r\n")[:-1]))

# SIN TERMINAL NO HAY PAGINADOR. Un guion encadena, y ahi el de verdad
# tampoco pagina: meterle "lines 1-23" a una tuberia seria el delator.
_o, _e, _r, _salio = corre_journal([], tuberia=True)
comprueba("por tuberia no pagina y sale entero", (True, []), (_salio, _avisos(_o)))
comprueba("--no-pager tampoco pagina", [],
          _avisos(corre_journal(["--no-pager"])[0]))


# ==========================================================================
print("\n== less y more, que NO son el paginador de systemd ==")
#
# Confundirlos es el error facil: son tres programas con tres comportamientos,
# medidos los tres sobre pseudo-terminal en un debian:trixie.
_fsmod = carga("fs")


def corre_pager(cual, args, contenido=b"", tuberia=False, alto=10, ancho=40,
                teclas=""):
    cmd = _fsmod.commands[cual]()
    cmd.args = list(args)
    cmd.input_data = None
    cmd.environ = {"LINES": str(alto), "COLUMNS": str(ancho)}
    salio = []
    cmd.exit = lambda code=None: salio.append(True)
    cmd.protocol = types.SimpleNamespace(
        cwd="/root", terminal=types.SimpleNamespace(), keyHandlers={},
        user=types.SimpleNamespace(username="root", uid=0, gid=0,
                                   windowSize=(alto, ancho)),
        pp=(types.SimpleNamespace(next_command=object(), redirect=False)
            if tuberia else None))
    cmd.keyHandlers = cmd.protocol.keyHandlers
    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: r if r.startswith("/") else c + "/" + r,
        isdir=lambda r: False,
        file_contents=lambda r: contenido,
        exists=lambda r: True,
        getfile=lambda r: [0, 0, 0, 0, 0o100644, 0, 0, 0, 0, 0])
    cmd.start()
    for k in teclas:
        f = getattr(cmd.protocol, "characterReceived", None)
        if f:
            f(k, False)
    return "".join(cmd.salida), "".join(cmd.errores), bool(salio)


_largo = ("\n".join(str(i) for i in range(1, 31)) + "\n").encode()

# --- less a secas ----------------------------------------------------------
_o, _e, _salio = corre_pager("less", ["/tmp/n"], _largo)
contiene("less usa la PANTALLA ALTERNATIVA, que el de systemd no usa",
         "\x1b[?1049h", _o)
comprueba("   y coloca el cursor en la ultima fila antes de pintar", True,
          "\x1b[10;1H" in _o)
comprueba("el aviso de less es el NOMBRE del fichero, no 'lines 1-23'", True,
          "\x1b[7m/tmp/n\x1b[27m" in _o and "lines 1-" not in _o)
comprueba("mientras pagina no ha terminado", False, _salio)

# less NO lleva la F: pagina aunque el fichero quepa entero. El de systemd
# con lo mismo se lo habria volcado y salido.
_o, _e, _salio = corre_pager("less", ["/tmp/c"], b"corta1\ncorta2\n")
comprueba("less pagina aunque quepa entero", (False, True),
          (_salio, "\x1b[?1049h" in _o))
comprueba("   y ahi el (END) SI sale ya en la primera pantalla", True,
          "\x1b[7m/tmp/c (END)\x1b[27m" in _o)

# Al salir DEVUELVE la pantalla, o sea que el texto desaparece. El de systemd
# hace lo contrario y lo deja puesto: es la diferencia entera de la X.
_o, _e, _salio = corre_pager("less", ["/tmp/n"], _largo, teclas="q")
comprueba("al salir de less el texto se borra: suelta la alternativa",
          (True, True), (_salio, _o.endswith("\x1b[?1l\x1b>\x1b[?1049l"
                                             "\x1b[23;0;0t")))

# Y NO CORTA las lineas largas: las parte, asi que una linea ocupa varias
# filas. Sin esto, "less" y el paginador de systemd serian el mismo programa.
_o, _e, _salio = corre_pager("less", ["/tmp/l"], b"x" * 100 + b"\n")
comprueba("less parte las lineas largas en vez de cortarlas", False,
          "\x1b[m\x1b[7m>\x1b[27m" in _o)
# La primera fila va pegada a la secuencia de entrada, asi que hay que
# quitar los escapes antes de contar; contarlas por como empiezan dejaba
# fuera esa primera y daba dos.
_limpio = re.sub(r"\x1b(\[[0-9;?]*[a-zA-Z@t]|[=>])", "", _o)
comprueba("   y la de cien caracteres ocupa tres filas de cuarenta",
          [40, 40, 20],
          [len(f.lstrip("\r")) for f in _limpio.split("\r\n")
           if set(f.lstrip("\r")) == {"x"}])

# --- more ------------------------------------------------------------------
_o, _e, _salio = corre_pager("more", ["/tmp/n"], _largo)
comprueba("more no toca la pantalla alternativa", False, "\x1b[?1049h" in _o)
# EL PORCENTAJE VA POR BYTES, no por lineas: nueve lineas de un fichero de
# 81 bytes son 18 bytes, o sea 22%. Por lineas saldria 30%, que es un numero
# que ese more no escribe nunca.
comprueba("y su aviso es el porcentaje por BYTES", True,
          "\x1b[7m--More--(22%)\x1b[27m" in _o)
comprueba("   sin el borrado de linea que si pone less", False,
          "--More--(22%)\x1b[27m\x1b[K" in _o)
comprueba("el espacio avanza y el porcentaje sube", True,
          "--More--(55%)" in corre_pager("more", ["/tmp/n"], _largo,
                                         teclas=" ")[0])

# more SI lleva algo parecido a la F: lo que cabe lo vuelca y se va.
_o, _e, _salio = corre_pager("more", ["/tmp/c"], b"corta1\ncorta2\n")
comprueba("more vuelca lo que cabe y termina", (True, "corta1\ncorta2\n"),
          (_salio, _o))

_o, _e, _salio = corre_pager("more", ["/tmp/n"], _largo, teclas="q")
comprueba("q sale de more borrando solo su aviso", (True, True),
          (_salio, _o.endswith("\r\x1b[K")))

# --- y ninguno de los dos pagina en una tuberia ----------------------------
for _cual in ("less", "more"):
    _o, _e, _salio = corre_pager(_cual, ["/tmp/n"], _largo, tuberia=True)
    comprueba("%s por tuberia vuelca entero y sale" % _cual, (True, 30),
              (_salio, _o.count("\n")))


# ==========================================================================
print("\n== que el senuelo ARRANQUE ==")
#
# Cowrie recorre command_modules y hace commands.update(module.commands) sin
# comprobar que el atributo exista. Un modulo de la lista que no lo tenga NO
# da un comando roto: revienta al importar shell/protocol.py y el senuelo no
# levanta, antes de escuchar en ningun puerto.
#
# Paso de verdad con paginador.py, y ninguna de las 726 pruebas de este
# fichero lo vio: todas cargaban modulos sueltos. Lo caza esta, que mira la
# lista entera.
_lista = ast.parse((COMANDOS / "__init__.py").read_text(encoding="utf-8"))
_modulos = []
for _n in ast.walk(_lista):
    if isinstance(_n, ast.Assign) and getattr(_n.targets[0], "id", "") \
            == "command_modules":
        _modulos = [x.value for x in _n.value.elts]
comprueba("la lista de modulos no esta vacia", True, len(_modulos) > 40)

# Solo los que enviamos NOSOTROS: la lista nombra tambien los que ya trae la
# imagen de Cowrie, que aqui no estan y no son cosa nuestra.
_sin_commands = []
for _m in _modulos:
    _ruta = COMANDOS / (_m + ".py")
    if not _ruta.exists():
        continue
    _arbol = ast.parse(_ruta.read_text(encoding="utf-8"))
    _tiene = any(
        (isinstance(_n, ast.Assign)
         and any(getattr(_t, "id", "") == "commands" for _t in _n.targets))
        or (isinstance(_n, ast.AnnAssign)
            and getattr(_n.target, "id", "") == "commands")
        for _n in _arbol.body)
    if not _tiene:
        _sin_commands.append(_m)
comprueba("todos los modulos NUESTROS de la lista exportan 'commands'", [],
          _sin_commands)

# Y al reves: un modulo nuestro que no este en la lista no se carga al
# arrancar, asi que un error de sintaxis suyo no se veria hasta que alguien
# teclee el comando.
_nuestros = {f.stem for f in COMANDOS.glob("*.py")
             if f.stem not in ("__init__",)}
comprueba("y ningun modulo nuestro se queda fuera de la lista", set(),
          _nuestros - set(_modulos))


# ==========================================================================
print("\n== el shell entre comandos ==")
#
# Estas cuatro salieron de pasar lineas por el shell DE VERDAD, con el
# protocolo de Cowrie montado sobre su fs.pickle: ver
# "3.6 Para facilitarnos la vida/banco_shell_real.py". Las pruebas de este
# fichero cargan cada comando por su cuenta y no ven nada de lo que pasa
# ENTRE comandos, que es donde estaban.
#
# Van sobre el arbol de sintaxis y no sobre el texto: nuestros comentarios
# citan el codigo viejo y un grep se encontraria a si mismo.
_hp = ast.parse((COMANDOS.parent / "shell" / "honeypot.py")
                .read_text(encoding="utf-8"))

# 1. HAY DOS LEXERS ---el de la linea y el del parentesis--- y tienen que
#    configurarse IGUAL. Estaban escritos por separado, y al anadir una marca
#    a uno y olvidarla en el otro, lo entrecomillado se partia solo dentro de
#    los parentesis: la clase de fallo que aparece un mes despues y en un caso
#    raro. Ahora la lista vive en una constante, asi que la prueba es que los
#    dos la usen y que lleve lo que tiene que llevar.
_wordchars = [n.value for n in ast.walk(_hp)
              if isinstance(n, ast.AugAssign)
              and getattr(n.target, "attr", "") == "wordchars"]
comprueba("hay DOS lexers, el de la linea y el del parentesis", 2,
          len(_wordchars))
comprueba("   y los dos usan la MISMA constante", [True, True],
          [isinstance(w, ast.Name) and w.id == "WORDCHARS_EXTRA"
           for w in _wordchars])

_extra = [n for n in _hp.body
          if isinstance(n, ast.Assign)
          and getattr(n.targets[0], "id", "") == "WORDCHARS_EXTRA"]
_piezas = {c.value for n in _extra for c in ast.walk(n)
           if isinstance(c, ast.Constant) and isinstance(c.value, str)}
_piezas |= {c.id for n in _extra for c in ast.walk(n)
            if isinstance(c, ast.Name)}
_literal = "".join(p for p in _piezas if len(p) > 3)
comprueba("   con los corchetes, la admiracion y los comodines dentro", [],
          [c for c in "[]!*?~" if c not in _literal])
comprueba("   y todas las marcas de lo que no se expande", set(),
          {"DOLAR_LITERAL", "TILDE_LITERAL", "FRONTERA", "ARIT_INI",
           "ARIT_FIN", "ALMOHADILLA", "MARCA_HEREDOC", "ASTERISCO",
           "INTERROGA", "CORCHETE"} - _piezas)

# 2. protocol.pp no siempre existe: lo crea el primer comando que se ejecuta.
#    Tocarlo a pelo tumbaba LA SESION ENTERA con un AttributeError ---no el
#    comando, la sesion--- en cuanto un subshell solo llevaba asignaciones.
def _cadena(nodo, camino):
    for paso in camino:
        if not isinstance(nodo, ast.Attribute) or nodo.attr != paso:
            return False
        nodo = nodo.value
    return isinstance(nodo, ast.Name) and nodo.id == "self"


_a_pelo = [n for n in ast.walk(_hp) if isinstance(n, ast.Attribute)
           and _cadena(n, ["next_command", "pp", "protocol"])]
comprueba("nadie toca protocol.pp.next_command sin mirar si pp existe", [],
          _a_pelo)

# 3. El "cd" de un subshell no sale del parentesis. Para eso existe un
#    subshell: medido en bash y en dash, "cd /root; (cd /tmp; pwd); pwd" dice
#    /tmp y luego /root. El nuestro se quedaba en /tmp y ademas CAMBIABA EL
#    PROMPT, que es la senal mas visible que puede dar una shell.
_restaura = []
for _n in ast.walk(_hp):
    if not isinstance(_n, ast.Try) or not _n.finalbody:
        continue
    for _f in ast.walk(ast.Module(body=_n.finalbody, type_ignores=[])):
        if isinstance(_f, ast.Assign) and any(
                isinstance(_t, ast.Attribute) and _t.attr == "cwd"
                and _cadena(_t, ["cwd", "protocol"]) for _t in _f.targets):
            _restaura.append(_f)
comprueba("el directorio se devuelve al salir del parentesis, y en un finally",
          True, len(_restaura) >= 1)

# 4. El codigo de salida SI sale del parentesis, aunque el directorio no.
#    Estaba clavado a cero, asi que "(comando-que-falla) || respaldo" no
#    lanzaba nunca el respaldo.
_desde_subshell = [n for n in ast.walk(_hp)
                   if isinstance(n, ast.Assign)
                   and any(getattr(x, "attr", "") == "last_status"
                           for x in n.targets)
                   and "_estado_subshell" in ast.dump(n.value)]
# Son varios sitios ---el parentesis y el cuerpo de una funcion--- y lo que
# se comprueba es que EXISTAN, no cuantos: contar el numero exacto hace que
# la prueba falle al anadir otro sin que nada se haya roto.
comprueba("el estado sale del parentesis en vez de estar clavado a cero",
          True, len(_desde_subshell) >= 1)


# ==========================================================================
print("\n== awk ==")
#
# Venia de Cowrie con el "-F" declarado SIN argumento, asi que las dos formas
# que se teclean fallaban: "-F :" tomaba el separador por el programa y "-F:"
# daba "invalid option". Y aunque hubieran pasado, el separador no se usaba
# en ningun sitio: el codigo partia siempre por espacios y lo decia un TODO.
#
# Los 23 casos estan comparados contra el mawk de un Debian 13: identicos.
_awk = carga("awk")


def corre_awk(args, entrada=b"", ficheros=None):
    cmd = _awk.commands["awk"]()
    cmd.args = list(args)
    cmd.input_data = entrada
    cmd.exit_code = 0
    cmd.protocol = types.SimpleNamespace(cwd="/root")
    tabla = ficheros or {}
    _no_esta = sys.modules["cowrie.shell.fs"].FileNotFound

    def _lee(r):
        # El sistema de ficheros de verdad lanza FileNotFound, no KeyError, y
        # awk captura por ese nombre: con un KeyError la prueba reventaba
        # donde el senuelo habria contestado bien.
        if r not in tabla:
            raise _no_esta(r)
        return tabla[r]

    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: r if r.startswith("/") else c + "/" + r,
        isdir=lambda r: False,
        file_contents=_lee)
    cmd.start()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


comprueba("-F pegado al separador", "b\n",
          corre_awk(["-F:", "{print $2}"], b"a:b:c\n")[0])
comprueba("-F con el separador SUELTO, que era el que fallaba", "b\n",
          corre_awk(["-F", ":", "{print $2}"], b"a:b:c\n")[0])
comprueba("un separador de varios caracteres es una expresion regular", "b\n",
          corre_awk(["-F", "[0-9]+", "{print $2}"], b"a1b22c\n")[0])
# Un separador de UN caracter va literal aunque sea un metacaracter: "-F."
# parte por puntos, no por cualquier cosa. Es la regla de POSIX.
comprueba("y uno de un caracter va literal, aunque sea metacaracter", "b\n",
          corre_awk(["-F", ".", "{print $2}"], b"a.b\n")[0])
comprueba("sin -F se sigue partiendo por rachas de espacios", "b\n",
          corre_awk(["{print $2}"], b"a   b\n")[0])

comprueba("NF cuenta los campos del separador que toque", "2\n",
          corre_awk(["-F:", "{print NF}"], b"a:b\n")[0])
comprueba("NR numera las lineas", "1\n2\n",
          corre_awk(["{print NR}"], b"x\ny\n")[0])
comprueba("-v define una variable", "adios\n",
          corre_awk(["-v", "x=adios", "{print x}"], b"hola\n")[0])
comprueba("   y pegada tambien", "adios\n",
          corre_awk(["-vx=adios", "{print x}"], b"hola\n")[0])
comprueba("-f lee el programa de un fichero", "b\n",
          corre_awk(["-f", "/p.awk", "-F:"], b"a:b\n",
                    {"/p.awk": b"{print $2}"})[0])

# LA COMA Y EL ESPACIO NO SON LO MISMO, y el de antes los trataba igual.
comprueba("la coma separa con UN espacio", "a c\n",
          corre_awk(["{print $1, $3}"], b"a b c\n")[0])
comprueba("sin coma se concatena, sin nada en medio", "ac\n",
          corre_awk(["-F:", "{print $1 $3}"], b"a:b:c\n")[0])
comprueba("una cadena entre comillas se pega tal cual", "a b\n",
          corre_awk(['{print $1 " " $2}'], b"a b\n")[0])
comprueba("'print' a secas imprime la linea entera", "hola\n",
          corre_awk(["{print}"], b"hola\n")[0])

# LOS ERRORES SON LOS DE MAWK, que no dice lo mismo que gawk.
comprueba("-F sin argumento", ("awk: option -F lacks argument\n", 2),
          corre_awk(["-F"])[1:3])
comprueba("una opcion que no existe: 'not an option', no 'invalid option'",
          ("awk: not an option: -Z\n", 2), corre_awk(["-Z"])[1:3])
comprueba("un fichero que falta se dice como lo dice mawk", True,
          corre_awk(["{print}", "/noexiste"])[1].startswith(
              'awk: cannot open "/noexiste" (No such file'))

# Y LA IDENTIDAD. La maquina no tiene gawk: "dpkg -l" declara mawk y gawk ni
# esta instalado, asi que un "awk --version" diciendo "GNU Awk" se
# contradecia con el listado de paquetes de al lado.
_v = corre_awk(["--version"])[0]
comprueba("--version dice mawk, no GNU Awk", True,
          _v.startswith("mawk 1.3.4 ") and "GNU Awk" not in _v)
comprueba("   con las dos lineas de derechos de mawk", 2,
          _v.count("Copyright"))
_h = corre_awk(["--help"])[0]
comprueba("y la ayuda es la de mawk", True,
          _h.startswith("Usage: mawk [Options]") and "gawk.info" not in _h)
comprueba("   sin las opciones largas de gawk, que mawk no tiene", False,
          "--characters-as-bytes" in _h)


# ---------------------------------------------------------------------------
# wc
# ---------------------------------------------------------------------------
#
# El de la imagen escribia recorriendo la lista de OPCIONES, asi que sin
# opciones no escribia nada: "wc fichero" y "algo | wc", que son las dos
# formas normales de llamarlo, no imprimian ni una linea. Ademas contaba las
# palabras partiendo solo por espacios ---un texto con saltos de linea era una
# sola palabra--- y no ensenaba ni el nombre del fichero ni la linea "total".
#
# Todo medido contra coreutils 9.7 en Debian 13.
_wc = carga("wc")


def corre_wc(args, entrada=None, ficheros=None, tuberia=False, dirs=(),
             entorno=None):
    cmd = _wc.commands["wc"]()
    cmd.args = list(args)
    cmd.environ = entorno or {}
    cmd.input_data = entrada
    cmd.exit_code = 0
    cmd.protocol = types.SimpleNamespace(
        cwd="/root",
        pp=types.SimpleNamespace(stdin_from_pipe=tuberia))
    tabla = ficheros or {}
    _no_esta = sys.modules["cowrie.shell.fs"].FileNotFound

    def _lee(r):
        if r not in tabla:
            raise _no_esta(r)
        return tabla[r]

    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: r if r.startswith("/") else c + "/" + r,
        isdir=lambda r: r in dirs,
        file_contents=_lee)
    cmd.start()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


_F1 = {"/root/f1": b"a b c\nd e\n"}          # 2 lineas, 5 palabras, 10 bytes

comprueba("sin opciones imprime las tres cifras y el nombre", " 2  5 10 f1\n",
          corre_wc(["f1"], ficheros=_F1)[0])
comprueba("-w cuenta palabras, no trozos entre espacios", "5 f1\n",
          corre_wc(["-w", "f1"], ficheros=_F1)[0])
comprueba("   y por eso un texto con saltos no es UNA palabra", "3\n",
          corre_wc(["-w"], entrada=b"a b\nc\n", tuberia=True)[0])
comprueba("-l cuenta saltos de linea", "2 f1\n",
          corre_wc(["-l", "f1"], ficheros=_F1)[0])
comprueba("el orden de las columnas es el de coreutils, no el de la linea",
          " 2  5 10  5 f1\n", corre_wc(["-clwL", "f1"], ficheros=_F1)[0])
comprueba("varios ficheros llevan linea 'total'",
          " 2  5 10 f1\n 1  1  2 f2\n 3  6 12 total\n",
          corre_wc(["f1", "f2"],
                   ficheros=dict(_F1, **{"/root/f2": b"x\n"}))[0])

# EL ANCHO DE LA COLUMNA sale del tamano en bytes de la entrada, y por una
# tuberia ese tamano no se sabe: coreutils reserva siete. Los mismos numeros
# salen con otro hueco segun de donde vengan, y eso se ve.
comprueba("una sola columna y un solo fichero van sin relleno", "2 f1\n",
          corre_wc(["-l", "f1"], ficheros=_F1)[0])
comprueba("por tuberia el hueco es de siete", "      1       1       5\n",
          corre_wc([], entrada=b"hola\n", tuberia=True)[0])
comprueba("con '< fichero' NO: ahi si se sabe cuanto mide", " 2  5 10\n",
          corre_wc([], entrada=b"a b c\nd e\n", tuberia=False)[0])

# "-m" Y "-c" SOLO SE DIFERENCIAN CON LOCALE. El senuelo no exporta LANG, y
# en C un Debian de verdad cuenta bytes con los dos: medido con "printf
# 'an~\\n' | wc -m", que dice 4 y no 3.
_acento = "a\u00f1\n".encode()
comprueba("sin LANG, -m cuenta bytes como -c: es lo que hace un Debian en C",
          ("4\n", "4\n"),
          (corre_wc(["-m"], entrada=_acento, tuberia=True)[0],
           corre_wc(["-c"], entrada=_acento, tuberia=True)[0]))
comprueba("   con LANG en UTF-8 ya no, y ahi si son tres caracteres",
          ("3\n", "4\n"),
          (corre_wc(["-m"], entrada=_acento, tuberia=True,
                    entorno={"LANG": "C.UTF-8"})[0],
           corre_wc(["-c"], entrada=_acento, tuberia=True,
                    entorno={"LANG": "C.UTF-8"})[0]))
comprueba("-L es el largo de la linea mas larga, sin el salto", "5 f1\n",
          corre_wc(["-L", "f1"], ficheros=_F1)[0])

comprueba("un fichero que falta", ("wc: nada: No such file or directory\n", 1),
          corre_wc(["nada"])[1:3])
comprueba("un directorio cuenta cero y avisa",
          ("      0       0       0 /etc\n", "wc: /etc: Is a directory\n", 1),
          corre_wc(["/etc"], dirs=("/etc",)))
comprueba("una opcion corta que no existe",
          ("wc: invalid option -- 'z'\nTry 'wc --help' for more information.\n",
           1), corre_wc(["-z", "f1"], ficheros=_F1)[1:3])

# LA VERSION SALE DEL LISTADO DE dpkg, no escrita a mano. Estaba a mano y
# distinta en cada comando: cut decia 8.30, chmod 8.25 y printenv 9.7, en la
# misma maquina y con un "dpkg -l" que declara uno solo.
def _version_de(nombre):
    mod = carga(nombre)
    cmd = mod.commands[nombre]()
    cmd.args = ["--version"]
    cmd.exit_code = 0
    cmd.environ = {}
    cmd.exported = set()
    cmd.protocol = types.SimpleNamespace(cwd="/root")
    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: r, isdir=lambda r: False)
    (cmd.call if hasattr(cmd, "call") else cmd.start)()
    return "".join(cmd.salida) + "".join(cmd.errores)


_versiones = [
    corre_wc(["--version"])[0],
    _version_de("cut"),
    _version_de("chmod"),
    _version_de("printenv"),
]
_numeros = {v.split("\n")[0].rsplit(") ", 1)[1] for v in _versiones}
comprueba("los cuatro coreutils publican LA MISMA version", 1, len(_numeros))
comprueba("   y es la que declara el listado de paquetes",
          {sys.modules["cowrie.commands.coreutils_extra"]
           .version_coreutils()[0]}, _numeros)
comprueba("con la linea de Debian, que un coreutils de Debian siempre trae",
          4, sum("Packaged by Debian" in v for v in _versiones))


# ---------------------------------------------------------------------------
# El codigo de salida cuando algo falla
# ---------------------------------------------------------------------------
#
# Casi ningun comando lo ponia: escribia su queja y devolvia CERO. Con eso,
# "cat fichero || wget URL -O fichero" se traga el respaldo, y ese patron
# ---intentar algo y tener un plan B--- es la mitad de lo que hace un dropper.
#
# La mixin FallaAlAvisar lo resuelve en un sitio: un comando que la hereda
# marca el fallo al escribir en la salida de error. Se hereda a mano y no se
# le pone a todos, porque hay comandos que escriben ahi SIN fallar: el aviso
# de apt, el progreso de wget, el "break" fuera de un bucle.
_base_mod = sys.modules["cowrie.commands.base"]
comprueba("la mixin existe y sale del base.py de verdad", True,
          hasattr(_base_mod, "FallaAlAvisar"))


def _hereda(modulo, nombre):
    """¿La clase de ese comando hereda la mixin? Se mira en el ARBOL del
    fichero y no importando el modulo: varios de estos no se pueden cargar
    aqui ---les faltan piezas de Cowrie que el doble no finge--- y lo que se
    quiere comprobar es la herencia, que esta escrita en el codigo."""
    arbol = ast.parse((COMANDOS / (modulo + ".py")).read_text(encoding="utf-8"))
    clases = {n.name: n for n in ast.walk(arbol)
              if isinstance(n, ast.ClassDef)}
    vistas, cola = set(), ["Command_" + nombre]
    while cola:
        actual = cola.pop()
        if actual in vistas:
            continue
        vistas.add(actual)
        nodo = clases.get(actual)
        if nodo is None:
            continue
        for base in nodo.bases:
            quien = getattr(base, "id", None) or getattr(base, "attr", None)
            if quien == "FallaAlAvisar":
                return True
            if quien:
                cola.append(quien)
    return False


def _codigo_de(modulo, nombre):
    """El CODIGO_DE_FALLO que declara la clase, o 1 si no declara ninguno."""
    arbol = ast.parse((COMANDOS / (modulo + ".py")).read_text(encoding="utf-8"))
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.ClassDef) and nodo.name == "Command_" + nombre:
            for cuerpo in nodo.body:
                if isinstance(cuerpo, ast.Assign) and \
                        getattr(cuerpo.targets[0], "id", "") == "CODIGO_DE_FALLO":
                    return cuerpo.value.value
    return 1


for _mod, _cmd in (("cat", "cat"), ("fs", "head"), ("fs", "tail"),
                   ("fs", "grep"), ("fs", "rm"), ("fs", "cp"), ("fs", "mv"),
                   ("fs", "mkdir"), ("fs", "touch"), ("fs", "cd"),
                   ("cut", "cut"), ("stat", "stat"), ("uniq", "uniq"),
                   ("chmod", "chmod"), ("du", "du"), ("ln", "ln"),
                   ("readlink", "readlink"), ("tee", "tee"),
                   ("which", "which"), ("tr", "tr"),
                   ("md5sum", "md5sum"), ("shasum", "sha256sum"),
                   ("coreutils_extra", "sort")):
    comprueba("   %s falla al avisar" % _cmd, True, _hereda(_mod, _cmd))

# El codigo NO siempre es 1: grep y sort dan 2. Medido en Debian 13.
comprueba("grep sale con 2, no con 1", 2, _codigo_de("fs", "grep"))
comprueba("y sort tambien", 2, _codigo_de("coreutils_extra", "sort"))
comprueba("pero cat sale con 1", 1, _codigo_de("cat", "cat"))

# LAS COMILLAS DE COREUTILS 9. La comilla invertida ---`x'--- es de coreutils
# 8 y de antes; el 9 escribe 'x'. Estaban mezcladas dentro del MISMO comando:
# el "Permission denied" de head ya iba con comilla recta y el "No such file"
# de al lado con la invertida.
_con_invertida = sorted(t for t in cadenas_de(COMANDOS / "fs.py") if "`" in t)
comprueba("ninguna cadena que fs.py pueda imprimir lleva comilla invertida",
          [], _con_invertida)


# ---------------------------------------------------------------------------
# El reparto en columnas de ls
# ---------------------------------------------------------------------------
#
# No era el de ls en tres cosas a la vez: escribia de izquierda a derecha
# ---el de verdad llena PRIMERO cada columna, hacia abajo---, separaba con UN
# espacio en vez de dos y rellenaba tambien el ultimo nombre de cada linea,
# dejando espacios al final. Se ve en la primera orden que teclea cualquiera.
#
# Comparado con un ls de verdad sobre un terminal de 80 columnas.
# La funcion REAL, sacada del propio ls.py: ese modulo no se puede importar
# aqui ---pide piezas de Cowrie que el doble no finge--- y una copia dejaria
# de probar lo que se despliega.
_ns: dict = {}
_src_ls = (COMANDOS / "ls.py").read_text(encoding="utf-8")
exec(compile(_src_ls[_src_ls.index("def reparte_en_columnas"):
                     _src_ls.index("def _cowrie_perm_ok")],
             "ls.py", "exec"), _ns)
_columnas = _ns["reparte_en_columnas"]

comprueba("tres nombres cortos: dos espacios y sin cola", ["a  b  c"],
          _columnas(["a", "b", "c"], 80))
comprueba("y treinta van HACIA ABAJO, no de izquierda a derecha",
          ["fichero01  fichero06  fichero11  fichero16  fichero21  fichero26",
           "fichero02  fichero07  fichero12  fichero17  fichero22  fichero27",
           "fichero03  fichero08  fichero13  fichero18  fichero23  fichero28",
           "fichero04  fichero09  fichero14  fichero19  fichero24  fichero29",
           "fichero05  fichero10  fichero15  fichero20  fichero25  fichero30"],
          _columnas(["fichero%02d" % k for k in range(1, 31)], 80))
comprueba("cada columna mide lo que SU nombre mas largo",
          ["a   ccc   eeeee   ggggggg   iiiiiiiii   kkkkkkkkkkk",
           "bb  dddd  ffffff  hhhhhhhh  jjjjjjjjjj  llllllllllll"],
          _columnas(["a", "bb", "ccc", "dddd", "eeeee", "ffffff", "ggggggg",
                     "hhhhhhhh", "iiiiiiiii", "jjjjjjjjjj", "kkkkkkkkkkk",
                     "llllllllllll"], 80))
comprueba("ninguna linea acaba en espacio", True,
          all(not l.endswith(" ")
              for l in _columnas(["a", "bb", "ccc"], 80)))
comprueba("si no caben, una por linea", ["unonombremuylargo", "otro"],
          _columnas(["unonombremuylargo", "otro"], 10))

# ---------------------------------------------------------------------------
# ulimit
# ---------------------------------------------------------------------------
#
# El de la imagen tenia el cuerpo entero en un "pass": "ulimit -n" ---de lo
# primero que mira quien va a abrir muchos sockets--- no escribia ni una
# linea. El parentesis de "-a" CIERRA SIEMPRE en la columna 40: medido.
_ulimit = carga("ulimit")


def corre_ulimit(args):
    cmd = _ulimit.commands["ulimit"]()
    cmd.args = list(args)
    cmd.exit_code = 0
    cmd.protocol = types.SimpleNamespace(cwd="/root")
    cmd.call()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


comprueba("-n da el numero de descriptores", "1024\n", corre_ulimit(["-n"])[0])
comprueba("sin opciones es como -f", "unlimited\n", corre_ulimit([])[0])
_todo = corre_ulimit(["-a"])[0].split("\n")[:-1]
comprueba("-a lista los diecisiete limites", 17, len(_todo))
comprueba("   y el parentesis cierra en la columna 40 en todas menos la"
          " primera, que no cabe", {40},
          {l.index(")") + 1 for l in _todo[1:]})
comprueba("una opcion que no existe", 2, corre_ulimit(["-Z"])[2])


# ---------------------------------------------------------------------------
# service NO puede describir otra maquina
# ---------------------------------------------------------------------------
#
# El de la imagen contestaba una lista fija de cuarenta y tantos servicios que
# es un escritorio Ubuntu en VMware ---cups, lightdm, bluetooth,
# network-manager, avahi-daemon, apport, plymouth, open-vm-tools---, y aqui la
# leyenda es un servidor Debian 13. La contradiccion se ve poniendo dos
# ordenes seguidas: "systemctl" no lista ninguna de esas y "dpkg -l" no
# declara ni cups ni lightdm. Ahora la lista sale de /etc/init.d y el estado
# de la tabla de systemctl, asi que no hay nada que escribir a mano.
_service_src = (COMANDOS / "service.py").read_text(encoding="utf-8")
# Contra lo que el modulo puede IMPRIMIR, no contra su texto: el comentario que
# explica por que se quitaron los nombra, y una prueba que cace su propia
# explicacion es una prueba que falla sola.
_service_dice = "\n".join(cadenas_de(COMANDOS / "service.py"))
for _fantasma in ("cups", "lightdm", "bluetooth", "network-manager",
                  "avahi-daemon", "apport", "plymouth", "open-vm-tools",
                  "brltty", "kerneloops"):
    comprueba("service ya no nombra '%s'" % _fantasma, False,
              _fantasma in _service_dice)
comprueba("y la lista sale del sistema de ficheros, no de una constante",
          True, "/etc/init.d" in _service_src)
comprueba("   y el estado, de la tabla de systemctl", True,
          "from cowrie.commands.systemctl import UNITS" in _service_src)

# ---------------------------------------------------------------------------
# useradd NO es adduser
# ---------------------------------------------------------------------------
#
# La imagen los tenia apuntando a la MISMA clase, y son dos programas
# distintos: adduser es el envoltorio interactivo de Debian y useradd el
# binario de shadow, que no imprime nada ni pregunta nada. Un "useradd pepe"
# contestaba "Adding user `pepe' ..." y se quedaba pidiendo una contrasena, o
# sea que colgaba el guion justo donde se crea la puerta trasera.
_usuarios = carga("usuarios")
comprueba("useradd tiene su propia clase, no la de adduser", True,
          _usuarios.commands["useradd"].__name__ == "Command_useradd")
comprueba("y estan los cinco de shadow", True,
          all(n in _usuarios.commands
              for n in ("useradd", "usermod", "userdel", "groupadd",
                        "groupdel")))
comprueba("todos escriben en /etc/passwd y /etc/group, no en una lista suya",
          ("/etc/passwd", "/etc/group", "/etc/shadow"),
          (_usuarios.PASSWD, _usuarios.GRUPO, _usuarios.SHADOW))

# ---------------------------------------------------------------------------
# Las banderas de lsattr
# ---------------------------------------------------------------------------
#
# Son VEINTIDOS huecos y el orden no se adivina: se midio poniendo cada
# bandera con "chattr +X" en un contenedor con CAP_LINUX_IMMUTABLE y viendo
# donde caia la letra. La "e" va siempre puesta, que la lleva cualquier
# fichero de ext4.
_finge_cowrie()
_lsattr = sys.modules["cowrie.commands.base"].BANDERAS_LSATTR
comprueba("veintidos huecos", 22, len(_lsattr))

# UN DIRECTORIO SE LISTA POR DENTRO, salvo con "-d", y el prefijo es el que se
# escribio. Es lo mismo que hace ls, y la primera version imprimia el propio
# directorio.
_src_base = (COMANDOS / "base.py").read_text(encoding="utf-8")
_cuerpo_lsattr = _src_base[_src_base.index("class Command_lsattr"):
                           _src_base.index('commands["/usr/bin/chattr"]')]
comprueba("lsattr entra en el directorio tambien cuando se lo nombran", False,
          "not solo_directorio and not self.args" in _cuerpo_lsattr)
comprueba("   y el prefijo sale de como lo escribieron", True,
          'prefijo = "." if not self.args else nombre' in _cuerpo_lsattr)
for _letra, _sitio in (("s", 0), ("u", 1), ("S", 2), ("D", 3), ("i", 4),
                       ("a", 5), ("d", 6), ("A", 7), ("e", 14)):
    comprueba("   '%s' va en el hueco %d" % (_letra, _sitio), _sitio,
              _lsattr.index(_letra))


# ---------------------------------------------------------------------------
# Ningun comando puede tapar a otro sin querer
# ---------------------------------------------------------------------------
#
# Cowrie construye el registro recorriendo command_modules EN ORDEN y haciendo
# commands.update(...), asi que el ULTIMO que registra un nombre gana. Eso ya
# ha mordido dos veces:
#
#   * "eval" estaba dos veces en bashbuiltins.py y el segundo era un no-op,
#     asi que "eval echo hola" no imprimia nada.
#   * "history" tenia su comando de verdad en base.py y un no-op en
#     bashbuiltins.py, que se carga despues: contestaba en blanco.
#
# Las dos veces el sintoma fue el mismo ---un comando que existe y calla--- y
# no lo caza ninguna otra prueba, porque cada modulo por separado esta bien.
_registros: dict = {}
_orden = [m for m in carga("__init__").command_modules
          if (COMANDOS / (m + ".py")).exists()]
for _mod in _orden:
    _arbol = ast.parse((COMANDOS / (_mod + ".py")).read_text(encoding="utf-8"))
    for _n in ast.walk(_arbol):
        if not isinstance(_n, ast.Assign):
            continue
        for _obj in _n.targets:
            if not (isinstance(_obj, ast.Subscript)
                    and getattr(_obj.value, "id", "") == "commands"):
                continue
            _clave = getattr(_obj.slice, "value", None)
            _clase = getattr(_n.value, "id", None)
            if isinstance(_clave, str) and _clase:
                _registros.setdefault(_clave, []).append((_mod, _clase))

# Lo que se busca NO es cualquier repeticion ---un modulo puede registrar el
# mismo nombre dos veces con la misma clase, y muchos no-op de base.py los
# sustituye luego bashbuiltins con el comando de verdad, que es la direccion
# BUENA---. Lo que no puede pasar es al reves: que el que gane sea un no-op y
# tape a uno implementado.
def _es_noop(modulo, clase):
    """True si el cuerpo de esa clase no hace nada: solo return o pass."""
    arbol = ast.parse((COMANDOS / (modulo + ".py")).read_text(encoding="utf-8"))
    for nodo in ast.walk(arbol):
        if not (isinstance(nodo, ast.ClassDef) and nodo.name == clase):
            continue
        cuerpos = [m for m in nodo.body
                   if isinstance(m, ast.FunctionDef)
                   and m.name in ("call", "start")]
        if not cuerpos:
            return False
        for metodo in cuerpos:
            for linea in metodo.body:
                if isinstance(linea, ast.Expr) and \
                        isinstance(linea.value, ast.Constant):
                    continue                      # el docstring
                if isinstance(linea, ast.Pass):
                    continue
                if isinstance(linea, ast.Return) and linea.value is None:
                    continue
                return False
        return True
    return False


_tapados = {}
for _clave, _quienes in _registros.items():
    if len(_quienes) < 2:
        continue
    _gana = _quienes[-1]
    if not _es_noop(*_gana):
        continue
    _antes = [q for q in _quienes[:-1] if not _es_noop(*q)]
    if _antes:
        _tapados[_clave] = (_antes, _gana)
comprueba("ningun no-op tapa a un comando que si esta implementado",
          {}, _tapados)
comprueba("y 'history' lo sirve el comando de verdad, no un no-op",
          [("base", "Command_history")], _registros.get("history"))


# ---------------------------------------------------------------------------
# x86_64 no es un binario raro: es setarch
# ---------------------------------------------------------------------------
#
# Es el CUARTO de la lista que saca que_le_falta_al_senuelo.py ---lo que la
# maquina dice tener y no sabe ejecutar, ordenado por veces tecleado--- con
# diez usos en noventa dias, detras de tr, sed y openssl. Y no era un comando
# que fallara y ya: en Debian /usr/bin/x86_64 es un enlace a setarch y lo que
# hace es EJECUTAR LO QUE SE LE PONGA DETRAS. Lo mas probable en esos diez
# usos es "x86_64 -R ./payload", que desactiva la aleatorizacion del espacio
# de direcciones; sin emularlo, la orden de dentro no corria nunca.
_setarch = carga("setarch")


def corre_setarch(args, como="x86_64", entorno=None, fs_vacio=False):
    cmd = _setarch.commands["x86_64"]()
    cmd.args = list(args)
    cmd.exit_code = 0
    cmd.environ = entorno or {"SHELL": "/bin/bash", "PATH": "/usr/bin:/bin"}
    cmd.protocol = types.SimpleNamespace(cwd="/root", _nombre_invocado=como,
                                         cmdstack=[])
    cmd.fs = types.SimpleNamespace(
        resolve_path=lambda r, c: c.rstrip("/") + "/" + r,
        exists=lambda r: not fs_vacio,
        isdir=lambda r: False)
    cmd.call()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


comprueba("los cuatro alias de Debian estan registrados", True,
          all(n in _setarch.commands
              for n in ("setarch", "x86_64", "i386", "linux32", "linux64")))
# setarch se nombra por su argv[0]: llamado como x86_64 NO dice "setarch".
_v = corre_setarch(["--version"])[0]
comprueba("--version se firma con el nombre con el que lo llamaron", True,
          _v.startswith("x86_64 from util-linux "))
comprueba("   y llamado de otra forma, con la otra", True,
          corre_setarch(["--version"], como="linux32")[0].startswith(
              "linux32 from util-linux "))
comprueba("   y por la ruta entera vale el ultimo trozo", True,
          corre_setarch(["--version"], como="/usr/bin/i386")[0].startswith(
              "i386 from util-linux "))
_h = corre_setarch(["--help"])[0]
comprueba("la ayuda es la de setarch y lleva su propio nombre", True,
          " x86_64 [options] [<program> [<argument>...]]" in _h
          and "For more details see setarch(8)." in _h)
comprueba("   y en ingles, que es lo que ve una sesion del senuelo", True,
          "turns on ADDR_LIMIT_32BIT" in _h)
comprueba("-v dice que personalidad enciende",
          "Switching on ADDR_NO_RANDOMIZE.\nExecute command `echo'.\n",
          corre_setarch(["-v", "-R", "echo", "hola"])[0])
# Y SI LA ORDEN NO EXISTE, se queja setarch, no el shell: hace execvp y el
# error es suyo, con codigo 127.
comprueba("una orden que no existe la reporta setarch, no bash",
          ("x86_64: failed to execute noexistejamas:"
           " No such file or directory\n", 127),
          corre_setarch(["noexistejamas"], fs_vacio=True)[1:3])
comprueba("una opcion larga que no existe",
          ("x86_64: unrecognized option '--nada'\n"
           "Try 'x86_64 --help' for more information.\n", 1),
          corre_setarch(["--nada"])[1:3])


# ---------------------------------------------------------------------------
# Lo que se quedo a medias y salio en el repaso previo al despliegue
# ---------------------------------------------------------------------------
#
# nohup ANUNCIABA EL FICHERO Y NO EJECUTABA NADA. Se escribia el mensaje, se
# creaba nohup.out vacio... y la orden no llegaba a correr nunca. O sea que la
# ultima linea de casi cualquier dropper ---"nohup ./x &"--- no hacia nada, y
# el atacante se iba creyendo que su binario estaba en marcha.
_nohup_src = (COMANDOS / "nohup.py").read_text(encoding="utf-8")
comprueba("nohup ejecuta la orden, no solo la anuncia", True,
          "_execute_subshell_with_full_output" in _nohup_src)
comprueba("   y deja su salida en el fichero, no en la pantalla", True,
          "escribe_fichero" in _nohup_src)
comprueba("   anexando, que dos nohup seguidos dejan las dos salidas", True,
          "anterior + salida.encode()" in _nohup_src)
comprueba("   y si la orden no existe sale con 127, como cualquiera", True,
          "self.exit_code = 127" in _nohup_src)

# /proc/self ES UN ENLACE a /proc/<PID_SESION>: el mismo fichero por dos
# nombres. Por el numero contestaba "No such file or directory".
_cat_src = (COMANDOS / "cat.py").read_text(encoding="utf-8")
comprueba("cat reconoce el cmdline por su numero y por /proc/self", True,
          '"/proc/%d/cmdline" % PID_SESION' in _cat_src)

# "time" NO es un binario: es una palabra clave de bash y funciona siempre.
_bb_src = (COMANDOS / "bashbuiltins.py").read_text(encoding="utf-8")
comprueba("'time' esta registrado como comando", True,
          'commands["time"] = Command_time' in _bb_src)
comprueba("   y su bloque va por la salida de error, como en bash", True,
          'self.errorWrite("\\nreal' in _bb_src)

# Y LA RANURA COMPARTIDA: relanzar una orden dejaba protocol.pp apuntando al
# comando de DENTRO, asi que la tuberia de fuera perdia su salida entera.
_relanzar_src = _bb_src[_bb_src.index("def _relanzar"):
                        _bb_src.index("class Command_eval")]
comprueba("_relanzar guarda y devuelve la ranura de la tuberia", True,
          "pp_de_fuera" in _relanzar_src and "finally:" in _relanzar_src)


# ---------------------------------------------------------------------------
# El dueno de /proc/self/status es el de la sesion, no el del pickle
# ---------------------------------------------------------------------------
#
# El status se hornea al construir el pickle con los datos de root, y el
# pickle es el MISMO para todas las sesiones. Entrando como un usuario normal
# el senuelo se contradecia en dos ordenes seguidas ---visto en la VPS ya
# desplegado---:
#
#     $ id
#     uid=1004(alyosha) gid=1004(alyosha) ...
#     $ grep Uid: /proc/self/status
#     Uid:  0  0  0  0
#
# El mismo proceso con dos duenos segun por donde se mire. Se corrigen al
# LEER solo las lineas que dependen del usuario, sobre el texto que ya trae el
# pickle: asi la plantilla sigue siendo una sola y las dos no pueden
# separarse.
_base_mod2 = sys.modules["cowrie.commands.base"]
_con_dueno = _base_mod2.con_dueno_de_sesion
_rutas = _base_mod2.rutas_del_proceso()


class _Sesion:
    def __init__(self, uid, gid):
        self.current_user = {"uid": uid, "gid": gid}


_STATUS = ("Name:\tbash\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
           "Groups:\t0 \nThreads:\t1\n")
_d = _Sesion(1004, 1004)
_visto = _con_dueno(_d, "/proc/self/status", _STATUS)
comprueba("el Uid del status es el de la sesion, no el de root",
          "Uid:\t1004\t1004\t1004\t1004", _visto.split("\n")[1])
comprueba("   y el Gid tambien", "Gid:\t1004\t1004\t1004\t1004",
          _visto.split("\n")[2])
comprueba("   y los grupos", "Groups:\t1004 ", _visto.split("\n")[3])
comprueba("   sin tocar nada mas", ["Name:\tbash", "Threads:\t1"],
          [_visto.split("\n")[0], _visto.split("\n")[4]])
comprueba("el cgroup cuelga del slice de ESE usuario",
          "0::/user.slice/user-1004.slice/session-89.scope\n",
          _con_dueno(_d, "/proc/self/cgroup",
                     "0::/user.slice/user-0.slice/session-89.scope\n"))
comprueba("y entrando como root no cambia nada", _STATUS,
          _con_dueno(_Sesion(0, 0), "/proc/self/status", _STATUS))
# NO SOLO cat: el usuario probo con grep y seguia saliendo root. Los dos
# nombres del mismo fichero ---/proc/self y /proc/<PID>--- tienen que estar.
comprueba("estan las dos formas de nombrar el fichero, y los tres ficheros",
          6, len(_rutas))
comprueba("   por su numero tambien", True,
          ("/proc/%d/status" % _base_mod2.PID_SESION) in _rutas)
comprueba("un fichero cualquiera no se toca", "Uid:\t0\t0\t0\t0\n",
          _con_dueno(_d, "/etc/passwd", "Uid:\t0\t0\t0\t0\n"))
comprueba("y funciona igual con bytes, que es como lo leen los comandos",
          b"Uid:\t1004\t1004\t1004\t1004\n",
          _con_dueno(_d, "/proc/self/status", b"Uid:\t0\t0\t0\t0\n"))
# Y que TODOS los lectores pasen por ahi, no solo cat.
for _mod in ("cat", "fs"):
    comprueba("   %s.py pasa lo que lee por el ayudante" % _mod, True,
              "con_dueno_de_sesion" in
              (COMANDOS / (_mod + ".py")).read_text(encoding="utf-8"))

# ---------------------------------------------------------------------------
# Un directorio con un espacio en el nombre
# ---------------------------------------------------------------------------
#
# En /home/admin hay un "ignis api". Visto en la VPS ya desplegado, cuatro
# piezas distintas se rompian con el, y cada una empujaba a la siguiente:
#
#     root@pc-dev-003-ignis:/home# ls admin/
#     ignis api                              <- parecen DOS entradas
#     root@...:/home# ls admin/ignis api/
#     ls: cannot access '/home/admin/ignis': No such file or directory
#                       ^^^^^^ la ruta resuelta, no lo que se escribio
#     root@...:/home/admin# cd ignis api/
#     -bash: cd: ignis: No such file or directory
#                ^^^^^^ bash dice "too many arguments"
#
# y el tabulador, que es de donde salia el "ignis api" sin escapar.

# --- lo que escribe ls ----------------------------------------------------
# El modulo no se puede importar aqui ---pide piezas de Cowrie que el doble no
# finge--- asi que se saca la fuente de verdad, como ya se hace con el reparto
# en columnas: una copia dejaria de probar lo que se despliega.
_nsq: dict = {"string": __import__("string")}
exec(compile(_src_ls[_src_ls.index("_SEGUROS ="):
                     _src_ls.index("def reparte_en_columnas")],
             "ls.py", "exec"), _nsq)
_escapa = _nsq["escapa_nombre"]
_comilla_c = _nsq["entrecomilla_c"]

comprueba("un nombre con espacio sale entrecomillado, como coreutils 8.25",
          "'ignis api'", _escapa("ignis api"))
comprueba("y uno normal sale DESNUDO: si se citara todo tampoco seria ls",
          "README.md", _escapa("README.md"))
comprueba("el guion inicial no obliga a comillas", "-rw", _escapa("-rw"))
comprueba("la comilla simple se cierra y se reabre, no se escapa dentro",
          "'it'\\''s'", _escapa("it's"))
comprueba("un tabulador va en su propio $'...'", "'a'$'\\t''b'",
          _escapa("a\tb"))
comprueba("la almohadilla molesta al principio y no en medio",
          ["'#tmp'", "a#b"], [_escapa("#tmp"), _escapa("a#b")])
comprueba("y la tilde igual", ["'~x'", "a~b"],
          [_escapa("~x"), _escapa("a~b")])
comprueba("el nombre vacio son dos comillas", "''", _escapa(""))
# "-Q" NO es el mismo estilo ---da comillas dobles--- y ademas cita siempre.
comprueba("ls -Q usa comillas dobles al estilo de C",
          ['"ignis api"', '"README.md"'],
          [_comilla_c("ignis api"), _comilla_c("README.md")])
comprueba("   y ahi el tabulador va en la propia cadena", '"a\\tb"',
          _comilla_c("a\tb"))
# Las dos opciones ni se aceptaban: getopt contestaba "option -- 'Q' is not
# recognized", que en un ls de verdad no pasa.
contiene("getopt conoce -Q y -N", "1@ABCFGHLNOPQRSTUWabcdefghiklmnopqrstuvwx",
         ls_txt2)
contiene("   y sus nombres largos", '"literal", "quote-name"', ls_txt2)
# En una tuberia NO se cita: un guion que corte la salida de ls no espera
# comillas. Es la misma condicion que decide la columna unica.
contiene("a una tuberia se escribe literal, como el de verdad",
         'self.estilo = "shell" if hay_terminal(self) else "literal"', ls_txt2)
# El listado normal, el nombre en "-l" y el destino del enlace: los tres.
comprueba("y los tres sitios que escriben un nombre pasan por el filtro", 3,
          ls_txt2.count("self.nombre(file[fs.A_NAME])")
          + ls_txt2.count("self.nombre(x[fs.A_NAME])")
          + ls_txt2.count("self.nombre(file[fs.A_TARGET])"))

# --- lo que escribe el tabulador ------------------------------------------
_nst: dict = {}
_src_hp = (COMANDOS.parent / "shell" / "honeypot.py").read_text(
    encoding="utf-8")
exec(compile(_src_hp[_src_hp.index("CARACTERES_A_ESCAPAR ="):
                     _src_hp.index('# UN "$" QUE NO SE EXPANDE')],
             "honeypot.py", "exec"), _nst)
_parte = _nst["parte_ultimo_token"]
_escapa_tab = _nst["escapa_completado"]

# El troceo era line.split(), o sea por espacios: con "cd ignis\ ap" el clue
# era "ap" y no completaba nada.
comprueba("el token se busca respetando la barra", ("cd ", "ignis ap", ""),
          _parte("cd ignis\\ ap"))
comprueba("   y las comillas simples sin cerrar", ("cd ", "ignis ap", "'"),
          _parte("cd 'ignis ap"))
comprueba("   y las dobles", ("cd ", "ignis ap", '"'),
          _parte('cd "ignis ap'))
comprueba("unas comillas ya cerradas cuentan como token sin comillas",
          ("cd ", "ignis api", ""), _parte("cd 'ignis api'"))
comprueba("tras un espacio el token esta vacio: se lista el directorio",
          ("cd ", "", ""), _parte("cd "))
# Lo de delante volvia por " ".join(line.split()), que aplastaba los espacios
# de mas Y las comillas de los argumentos anteriores.
comprueba("lo de antes del token vuelve TAL CUAL", ("cp  'a b'  ", "de", ""),
          _parte("cp  'a b'  de"))

comprueba("sin comillas se escapa con barra", "ignis\\ api",
          _escapa_tab("ignis api", "", True))
comprueba("dentro de comillas simples no hace falta, y se cierran",
          "'ignis api'", _escapa_tab("ignis api", "'", True))
# Un directorio deja la comilla ABIERTA y mete la barra dentro, que es lo
# que escribe bash: con "cd \"/home/adm" el tabulador no hacia nada de nada,
# porque el clue se llevaba la comilla de apertura pegada delante.
contiene("un directorio no cierra la comilla: la barra va dentro",
         'newbuf = cabecera + escapa_completado(nombre, comilla, not es_dir)',
         _src_hp)
comprueba("un completado PARCIAL deja la comilla abierta", "'ignis api",
          _escapa_tab("ignis api", "'", False))
comprueba("la tilde inicial es una expansion y no se toca", "~/Documentos",
          _escapa_tab("~/Documentos", "", True))
# La lista de bash escapa tambien "=", ":" y "@", que sorprenden pero son
# los de rl_filename_quote_characters.
comprueba("y la lista es la de bash, con = : y @", "a\\=b\\:c\\@d",
          _escapa_tab("a=b:c@d", "", True))

# --- lo que contesta cd ----------------------------------------------------
_fs_txt2 = (COMANDOS / "fs.py").read_text(encoding="utf-8")
contiene("cd con dos destinos se planta, como bash",
         '"-bash: cd: too many arguments\\n"', _fs_txt2)
contiene("   y -L y -P son opciones, no directorios llamados asi",
         'while args and args[0] in ("-L", "-P", "-e", "-@"):', _fs_txt2)
comprueba("cd ya no lee self.args[0] a pelo", False,
          "pname = self.args[0]" in _fs_txt2)

# ==========================================================================
print("\n== psql y node, que es donde muere el cebo ==")
#
# El senuelo deja un .env con DATABASE_URL=postgres://...@db-internal... y el
# PACKAGES instala postgresql-client y nodejs, asi que la maquina los declara:
# "which psql" los encuentra, "ls -la" los ensena y "dpkg -l" los lista. Sin
# emularlos, la contradiccion llegaba JUSTO DESPUES de que el atacante picara
# con el cebo, que es el peor momento posible. Sale de una captura de verdad:
# once intentos con psql y seis con node en la misma sesion.
_tsv_bd = tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False,
                                      encoding="utf-8")
_tsv_bd.write("postgresql-client-17\t17.6-0+deb13u1\tamd64\tfront-end\n")
_tsv_bd.write("nodejs\t20.19.2+dfsg-1\tamd64\tevented I/O for V8\n")
_tsv_bd.close()

sys.modules["cowrie.commands.ping"] = carga("ping")
_psql = carga("psql")
_node = carga("node")
# El MISMO lector que el dpkg, apuntando al listado de prueba: asi se prueba
# tambien que la version sale de ahi y no de un numero escrito a mano.
_psql.leer_paquetes = lambda: _dpkg_mod.leer_paquetes(_tsv_bd.name)
_node.leer_paquetes = lambda: _dpkg_mod.leer_paquetes(_tsv_bd.name)


def corre_bd(mod, clave, args, hosts=b"127.0.0.1\tlocalhost\n"):
    cmd = mod.commands[clave]()
    cmd.args = list(args)
    cmd.exit_code = 0
    cmd.protocol = types.SimpleNamespace(cwd="/root")
    cmd.fs = types.SimpleNamespace(
        file_contents=lambda r: hosts,
        exists=lambda r: False,
        resolve_path=lambda r, c: r if r.startswith("/") else c + "/" + r)
    cmd.call()
    return "".join(cmd.salida), "".join(cmd.errores), cmd.exit_code


# LA VERSION SALE DEL dpkg -l, no de un numero escrito aqui. Si se escribiera a
# mano, el dia que se regenerara el sistema de ficheros con otra version el
# senuelo se contradiria solo: "dpkg -l" diria una cosa y "psql --version" otra.
salida, _e, rc = corre_bd(_psql, "psql", ["--version"])
comprueba("psql --version dice lo que declara el dpkg",
          "psql (PostgreSQL) 17.6 (Debian 17.6-0+deb13u1)\n", salida)
comprueba("y sale con cero", 0, rc)
salida, _e, _rc = corre_bd(_node, "node", ["--version"])
comprueba("node --version, igual", "v20.19.2\n", salida)

# EL CASO DE LA CAPTURA: la URL entera del .env del cebo.
_url = "postgres://ignis_app:Xk7$vProd2025@db-internal.ignislabs.dev:5432/ignis_prod"
_s, err, rc = corre_bd(_psql, "psql", [_url, "-c", "\\dt"])
comprueba("con la URL del cebo, psql falla al conectar", 2, rc)
comprueba("diciendo el host y el puerto de la URL", True,
       'connection to server at "db-internal.ignislabs.dev"' in err
       and ", port 5432 failed" in err)
comprueba("y con la segunda linea que escribe psql de verdad", True,
       "Is the server running on that host and accepting TCP/IP connections?"
       in err)
comprueba("y no escribe nada por la salida buena", "", _s)

# EL MISMO RESOLVEDOR QUE ping. Si cada uno resolviera a su manera, un ping y
# un psql al mismo nombre darian respuestas distintas, que es de lo primero que
# tira quien sospecha.
_ping = sys.modules["cowrie.commands.ping"]
_ip_ping = _ping.resuelve_nombre("db-internal.ignislabs.dev",
                                 types.SimpleNamespace(
                                     file_contents=lambda r: b""))
comprueba("psql ensena la MISMA IP a la que resuelve ping", True, _ip_ping in err)

# Con -h y una IP literal no se repite la IP entre parentesis, como el de verdad.
_s, err, _rc = corre_bd(_psql, "psql", ["-h", "10.10.3.10", "-U", "ignis_app",
                                        "-c", "SELECT version()"])
comprueba("con una IP, psql no la repite entre parentesis", True,
       'at "10.10.3.10", port 5432 failed' in err)

# Sin -h no hay red que valga: un psql de verdad va al socket de unix, y el
# error no habla ni de puertos ni de nombres.
_s, err, rc = corre_bd(_psql, "psql", ["-l"])
comprueba("sin -h, el error es el del socket local", True,
       'socket "/var/run/postgresql/.s.PGSQL.5432" failed: No such file or '
       "directory" in err)
comprueba("y su segunda linea tambien es la otra", True,
       "Is the server running locally" in err)

_s, err, _rc = corre_bd(_psql, "psql", ["-h", "nosuch", "-p", "5433"])
comprueba("un nombre que no resuelve se dice como tal", True,
       'could not translate host name "nosuch" to address' in err)

# Y la ruta ENTERA del binario, que es la que tecleo el atacante de la captura:
# /usr/bin/psql es un enlace al envoltorio y el ejecutable vive ahi.
salida, _e, _rc = corre_bd(_psql, "/usr/lib/postgresql/17/bin/psql",
                           ["--version"])
comprueba("la ruta larga del binario contesta igual", True,
       salida.startswith("psql (PostgreSQL) 17.6"))

# NODE. Lo que probo el atacante: si la maquina trae el cliente de PostgreSQL.
_s, err, rc = corre_bd(_node, "node", ["-e", 'const {Client}=require("pg");'])
comprueba("un require de algo que no esta falla, como en node", 1, rc)
comprueba("con el error de verdad y su codigo", True,
       "Error: Cannot find module 'pg'" in err
       and "code: 'MODULE_NOT_FOUND'" in err)
comprueba("y firmado con la version del dpkg", True, "Node.js v20.19.2" in err)

_s, err, rc = corre_bd(_node, "node", ["-e", 'const net=require("net");'])
comprueba("pero un modulo de fabrica NO falla: net viene dentro", 0, rc)
comprueba("y no escribe ningun error", "", err)
comprueba("tampoco por node:net", "", corre_bd(
    _node, "node", ["-e", 'require("node:dgram");'])[1])

_s, err, rc = corre_bd(_node, "node", ["/tmp/probe.js"])
comprueba("un fichero que no existe se dice con su ruta entera", True,
       "Error: Cannot find module '/tmp/probe.js'" in err)

# El limite conocido, escrito para que nadie crea otra cosa: aqui no se evalua
# JavaScript, igual que el python3 de al lado no evalua Python.
comprueba("no se evalua JavaScript, y la cabecera lo dice", True,
          "QUE NO HACE: ejecutar JavaScript" in
          (COMANDOS / "node.py").read_text(encoding="utf-8"))

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
