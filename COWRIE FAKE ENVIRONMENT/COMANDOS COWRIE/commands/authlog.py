# SPDX-License-Identifier: BSD-3-Clause
"""
/var/log/auth.log, generado al abrir la sesion.

QUE PASABA. systemctl declara rsyslog.service activo y build-dirtyland-fs.sh
instala el paquete, asi que el dpkg tambien lo da por instalado --- pero el
contenedor de construccion NUNCA lo arranca, y rsyslog solo crea sus ficheros
al correr. La maquina decia tener un demonio de registro funcionando y no
tenia /var/log/auth.log.

Y ese fichero se mira. Quien entra comprueba si su acceso ha quedado anotado,
y muchos droppers hacen "> /var/log/auth.log" para borrar rastro. Que no
exista contesta la pregunta antes de hacerla.

POR QUE NO VALE GUARDARLO EN EL PICKLE, que era lo facil: nace correcto y a
los cinco minutos ya miente, igual que pasaba con /proc/uptime. Y peor,
porque cron abre una sesion PAM cada hora: un auth.log cuya ultima linea sea
de hace seis meses, en una maquina que "uptime" dice llevar seis meses
encendida y con cron activo, delata MAS que no tener el fichero.

Asi que se genera al empezar la sesion y se escribe en el sistema de ficheros
---como hace nano al guardar--- para que lo vean cat, tail, grep y less por
igual. Un apano dentro de cat.py, como el de /proc/uptime, dejaria a
"tail /var/log/auth.log" contando otra cosa.

TODO EL FORMATO ESTA MEDIDO en un debian:trixie con rsyslog, cron y sshd
arrancados de verdad. Tres cosas que no se adivinan:

  1. LA MARCA DE TIEMPO NO ES LA CLASICA. El rsyslog de trixie escribe ISO con
     microsegundos y huso ---"2026-09-03T12:27:57.500034+00:00"--- y no el
     "Sep  3 12:27:57" de toda la vida. journalctl SI usa el corto, asi que
     los dos conviven en la misma maquina diciendo cada uno lo suyo.

  2. LAS CONEXIONES SON "sshd-session", NO "sshd". Desde OpenSSH 9.8 el
     demonio se parte en dos: "sshd" es el que escucha y "sshd-session" el que
     atiende cada conexion. Un log que diga "sshd[682]: Accepted password"
     esta escrito de memoria y se nota.

  3. EL FICHERO ES root:root, no el root:adm de toda la vida.

Y una linea que sale por coherencia con lo demas, no por adorno:

    pam_env(sshd:session): Unable to open env file: /etc/default/locale

Sale porque la maquina no tiene ese fichero --- que es exactamente la razon
por la que la sesion no exporta LANG y por la que pstree y lsblk dibujan en
ASCII. Se comprueba en el sistema de ficheros antes de escribirla: si algun
dia ese fichero existe, la linea desaparece sola.
"""

from __future__ import annotations

import random
import time

commands: dict = {}

RUTA = "/var/log/auth.log"
DIAS = 7                      # lo que aguanta antes de que logrotate lo rote
PID_SSHD = 682                # el mismo que el ps y que netstat
# 670 y no 654: lo dice ps_command_output.json, y el journalctl tambien lo
# nombra. Estuvo mal desde que se escribio este fichero: el auth.log daba un
# systemd-logind[654] que no existia en la tabla de procesos, y basta un
# "ps aux | grep logind" para ver que no cuadra.
PID_LOGIND = 670


def _marca(momento: float) -> str:
    """La marca ISO de rsyslog: microsegundos y huso con dos puntos.

    El desfase se le pide a strftime en vez de fijarlo, por lo mismo que en
    stat: Kyiv es +03:00 en verano y +02:00 en invierno, y un valor escrito a
    mano acierta medio ano.
    """
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(momento))
    micro = "%06d" % int((momento % 1) * 1_000_000)
    z = time.strftime("%z", time.localtime(momento)) or "+0000"
    return "%s.%s%s:%s" % (base, micro, z[:3], z[3:])


def linea(host: str, ev) -> str:
    """Una entrada en el formato de rsyslog, que es el del auth.log."""
    momento, quien, pid, texto = ev
    return "%s %s %s[%d]: %s" % (_marca(momento), host, quien, pid, texto)


def _pam(quien: str, servicio: str, usuario: str, uid: int, pid: int,
         momento: float, host: str, sin_locale: bool) -> list:
    """Las tres cosas que deja una sesion PAM, en orden.

    Devuelve EVENTOS ---(momento, quien, pid, texto)---, no lineas ya
    formateadas. El motivo es que estos mismos hechos salen por dos sitios
    con dos formatos distintos: el auth.log los escribe como rsyslog y el
    journalctl como journald. Si cada uno se los inventara por su cuenta
    acabarian contando historias distintas de la misma maquina, que es
    justo lo que pasaba antes: el journalctl llevaba fechas de julio fijas.
    """
    lineas = []
    if sin_locale:
        lineas.append((momento, quien, pid,
                       "pam_env(%s:session): Unable to open env file: "
                       "/etc/default/locale" % servicio))
    # Los desplazamientos tampoco son fijos: se sacan del propio instante,
    # asi que varian entre entradas y se repiten si se regenera el fichero.
    d1 = 0.0004 + (int(momento * 1e6) % 900) / 1e6
    d2 = 0.004 + (int(momento * 1e6) % 7000) / 1e6
    lineas.append((momento + d1, quien, pid,
                   "pam_unix(%s:session): session opened for user %s(uid=%d)"
                   " by %s(uid=0)"
                   % (servicio, usuario, uid,
                      usuario if servicio == "sshd" else "root")))
    lineas.append((momento + d2, quien, pid,
                   "pam_unix(%s:session): session closed for user %s"
                   % (servicio, usuario)))
    return lineas


def eventos(usuario: str, uid: int, ip: str, puerto: int, ahora: float,
            sin_locale: bool, sesion: int) -> list:
    """Lo que ha PASADO en la maquina, sin formato: [(momento, quien, pid,
    texto)] ordenado por tiempo.

    Lo usan dos: el auth.log y el journalctl. Antes cada uno se inventaba lo
    suyo y se contradecian ---el journalctl llevaba un "Jul 23" fijo mientras
    el auth.log iba al dia---. Con una sola fuente eso ya no puede pasar.
    """
    r = random.Random(int(ahora) // 3600)       # estable dentro de la hora
    lineas: list = []
    desde = ahora - DIAS * 86400
    pid = r.randint(9000, 40000)

    # cron: /etc/crontab dispara run-parts /etc/cron.hourly a y 17 de cada
    # hora, y las diarias a las 6:25. Son las entradas que mas llenan el
    # fichero en una maquina donde no entra nadie.
    t = desde - (desde % 3600) + 17 * 60
    while t < ahora:
        pid += r.randint(3, 40)
        # CADA ENTRADA CON SU PROPIO RETRASO. cron dispara a y 17 en punto,
        # pero la sesion PAM se abre uno o dos segundos despues. Sin esto las
        # 168 entradas de la semana caian todas en ":17:00.000000" clavado,
        # que es un patron que no da ninguna maquina.
        cuando = t + r.random() * 2
        lineas.extend(_pam("CRON", "cron", "root", 0, pid, cuando, "",
                           sin_locale))
        # La orden que ejecuta cron va SOLO al journal, no al auth.log: es
        # cron.log, no authpriv. Por eso lleva marca y aqui se distingue con
        # el nombre del servicio.
        lineas.append((cuando + 0.002, "CRON", pid,
                       "(root) CMD (   cd / && run-parts --report "
                       "/etc/cron.hourly)", "cron"))
        marca = time.localtime(t)
        if marca.tm_hour == 6:
            pid += r.randint(3, 40)
            diaria = t - 17 * 60 + 25 * 60 + r.random() * 3
            lineas.extend(_pam("CRON", "cron", "root", 0, pid, diaria, "",
                               sin_locale))
            lineas.append((diaria + 0.002, "CRON", pid,
                           "(root) CMD (test -x /usr/sbin/anacron || "
                           "{ cd / && run-parts --report /etc/cron.daily; })",
                           "cron"))
        t += 3600

    # Y la sesion que se esta abriendo AHORA, que es la que de verdad
    # convence: quien busca su IP en el log y la encuentra deja de dudar.
    pid += r.randint(3, 40)
    lineas.append((ahora, "sshd-session", pid,
                   "Accepted password for %s from %s port %d ssh2"
                   % (usuario, ip, puerto)))
    lineas.append((ahora + 0.003, "sshd-session", pid,
                   "pam_unix(sshd:session): session opened for user "
                   "%s(uid=%d) by %s(uid=0)" % (usuario, uid, usuario)))
    if sin_locale:
        lineas.append((ahora + 0.29, "sshd-session", pid,
                       "pam_env(sshd:session): Unable to open env file: "
                       "/etc/default/locale"))
    lineas.append((ahora + 0.30, "systemd-logind", PID_LOGIND,
                   "New session %d of user %s." % (sesion, usuario)))

    lineas.sort(key=lambda x: x[0])
    return lineas


def construir(host: str, usuario: str, uid: int, ip: str, puerto: int,
              ahora: float, sin_locale: bool, sesion: int) -> str:
    """El auth.log entero, hasta la entrada del propio atacante.

    Del journal se queda con lo de authpriv, que es lo que rsyslog manda a
    este fichero: las sesiones PAM y el ssh. La orden que ejecuta cron NO
    entra ---esa es de la facilidad cron--- y por eso los eventos que la
    llevan vienen marcados.
    """
    return "\n".join(linea(host, ev) for ev in
                      eventos(usuario, uid, ip, puerto, ahora, sin_locale,
                              sesion)
                      if len(ev) == 4) + "\n"


def datos_sesion(protocol) -> tuple:
    """(usuario, uid, ip, puerto, sesion) de quien esta conectado.

    Vive aqui y no en cada sitio porque lo usan DOS: este fichero y
    journalctl. El puerto se lleva la peor parte: cuando Cowrie no lo dice,
    el valor de reserva tiene que ser el MISMO en las dos llamadas. Con un
    random.randint suelto ---que es lo que habia--- el auth.log decia un
    puerto y el journalctl decia otro para la misma conexion, y eso es una
    contradiccion que se ve poniendo los dos registros uno al lado del otro.
    Se saca de la IP, que no cambia dentro de una sesion.
    """
    usuario = getattr(getattr(protocol, "user", None), "username", "root")
    uid = int(getattr(getattr(protocol, "user", None), "uid", 0) or 0)
    ip = getattr(protocol, "clientIP", "127.0.0.1")
    puerto = int(getattr(protocol, "realClientPort", 0) or 0)
    if not puerto:
        puerto = 32768 + (sum(ord(c) for c in str(ip)) * 7919) % 28232
    entorno = getattr(protocol, "environ", None) or {}
    try:
        sesion = int(entorno.get("XDG_SESSION_ID", "24"))
    except (TypeError, ValueError):
        sesion = 24
    return usuario, uid, ip, puerto, sesion


def generar(protocol) -> None:
    """Deja el fichero en el sistema falso. No puede tumbar una sesion."""
    try:
        fs = protocol.fs
        usuario, uid, ip, puerto, sesion = datos_sesion(protocol)
        host = getattr(protocol, "hostname", "localhost")
        # La linea del pam_env solo si de verdad falta el fichero. Si algun
        # dia la maquina trae /etc/default/locale, desaparece sola.
        sin_locale = not fs.exists("/etc/default/locale")

        texto = construir(host, usuario, uid, ip, puerto, time.time(),
                          sin_locale, sesion)
        datos = texto.encode("utf-8", "replace")

        from cowrie.core.artifact import Artifact

        # 0640 y root:root. Lo segundo NO es el root:adm de toda la vida:
        # en trixie es root:root, medido.
        fs.mkfile(RUTA, 0, 0, len(datos), 0o100640)
        artefacto = Artifact("authlog")
        with artefacto:
            artefacto.write(datos)
        fs.update_realfile(fs.getfile(RUTA), artefacto.shasumFilename)
    except Exception:                                      # noqa: BLE001
        # Un fallo aqui no puede llevarse la sesion por delante: como mucho el
        # fichero se queda como estaba.
        pass
