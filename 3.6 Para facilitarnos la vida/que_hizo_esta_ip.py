#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
que_hizo_esta_ip.py
Todo lo que UNA IP ha hecho aqui, hora por hora, y sus hallazgos aparte en un
tar cifrado.

    sudo ~/que_hizo_esta_ip.py                  pregunta la IP
    sudo ~/que_hizo_esta_ip.py 198.51.100.23      con la IP ya puesta

NO LLEVA NI UN PARAMETRO, a proposito. Lo que hay que decidir ---la ventana de
tiempo, si se quiere el log entero o solo los comandos, si se quiere el tar---
lo pregunta el guion y se contesta con s o con n. Una opcion en la linea de
ordenes es una opcion que hay que recordar, y esta carpeta existe justamente
para no tener que recordar nada. Lo unico que se puede escribir en la orden es
la IP, que no es una opcion: es el sujeto, y se pega del aviso de Telegram.

DEJA DOS FICHEROS en el home de quien lo lanza, y son dos a proposito:

    ficha-<IP>-<fecha>.txt            EL LOG: que hizo, hora por hora
    ficha-<IP>-<fecha>.tar.gz.enc     LOS HALLAZGOS: los binarios que bajo, las
                                      grabaciones del terminal, las lineas
                                      crudas del log y lo que se publico de el

El primero se lee aqui mismo y no lleva ni un binario dentro. El segundo SI, y
por eso va cifrado.

POR QUE EXISTE. Cuando llega un aviso al movil con una IP, lo siguiente que se
quiere saber es siempre lo mismo ---que hizo, cuando, que bajo, si sigue
volviendo--- y contestarlo a mano son cinco o seis ordenes largas: un `grep`
sobre un cowrie.json de cientos de megas, un `sqlite3` a la base de Dionaea,
un `nft list set` para ver si esta baneada, y buscar cada binario por su hash
en la carpeta de descargas. Cinco ordenes que hay que recordar y teclear bien a
las tres de la manana no se teclean: se mira el aviso y se pasa.

EL TAR VA CIFRADO CON 1234, Y NO ES UN SECRETO. Es lo mismo que hace el
respaldo del apartado 3.7.11 y por el mismo motivo: en cuanto un .tar.gz con
muestras toca un disco Windows, Defender mira dentro, ve los binarios
capturados y TE LOS PONE EN CUARENTENA ---y entonces el hash de esa captura ya
no cuadra con lo que se denuncio---. Cifrado, el antivirus ve ruido y lo deja
pasar. Cualquiera con el fichero lo abre al instante: la proteccion de verdad
es no dejarlo rodando y borrarlo en cuanto se use.

Y es la MISMA contrasena que el respaldo, tambien a proposito: dos claves
distintas para dos ficheros que se bajan igual solo servirian para probar las
dos. Va escrita aqui, en el README y dentro del propio tar.

LAS HORAS SON UTC, todas, y cada bloque lo dice. Cowrie firma sus marcas con
una "Z" pero escribe la hora LOCAL del contenedor ---con el senuelo en Kyiv son
tres horas de mas---, asi que se corrigen al leer, con el huso que declara el
config.ini del reporter. Dionaea no tiene el problema: guarda epoch.

NO CAMBIA NADA Y NO EJECUTA NADA. Lee los logs, la base de Dionaea, la del
reporter y la tabla del cortafuegos; de los binarios solo copia el fichero y
mira su tamano y su hash. Ni una muestra se ejecuta, ni se borra nada, ni se
toca el senuelo.
"""

from __future__ import annotations

import collections
import configparser
import glob as _glob
import gzip
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

# Todo lo que se puede cambiar de sitio se lee del entorno, y no porque haga
# falta en la VPS ---alli los valores de abajo son los buenos--- sino para que
# la suite pueda apuntar a un arbol de mentira sin tocar el codigo. Es lo mismo
# que hace voy_al_dia.py con DIRTYLAND_REPO.
CFG = os.environ.get("DIRTYLAND_CFG",
                     "/opt/dirtyland/platform-reporter/config.ini")
GEOIP = os.environ.get("DIRTYLAND_GEOIP", "/opt/dirtyland/geoip")
NFT = os.environ.get("DIRTYLAND_NFT", "/usr/sbin/nft")
TABLA_NFT = os.environ.get("DIRTYLAND_TABLA_NFT", "inet dirtyland")

# La contrasena del tar. Ver la cabecera: esta para que el antivirus del equipo
# de destino no mire dentro, no para que no lo lea una persona.
CLAVE_TAR = "1234"

# El sha256 de un fichero VACIO. Cowrie firma cada grabacion del terminal con el
# hash de lo grabado, asi que este valor significa "aqui no se grabo nada": pasa
# con las sesiones de telnet que no llegan a teclear. Se comprueba en un segundo
# con  printf "" | sha256sum.
SHA_VACIO = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Cuantos binarios de Dionaea se hashean como maximo para atarlos con su fila
# de descarga. La carpeta suele tener unos cientos; el tope esta para que una
# carpeta enorme no convierta una consulta de diez segundos en una de diez
# minutos sin avisar. Si se llega al tope, la ficha lo dice.
TOPE_HASHEO = 3000

# Valores por defecto: los mismos del config.ini.example. Se usan SOLO si el
# config.ini no se puede leer, para que esto siga sirviendo en una maquina a
# medio instalar. En la instalada manda el fichero, que es el que se mantiene al
# dia ---una segunda lista de rutas es una lista que algun dia dice otra cosa, y
# justo el dia que se mueva un volumen---.
POR_DEFECTO = {
    "cowrie_log_dir":
        "/var/lib/docker/volumes/dirtyland_cowrie-var/_data/log/cowrie",
    "cowrie_log_glob": "cowrie.json*",
    "downloads_dir":
        "/var/lib/docker/volumes/dirtyland_cowrie-var/_data/lib/cowrie/downloads",
    "cowrie_log_tz": "Europe/Kyiv",
    "cowrie_puertos_publicos": "2222:22, 2223:23",
    "dionaea_sqlite":
        "/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite",
    "dionaea_binaries":
        "/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/binaries",
    "state_db": "/var/lib/dirtyland-reporter/state.sqlite3",
    "blocklist_ips": "",
    "blocklist_cidrs": "",
}

# Lo que se reserva en la barra para todo lo que NO es leer el log: consultar
# Dionaea, hashear los binarios, escribir la ficha y cifrar el tar. Se mide en
# la misma unidad que la lectura ---bytes--- porque la barra es una sola, y sale
# de un porcentaje de lo que hay que leer para que en un log pequeno no se coma
# la barra entera y en uno grande siga viendose.
#
# No pretende ser una prediccion de tiempo: leer 400 MB de JSON tarda mucho mas
# que cifrar un tar de dos megas. Lo que tiene que hacer es MOVERSE y llegar al
# final, que es lo que dice que el programa no se ha colgado.
RESERVA_FINAL = 0.10


# -------------------------------------------------------------------- la barra
#
# POR QUE HACE FALTA. Entre teclear la IP y ver el resultado hay dos pasadas
# sobre todo el cowrie.json ---que en una maquina que lleva meses expuesta son
# cientos de megas repartidos en ocho o diez ficheros---, y antes aqui solo se
# escribia "leyendo 8 fichero(s)..." y luego nada. Un minuto sin una sola linea
# nueva no se distingue de un programa colgado, y lo que hace uno entonces es
# matarlo con Ctrl-C justo cuando estaba a la mitad.
#
# SE MIDE EN BYTES DEL LOG y no en ficheros: con ocho ficheros la barra daria
# ocho saltos, y el ultimo ---el cowrie.json de hoy, que es el mas gordo---
# tardaria mas que los siete anteriores juntos sin que la barra se moviera.
class Barra:
    """Una barra clasica, de las de toda la vida, en una sola linea."""

    ANCHO = 28

    def __init__(self, total: float, activa: bool | None = None) -> None:
        self.total = max(float(total), 1.0)
        self.hecho = 0.0
        self.etiqueta = ""
        self._ultimo = 0.0
        self._cerrada = False
        # SIN TERMINAL NO SE PINTA NINGUNA BARRA. Un "\r" en un fichero de log
        # o en una tuberia deja una linea ilegible de miles de caracteres; ahi
        # se escribe una linea por etapa, que es lo que sirve para leerlo
        # despues. Lo mismo que hacen los vigilantes con los colores.
        if activa is None:
            try:
                activa = bool(sys.stdout.isatty())
            except Exception:                             # noqa: BLE001
                activa = False
        self.activa = activa

    def etapa(self, texto: str) -> None:
        self.etiqueta = texto
        if self.activa:
            self.pinta(forzar=True)
        else:
            print("  ... %s" % texto, flush=True)

    def avanza(self, cuanto: float) -> None:
        self.hecho = min(self.hecho + cuanto, self.total)
        self.pinta()

    def pinta(self, forzar: bool = False) -> None:
        if not self.activa or self._cerrada:
            return
        # Como mucho diez veces por segundo: repintar en cada linea de un log de
        # cientos de miles cuesta mas que leerlo.
        ahora = time.monotonic()
        if not forzar and ahora - self._ultimo < 0.1:
            return
        self._ultimo = ahora
        parte = self.hecho / self.total
        lleno = int(parte * self.ANCHO)
        print("\r  [%s%s] %3d%%  %-38s"
              % ("#" * lleno, "-" * (self.ANCHO - lleno), int(parte * 100),
                 self.etiqueta[:38]), end="", flush=True)

    def cierra(self, texto: str = "listo") -> None:
        """Deja la barra al 100 y baja de linea, para lo que venga detras."""
        if self._cerrada:
            return
        self.hecho = self.total
        self.etiqueta = texto
        if self.activa:
            self.pinta(forzar=True)
            print()
        self._cerrada = True


def tamano_legible(n: float) -> str:
    """1234567 -> "1.2 MB". Para decir cuanto hay que leer antes de leerlo."""
    for unidad in ("B", "KB", "MB", "GB"):
        if n < 1024 or unidad == "GB":
            return "%.0f %s" % (n, unidad) if unidad == "B" else "%.1f %s" % (n, unidad)
        n /= 1024.0
    return "%.1f GB" % n


def peso_de_log(ruta: str) -> int:
    """Lo que hay que LEER de ese fichero, descomprimido.

    De un .gz se saca de sus cuatro ultimos bytes, que es donde gzip guarda el
    tamano original: asi la barra sabe cuanto queda sin tener que descomprimir
    el fichero una vez de mas solo para medirlo. Si eso falla ---un .gz a medio
    escribir--- vale el tamano en disco, que se queda corto pero no rompe nada:
    la barra llegaria al 100% antes de tiempo y ya esta.
    """
    try:
        if ruta.endswith(".gz"):
            with open(ruta, "rb") as fh:
                fh.seek(-4, os.SEEK_END)
                tamano = int.from_bytes(fh.read(4), "little")
            if tamano > 0:
                return tamano
        return os.path.getsize(ruta)
    except OSError:
        return 0


# ---------------------------------------------------------------- las rutas
def rutas() -> dict[str, str]:
    """Donde esta cada cosa, segun el config.ini del reporter."""
    datos = dict(POR_DEFECTO)
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    try:
        cp.read(CFG, encoding="utf-8")
    except Exception:                                     # noqa: BLE001
        return datos
    for clave in ("cowrie_log_dir", "cowrie_log_glob", "downloads_dir",
                  "cowrie_log_tz", "cowrie_puertos_publicos",
                  "dionaea_sqlite", "dionaea_binaries"):
        valor = cp.get("paths", clave, fallback="").strip()
        if valor:
            datos[clave] = valor
    valor = cp.get("general", "state_db", fallback="").strip()
    if valor:
        datos["state_db"] = valor
    datos["blocklist_ips"] = cp.get("blocklist", "ips", fallback="")
    datos["blocklist_cidrs"] = cp.get("blocklist", "cidrs", fallback="")
    return datos


def mapa_puertos(crudo: str) -> dict[int, int]:
    """"2222:22, 2223:23" -> {2222: 22, 2223: 23}.

    Cowrie escribe el puerto en el que EL escucha dentro del contenedor, no el
    que marco el atacante. Sin traducir, la ficha diria "puerto 2222", que es un
    puerto al que nadie ha llamado nunca. Misma tabla y mismo motivo que en el
    recolector del reporter.
    """
    tabla: dict[int, int] = {}
    for trozo in re.split(r"[,\s]+", crudo or ""):
        if ":" not in trozo:
            continue
        dentro, fuera = trozo.split(":", 1)
        try:
            tabla[int(dentro)] = int(fuera)
        except ValueError:
            continue
    return tabla


def puerto_publico(puerto, tabla: dict[int, int]):
    try:
        return tabla.get(int(puerto), int(puerto))
    except (TypeError, ValueError):
        return puerto


def es_nuestra(ip: str, r: dict[str, str]) -> bool:
    """True si esa IP es de las nuestras, segun la [blocklist] del reporter.

    La lista vive en un solo sitio, que es la que ya se mantiene al dia porque
    de ella depende no denunciarnos a nosotros mismos. Aqui solo sirve para
    avisar: la ficha de nuestro propio nodo de VPN se saca igual, pero conviene
    saber de quien es antes de leerla como si fuera la de un atacante.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not addr.is_global:
        return True
    trocear = lambda v: [x for x in re.split(r"[,\s]+", v or "")
                         if x and not x.startswith("<")]
    for uno in trocear(r.get("blocklist_ips", "")):
        try:
            if addr == ipaddress.ip_address(uno):
                return True
        except ValueError:
            continue
    for red in trocear(r.get("blocklist_cidrs", "")):
        try:
            if addr in ipaddress.ip_network(red, strict=False):
                return True
        except ValueError:
            continue
    return False


# ------------------------------------------------------------------ el huso
#
# COWRIE FIRMA SUS MARCAS CON UNA "Z" Y ESCRIBE LA HORA LOCAL DEL CONTENEDOR.
# Con el senuelo en Europe/Kyiv son tres horas de mas, y no se nota en ningun
# sitio: la cadena es ISO valida y se interpreta sin error. Ya mordio una vez
# ---AbuseIPDB recibia denuncias fechadas en el futuro--- y esta contado entero
# en collectors/cowrie.py.
#
# Aqui se repite la correccion en lugar de importar aquel modulo, que arrastra
# el paquete del reporter entero. Para que las dos no se separen con el tiempo,
# la suite extrae las dos funciones de sus ficheros y comprueba que dan el MISMO
# resultado sobre las mismas marcas. Es lo que ya hace test_analisis.py.
_CON_HUSO = re.compile(r"[+-]\d{2}:?\d{2}$")


def parse_timestamp(raw: str | None, tz: tzinfo = timezone.utc):
    """La marca de un evento de Cowrie, en UTC de verdad."""
    if not raw:
        return None
    explicito = _CON_HUSO.search(raw) is not None
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if explicito:
        return ts.astimezone(timezone.utc)
    return ts.replace(tzinfo=None).replace(tzinfo=tz).astimezone(timezone.utc)


def resolver_huso(nombre: str) -> tzinfo:
    """Nombre IANA -> huso. Si no se reconoce, UTC Y SE DICE.

    Caer a UTC en silencio es lo peor que podria hacer: la ficha sale entera,
    con pinta de correcta, y con todas las horas tres horas corridas.
    """
    if not nombre or nombre.upper() == "UTC":
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo                      # noqa: PLC0415
        return ZoneInfo(nombre)
    except Exception as exc:                              # noqa: BLE001
        print("  aviso: no se pudo resolver el huso %r (%s): las horas de "
              "Cowrie saldran SIN corregir." % (nombre, exc), file=sys.stderr)
        print("         en Windows falta la base de husos: pip install tzdata",
              file=sys.stderr)
        return timezone.utc


# -------------------------------------------------------------- leer el log
# QUE HACER CON LO QUE NO ES TEXTO.
#
# Un atacante no teclea texto: manda BYTES, y ahi caben escapes de terminal,
# nulos, trozos de binario y cachos de UTF-8 a medias. Con errors="replace" ---lo
# que habia antes--- cada byte de esos se convertia en un U+FFFD, que en un
# editor de Windows sale como un rombo negro con un interrogante: se pierde el
# valor del byte Y ademas no se sabe si el rombo lo escribio el atacante o lo
# puso el editor por no saber pintarlo.
#
# Con "surrogateescape" el byte se guarda entero ---en el hueco U+DC80..U+DCFF---
# asi que luego se puede escribir como \xNN y volver a leerlo tal cual salio del
# log. Es lo mismo que hace Python con los nombres de fichero que no son UTF-8.
def _abrir(ruta: str):
    if ruta.endswith(".gz"):
        return gzip.open(ruta, "rt", encoding="utf-8", errors="surrogateescape")
    return open(ruta, "rt", encoding="utf-8", errors="surrogateescape")


def texto_plano(s: str) -> str:
    """El texto, dejado en ASCII imprimible y marcando lo que no lo era.

    LA FICHA ENTERA ES ASCII, y eso no es una manía: se abre en un Notepad de
    Windows, en un `less` de la VPS y en lo que haya, y ninguno puede
    estropearla ni hacer dudar de lo que vio el senuelo. Lo que no es ASCII
    imprimible se escribe de forma que se lea y no se pueda confundir:

        byte suelto que no es texto   \\xe2      (el valor exacto que llego)
        caracter de control           ^[  ^@    (como lo ensena `cat -v`)
        lo que Cowrie ya no pudo leer <?>       (llego asi al log)
        cualquier otro no ASCII       <U+00F1>

    Y NO SE PIERDE NADA: la linea original, byte por byte, va en el
    eventos-cowrie.json del tar. Esto es la copia para leer.
    """
    salida = []
    for c in s:
        n = ord(c)
        if n == 9 or 32 <= n <= 126:            # tabulador y ASCII imprimible
            salida.append(c)
        elif 0xDC80 <= n <= 0xDCFF:             # un byte crudo del log
            salida.append("\\x%02x" % (n - 0xDC00))
        elif c == "�":                     # ya venia roto del log
            salida.append("<?>")
        elif n < 32 or n == 127:                # control: ^[ para el ESC
            salida.append("^%s" % chr((n + 64) % 128))
        else:
            salida.append("<U+%04X>" % n)
    return "".join(salida)


def sin_banderas(s: str) -> str:
    """La etiqueta del pais sin el emoji de la bandera.

    La bandera son dos "indicadores regionales" de Unicode, y las fuentes de
    consola de Windows no los traen: salen dos cuadros. En un aviso de Telegram
    se ven y ayudan; en un fichero de texto no aportan nada que no diga ya el
    nombre del pais escrito al lado.
    """
    return " ".join(c for c in s.split()
                    if not all(0x1F1E6 <= ord(x) <= 0x1F1FF for x in c))


def ficheros_de_log(r: dict[str, str]) -> list[str]:
    return sorted(_glob.glob(os.path.join(r["cowrie_log_dir"],
                                          r["cowrie_log_glob"])))


def sesiones_de(ficheros: list[str], ip: str, barra: Barra | None = None) -> set[str]:
    """Las sesiones que abrio esa IP.

    Primera de las dos pasadas. Hace falta porque no todos los eventos de una
    sesion llevan la IP: el que dice donde quedo la grabacion del terminal
    (cowrie.log.closed) va con el numero de sesion y poco mas, y sin esta lista
    la grabacion se quedaria fuera del tar sin que nada lo dijera.
    """
    ses: set[str] = set()
    for ruta in ficheros:
        # La barra se mueve cada 4000 lineas y no en cada una: llamarla por
        # linea, en un fichero de un millon, cuesta mas que el propio filtro.
        acumulado, cuantas = 0, 0
        try:
            with _abrir(ruta) as fh:
                for linea in fh:
                    if barra is not None:
                        acumulado += len(linea)
                        cuantas += 1
                        if cuantas >= 4000:
                            barra.avanza(acumulado)
                            acumulado, cuantas = 0, 0
                    # El "ip in linea" es un filtro barato ANTES del json.loads,
                    # que es lo caro: un cowrie.json de varios cientos de megas
                    # no se puede parsear entero linea a linea. Que cace de mas
                    # ---una orden que MENCIONA la IP--- no importa: lo de abajo
                    # compara el campo exacto.
                    if ip not in linea:
                        continue
                    try:
                        ev = json.loads(linea)
                    except ValueError:
                        continue
                    if ev.get("src_ip") == ip and ev.get("session"):
                        ses.add(str(ev["session"]))
        except OSError:
            continue
        if barra is not None:
            barra.avanza(acumulado)
    return ses


def eventos_cowrie(ficheros: list[str], ip: str, sesiones: set[str],
                   tz: tzinfo, desde, barra: Barra | None = None):
    """(eventos, lineas crudas) de esa IP, en orden.

    Los eventos son (marca_utc, evento). Las lineas crudas se guardan tal cual
    para el tar: son LA evidencia, y un informe reescrito no sirve para
    acreditar nada ante una plataforma.
    """
    # Un solo filtro para las dos cosas que valen: la IP o una de sus sesiones.
    # Se compila una vez y se pasa por cada linea.
    trozos = [re.escape(ip)] + [re.escape(s) for s in sorted(sesiones)]
    filtro = re.compile("|".join(trozos))

    eventos, crudas = [], []
    for ruta in ficheros:
        acumulado, cuantas = 0, 0
        try:
            with _abrir(ruta) as fh:
                for linea in fh:
                    if barra is not None:
                        acumulado += len(linea)
                        cuantas += 1
                        if cuantas >= 4000:
                            barra.avanza(acumulado)
                            acumulado, cuantas = 0, 0
                    if not filtro.search(linea):
                        continue
                    try:
                        ev = json.loads(linea)
                    except ValueError:
                        continue
                    if ev.get("src_ip") != ip and \
                            str(ev.get("session", "")) not in sesiones:
                        continue
                    ts = parse_timestamp(ev.get("timestamp"), tz)
                    if ts is None:
                        continue
                    if desde and ts < desde:
                        continue
                    eventos.append((ts, ev))
                    crudas.append(linea.rstrip("\n"))
        except OSError:
            continue
        if barra is not None:
            barra.avanza(acumulado)
    orden = sorted(range(len(eventos)), key=lambda i: eventos[i][0])
    return [eventos[i] for i in orden], [crudas[i] for i in orden]


# ------------------------------------------------------------- lo de Dionaea
def _abrir_solo_lectura(ruta: str) -> sqlite3.Connection:
    """La base, en modo solo lectura. Dionaea esta escribiendo en la suya.

    Con `as_uri()` y no con un "file:" pegado a mano: en Windows ---donde se
    corre la suite--- la letra de unidad y las barras invertidas no forman una
    URI valida y sqlite se niega a abrirla. Si aun asi falla, se abre normal:
    aqui no se escribe nada en ningun caso.
    """
    try:
        return sqlite3.connect(Path(ruta).absolute().as_uri() + "?mode=ro",
                               uri=True)
    except (sqlite3.OperationalError, ValueError):
        return sqlite3.connect(ruta)


def _hay_tabla(db, nombre: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND "
                      "name=?", (nombre,)).fetchone() is not None


def _columnas(db, tabla: str) -> list[str]:
    try:
        return [f[1] for f in db.execute("PRAGMA table_info(%s)" % tabla)]
    except sqlite3.Error:
        return []


def _ts_de_conexion(db, conexion):
    try:
        f = db.execute("SELECT connection_timestamp FROM connections WHERE "
                       "connection=?", (conexion,)).fetchone()
        return datetime.fromtimestamp(int(f[0]), tz=timezone.utc) if f else None
    except (sqlite3.Error, TypeError, ValueError):
        return None


def eventos_dionaea(r: dict[str, str], ip: str, desde):
    """(eventos, descargas, puertos) de esa IP en Dionaea.

    Aqui no hay ninguna hora que corregir: Dionaea guarda epoch, que es la
    unica marca de este proyecto que no miente.

    Solo cuentan las conexiones 'accept'. Un 'reject' no llego a establecerse y
    un 'listen' es un socket NUESTRO; el mismo criterio que el recolector.
    """
    ruta = r["dionaea_sqlite"]
    if not os.path.isfile(ruta):
        return [], [], set()
    try:
        db = _abrir_solo_lectura(ruta)
    except sqlite3.Error:
        return [], [], set()
    db.row_factory = sqlite3.Row

    # Algunas versiones anotan las IPv4 como "::ffff:1.2.3.4". Se preguntan las
    # dos formas: pedir solo una deja la mitad de las conexiones fuera y la
    # ficha diria que por SMB no entro nadie.
    formas = (ip, "::ffff:" + ip) if ":" not in ip else (ip, ip)

    eventos: list[tuple] = []
    puertos: set = set()
    de_esta_ip: set = set()
    try:
        filas = db.execute(
            "SELECT connection, remote_port, local_port,"
            "       connection_protocol, connection_timestamp"
            "  FROM connections"
            " WHERE connection_type='accept' AND remote_host IN (?, ?)",
            formas).fetchall()
    except sqlite3.Error:
        filas = []
    for f in filas:
        try:
            ts = datetime.fromtimestamp(int(f["connection_timestamp"]),
                                        tz=timezone.utc)
        except (TypeError, ValueError):
            continue
        de_esta_ip.add(f["connection"])
        if desde and ts < desde:
            continue
        puertos.add(f["local_port"])
        eventos.append((ts, "DIONAEA CONEXION",
                        "puerto %s   %s   desde su puerto %s"
                        % (f["local_port"], f["connection_protocol"] or "?",
                           f["remote_port"])))

    # Lo que se teclea por MSSQL. El texto no se publica en ninguna parte ---eso
    # lo decide el reporter--- pero es lo que dice si aquello fue un escaneo o
    # un intento de ejecutar algo.
    if _hay_tabla(db, "mssql_commands"):
        cols = _columnas(db, "mssql_commands")
        cual = next((c for c in ("cmd", "mssql_command_cmd", "command")
                     if c in cols), None)
        if cual:
            try:
                filas = db.execute("SELECT connection, %s AS cuerpo FROM "
                                   "mssql_commands" % cual).fetchall()
            except sqlite3.Error:
                filas = []
            for f in filas:
                if f["connection"] not in de_esta_ip:
                    continue
                cuerpo = f["cuerpo"] or ""
                if isinstance(cuerpo, (bytes, bytearray)):
                    cuerpo = cuerpo.decode("utf-8", "replace")
                ts = _ts_de_conexion(db, f["connection"])
                if ts is None or (desde and ts < desde):
                    continue
                eventos.append((ts, "DIONAEA MSSQL", cuerpo.strip()))

    descargas: list[dict] = []
    if _hay_tabla(db, "downloads"):
        cols = _columnas(db, "downloads")
        col_url = next((c for c in cols if "url" in c.lower()), None)
        col_md5 = next((c for c in cols if "md5" in c.lower()), None)
        col_sha = next((c for c in cols if "sha" in c.lower()), None)
        campos = ["d.connection AS conn"]
        campos.append("d.%s AS url" % col_url if col_url else "'' AS url")
        campos.append("d.%s AS md5" % col_md5 if col_md5 else "NULL AS md5")
        campos.append("d.%s AS sha" % col_sha if col_sha else "NULL AS sha")
        try:
            filas = db.execute("SELECT %s FROM downloads d"
                               % ", ".join(campos)).fetchall()
        except sqlite3.Error:
            filas = []
        for f in filas:
            if f["conn"] not in de_esta_ip:
                continue
            ts = _ts_de_conexion(db, f["conn"])
            if ts is None or (desde and ts < desde):
                continue
            descargas.append({"ts": ts, "url": f["url"] or "",
                              "md5": str(f["md5"] or "").lower(),
                              "sha": str(f["sha"] or "").lower()})
    db.close()
    eventos.sort(key=lambda e: e[0])
    return eventos, descargas, puertos


def hashes_de(ruta: str) -> tuple[str, str] | None:
    """(md5, sha256) del fichero, en una sola lectura.

    Los dos, porque Dionaea nombra sus binarios de una forma u otra segun la
    version y su fila de descarga puede traer solo el md5. El sha256 es el hash
    con el que trabajan VirusTotal y MalwareBazaar, o sea el que sirve para
    buscar la muestra despues.
    """
    md5, sha = hashlib.md5(), hashlib.sha256()
    try:
        with open(ruta, "rb") as fh:
            for trozo in iter(lambda: fh.read(1 << 20), b""):
                md5.update(trozo)
                sha.update(trozo)
    except OSError:
        return None
    return md5.hexdigest(), sha.hexdigest()


def indice_binarios(carpeta: str) -> tuple[dict[str, str], bool]:
    """{hash: ruta} de la carpeta de binarios de Dionaea, y si se llego al tope.

    Se indexa por nombre Y por los dos hashes calculados del fichero. Fiarse del
    nombre es lo que hacia el recolector al principio ---daba por hecho que
    Dionaea nombra por MD5 cuando esta version nombra por SHA-256--- y por eso
    no ataba ni un binario con su fila de descarga.
    """
    indice: dict[str, str] = {}
    if not os.path.isdir(carpeta):
        return indice, False
    nombres = sorted(os.listdir(carpeta))
    tope = len(nombres) > TOPE_HASHEO
    for nombre in nombres[:TOPE_HASHEO]:
        ruta = os.path.join(carpeta, nombre)
        if not os.path.isfile(ruta):
            continue
        indice.setdefault(nombre.lower(), ruta)
        pareja = hashes_de(ruta)
        if pareja:
            indice.setdefault(pareja[0], ruta)
            indice.setdefault(pareja[1], ruta)
    return indice, tope


# -------------------------------------------------------- pais y cortafuegos
def pais_de(ip: str) -> str:
    """La bandera y el pais, de la tabla local. Vacio si no se puede.

    Es un adorno de la cabecera: si falta la tabla, la ficha sale igual.
    """
    ruta = os.path.join(GEOIP, "paises.py")
    if not os.path.isfile(ruta):
        return ""
    try:
        spec = importlib.util.spec_from_file_location("paises_ficha", ruta)
        modulo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modulo)
        return modulo.etiqueta(ip) or ""
    except Exception:                                     # noqa: BLE001
        return ""


def baneo_de(ip: str) -> tuple[str | None, str]:
    """(comentario del baneo, elemento crudo) si esa IP esta baneada ahora.

    Se le pregunta a nftables y no a un registro nuestro, por lo mismo que
    baneadas-diario.sh: la tabla del kernel es la unica fuente que dice lo que
    la maquina esta bloqueando AHORA. Y el comentario es lo unico que distingue
    un baneo automatico de uno que pulsaste tu en Telegram.
    """
    if not (os.path.exists(NFT) or shutil.which(NFT)):
        return None, ""
    conjunto = "ban6" if ":" in ip else "ban4"
    try:
        salida = subprocess.run([NFT, "list", "set", *TABLA_NFT.split(),
                                 conjunto], capture_output=True, text=True,
                                timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None, ""
    if salida.returncode != 0:
        return None, ""
    # Los elementos vienen separados por comas y repartidos en varias lineas,
    # con su comentario detras: se aplana todo y se corta por comas, igual que
    # en baneadas-diario.sh.
    plano = " ".join(salida.stdout.split())
    lista = re.search(r"elements = \{(.*?)\}", plano)
    if not lista:
        return None, ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, ""
    for trozo in lista.group(1).split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        try:
            # Comparar direcciones y no cadenas: un IPv6 se puede escribir de
            # varias formas y la del kernel no tiene por que ser la tecleada.
            if ipaddress.ip_address(trozo.split()[0]) != addr:
                continue
        except ValueError:
            continue
        comentario = re.search(r'comment "([^"]*)"', trozo)
        return (comentario.group(1) if comentario else "sin comentario"), trozo
    return None, ""


# ----------------------------------------------------------- lo del reporter
def lo_publicado(r: dict[str, str], ip: str, shas: list[str]) -> list[str]:
    """Que se publico y que se descarto de esta IP y de sus muestras."""
    base = r["state_db"]
    if not os.path.isfile(base):
        return ["  (no hay base de estado del reporter en %s)" % base]
    try:
        db = _abrir_solo_lectura(base)
    except sqlite3.Error as exc:
        return ["  (no se pudo abrir %s: %s)" % (base, exc)]
    db.row_factory = sqlite3.Row
    lineas: list[str] = []

    # El LIKE es un cedazo, no la respuesta: "1.2.3.4" casa tambien dentro de
    # "11.2.3.45". Lo que decide es el repaso con esta expresion, que exige que
    # la IP no venga pegada a otro digito ni a otro punto.
    limite = re.compile(r"(?<![\d.])%s(?![\d.])" % re.escape(ip))

    def filas(consulta, patron):
        try:
            return [f for f in db.execute(consulta, (patron,))
                    if limite.search(f["key"] or "")]
        except sqlite3.Error:
            return []

    env = filas("SELECT platform, status, sent_at, key, detail FROM sent "
                "WHERE key LIKE ? ORDER BY sent_at", "%" + ip + "%")
    lineas.append("  PUBLICADO de esta IP:")
    if not env:
        lineas.append("    nada")
    for f in env:
        lineas.append("    %s  %-14s %-10s %s"
                      % ((f["sent_at"] or "")[:19], f["platform"], f["status"],
                         f["detail"] or ""))

    rz = filas("SELECT ts, platform, gate, key, reason FROM rejections "
               "WHERE key LIKE ? ORDER BY ts DESC", "%" + ip + "%")
    lineas.append("")
    lineas.append("  DESCARTADO de esta IP: %d" % len(rz))
    for f in rz[:10]:
        lineas.append("    %s  %-14s [%s]"
                      % ((f["ts"] or "")[:19], f["platform"], f["gate"]))
        lineas.append("        %s" % (f["reason"] or "")[:150])
    if len(rz) > 10:
        lineas.append("    ... y %d mas. El por que de cada puerta lo explica "
                      "~/que_pasa_con_las_plataformas.py" % (len(rz) - 10))

    if shas:
        lineas.append("")
        lineas.append("  SUS MUESTRAS en la base del reporter:")
        for sha in sorted(set(shas)):
            try:
                f = db.execute("SELECT state, family, vt_malicious FROM samples"
                               " WHERE sha256=?", (sha,)).fetchone()
            except sqlite3.Error:
                f = None
            if not f:
                lineas.append("    %s  no esta en la base: el colector no la "
                              "recogio" % sha[:16])
                continue
            lineas.append("    %s  %-12s motores %-4s familia %s"
                          % (sha[:16], f["state"],
                             f["vt_malicious"] if f["vt_malicious"] is not None
                             else "-", f["family"] or "-"))
    db.close()
    return lineas


# ------------------------------------------------------------------ la ficha
def texto_evento(ev: dict, tabla: dict[int, int], shas_en_disco: set[str],
                 grabaciones: dict[str, int | None] | None = None
                 ) -> tuple[str, str]:
    """(etiqueta, cuerpo) de un evento de Cowrie.

    Lo que no se reconoce NO se tira: sale con su eventid y su mensaje. Un
    evento nuevo de Cowrie que desapareciera de la ficha seria un agujero que no
    veria nadie, y esta ficha vale justo por estar completa.
    """
    eid = str(ev.get("eventid", ""))
    if eid == "cowrie.session.connect":
        return ("SESION ABIERTA",
                "%s al puerto %s   sesion %s   (desde su puerto %s)"
                % ((ev.get("protocol") or "?").lower(),
                   puerto_publico(ev.get("dst_port"), tabla),
                   ev.get("session", "?"), ev.get("src_port", "?")))
    if eid == "cowrie.client.version":
        # Vacio cuando el cliente corta antes de anunciarse. Se dice, en vez de
        # dejar una etiqueta con nada detras.
        return ("CLIENTE", str(ev.get("version") or "(no llego a decirlo)"))
    if eid == "cowrie.client.kex":
        return ("HUELLA DEL CLIENTE", "hassh %s" % ev.get("hassh", "?"))
    if eid == "cowrie.client.fingerprint":
        return ("CLAVE PUBLICA OFRECIDA", str(ev.get("fingerprint", "")))
    if eid == "cowrie.login.success":
        return ("LOGIN CORRECTO", "%s / %s" % (ev.get("username", ""),
                                              ev.get("password", "")))
    if eid == "cowrie.login.failed":
        return ("login fallido", "%s / %s" % (ev.get("username", ""),
                                             ev.get("password", "")))
    if eid == "cowrie.command.input":
        return ("ORDEN", str(ev.get("input", "")))
    if eid == "cowrie.command.failed":
        # Esto no es un fallo del atacante: es el senuelo delatandose. Un
        # binario que su sistema de ficheros anuncia y Cowrie no sabe ejecutar.
        return ("ORDEN QUE EL SENUELO NO SUPO EJECUTAR",
                str(ev.get("input", "")))
    if eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        sha = str(ev.get("shasum", "") or "").lower()
        que = "DESCARGA" if eid.endswith("download") else "SUBIDA (scp)"
        origen = (ev.get("url") or ev.get("filename") or ev.get("destfile")
                  or ev.get("outfile") or "")
        if not sha:
            estado = "no se llego a capturar el binario"
        elif sha in shas_en_disco:
            estado = "va en el tar cifrado"
        else:
            estado = "el binario YA NO ESTA en la carpeta de descargas"
        return (que, "%s\nsha256 %s   (%s)" % (origen, sha or "-", estado))
    if eid.startswith("cowrie.direct-tcpip"):
        return ("INTENTO DE TUNEL",
                "hacia %s:%s   (usarnos de salto; Cowrie no lo permite)"
                % (ev.get("dst_ip", "?"), ev.get("dst_port", "?")))
    if eid == "cowrie.log.closed":
        # Lo que pesa EN EL DISCO, no el "size" del evento, y se dice cuando no
        # hay nada grabado. En el log salian cuatro sesiones de telnet con la
        # misma grabacion "de 315 bytes" cuyo hash es SHA_VACIO: eran cuatro
        # lineas anunciando un hallazgo que no existe.
        nombre = os.path.basename(str(ev.get("ttylog", "?")))
        pesa = (grabaciones or {}).get(nombre)
        if str(ev.get("shasum", "")).lower() == SHA_VACIO:
            estado = "no grabo nada: su hash es el de un fichero vacio"
        elif pesa is None:
            estado = "ya no esta en el disco"
        elif pesa == 0:
            estado = "vacia"
        else:
            estado = "%d bytes, va en el tar cifrado" % pesa
        return ("GRABACION DEL TERMINAL", "%s   (%s)" % (nombre, estado))
    if eid == "cowrie.session.closed":
        # EL CAMPO ES duration_ms, no "duration". Pidiendo el que no existe
        # salia "duracion ? s" en cada sesion: una linea por sesion para no
        # decir nada. Se lee igual que en ANALISIS/analisis.py, y se prueba que
        # los dos nombres sirvan por si cambia con la version de Cowrie.
        for clave, divisor in (("duration_ms", 1000.0), ("duration", 1.0)):
            valor = ev.get(clave)
            if isinstance(valor, (int, float)):
                return ("sesion cerrada", "duro %.1f s" % (valor / divisor))
        return ("sesion cerrada", "")
    return (eid or "evento sin nombre", str(ev.get("message", "")))


def solo_comandos(eventos: list[tuple]) -> list[str]:
    """LAS ORDENES QUE TECLEO, Y NADA MAS. Va lo primero de la ficha.

    Es la parte que se lee SIEMPRE, y por eso va delante: de una sesion de
    veinte minutos, lo que dice que buscaba el atacante son las diez lineas que
    escribio. Todo lo demas ---la negociacion de telnet, las variables de
    entorno que manda el cliente, los parametros de la sesion--- es como se
    monto la conversacion, no que dijo en ella.

    Solo entran los `cowrie.command.input`, que son las lineas TAL CUAL las
    tecleo. No entran los `cowrie.command.failed`, y no es un descuido: esos son
    la reaccion del senuelo ---lo que no supo ejecutar--- y ademas repiten el
    texto de la orden, o un trozo suyo. Aqui se veria la misma linea dos veces.

    Sin sangria y una orden por bloque, para que se puedan copiar y pegar tal
    cual en un analisis.
    """
    L = ["=" * 72, "SOLO COMANDOS".center(72), "=" * 72, ""]
    hubo = False
    for ts, ev in eventos:
        if str(ev.get("eventid", "")) != "cowrie.command.input":
            continue
        hubo = True
        L.append("[%s]" % ts.strftime("%Y-%m-%d %H:%M:%S"))
        L.append("")
        for trozo in str(ev.get("input", "")).splitlines() or [""]:
            L.append(trozo.rstrip())
        L.append("")
    if not hubo:
        L.append("(ninguno: por aqui no se tecleo nada)")
        L.append("")
    return L


def bloques_por_hora(lineas: list[tuple]) -> list[str]:
    """El log, hora por hora. Es el cuerpo de la ficha.

    Se agrupa por hora y no por sesion a proposito: lo que se quiere ver es la
    forma del ataque en el tiempo ---cuando entro, cuanto duro, si volvio al dia
    siguiente a la misma hora---, y eso se lee de un vistazo en bloques de una
    hora. La sesion va en su linea para quien la necesite.
    """
    salida: list[str] = []
    hora_actual = None
    grupo: list[tuple] = []

    def cerrar():
        if not grupo:
            return
        salida.append("=" * 72)
        salida.append("[%s UTC]   %d evento(s)"
                      % (hora_actual.strftime("%Y-%m-%d %H:00"), len(grupo)))
        salida.append("=" * 72)
        salida.append("")
        for ts, etiqueta, cuerpo in grupo:
            salida.append("[%s]  %s" % (ts.strftime("%Y-%m-%d %H:%M:%S"),
                                        etiqueta))
            for trozo in (cuerpo or "").splitlines():
                if trozo.strip():
                    salida.append("    %s" % trozo.rstrip())
            salida.append("")

    for ts, etiqueta, cuerpo in lineas:
        hora = ts.replace(minute=0, second=0, microsecond=0)
        if hora != hora_actual:
            cerrar()
            grupo = []
            hora_actual = hora
        grupo.append((ts, etiqueta, cuerpo))
    cerrar()
    return salida


# --------------------------------------------------------------------- el tar
LEEME = """\
ESTE TAR ESTA CIFRADO Y LA CONTRASENA ES  1234

No es un secreto y no pretende serlo. Va cifrado para que el antivirus del
equipo al que se baje no mire dentro: en cuanto un .tar.gz con muestras toca un
disco Windows, Defender ve los binarios capturados y te los pone en cuarentena
---y entonces el hash de la captura ya no cuadra con lo que se denuncio a las
plataformas---. Es la misma contrasena y el mismo motivo que el respaldo del
apartado 3.7.11 del README.

Para ver que hay dentro sin extraerlo:
  openssl enc -d -aes-256-cbc -pbkdf2 -in ESTE-FICHERO -k 1234 | tar -tzf -

Para extraerlo:
  openssl enc -d -aes-256-cbc -pbkdf2 -in ESTE-FICHERO -k 1234 | tar -xzf -

QUE HAY AQUI
  FICHA.txt              el log, hora por hora, y el resumen de arriba
  eventos-cowrie.json    las lineas del cowrie.json tal cual, sin tocar: son LA
                         evidencia, y un informe reescrito no acredita nada
  dionaea.txt            las conexiones y descargas de esa IP en Dionaea
  reporter.txt           que se publico y que se descarto de esa IP
  nftables.txt           su elemento en el cortafuegos, con el comentario que
                         dice si el baneo fue automatico o a mano
  urls.txt               de donde intento bajar cosas
  hashes.txt             cada binario con su hash y su origen
  binarios/              LAS MUESTRAS. Malware de verdad, sin desactivar
  terminal/              las grabaciones del terminal de Cowrie. Se ven con
                         cowrie/bin/playlog, o en crudo con `cat -v`

Y LO DE SIEMPRE, que sigue en pie: esto lleva malware en crudo, IPs y hashes de
capturas reales. NO va al repositorio, ni a un almacenamiento de terceros, ni a
un correo. Se baja solo por el tunel de administracion, y se borra en cuanto se
use:  shred -u <fichero>
"""


def empaquetar(destino: str, raiz: str, textos: list[tuple[str, str]],
               piezas: list[tuple[str, str]]) -> str | None:
    """Escribe el tar CIFRADO. Devuelve el problema, o None si fue bien.

    NO DEJA UN .tar.gz EN CLARO EN EL DISCO en ningun momento: tarfile escribe
    directamente en la tuberia de openssl. Es lo mismo que hace el respaldo del
    3.7.11 con `tar | gzip | openssl`, en Python porque aqui hay que elegir
    fichero por fichero en vez de dar una lista de carpetas.

    La contrasena va en la linea de ordenes, o sea que se ve en un `ps`. Es 1234
    y esta escrita en el README: lo que se gana a cambio es que la orden para
    abrirlo sea EXACTAMENTE la misma que la del respaldo.
    """
    if not shutil.which("openssl"):
        return ("no hay openssl en esta maquina, asi que no se puede cifrar. NO "
                "se escribe un tar en claro: instalalo con 'apt install "
                "openssl', o contesta que NO al tar cuando lo pregunte.")
    orden = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
             "-k", CLAVE_TAR, "-out", destino]
    try:
        proc = subprocess.Popen(orden, stdin=subprocess.PIPE)
    except OSError as exc:
        return "no se pudo arrancar openssl: %s" % exc
    ahora = int(time.time())
    try:
        with tarfile.open(fileobj=proc.stdin, mode="w|gz") as tar:
            for nombre, datos in textos:
                # surrogateescape: las lineas crudas del log llevan los bytes
                # del atacante tal cual, y asi el eventos-cowrie.json del tar
                # sale identico al log byte por byte. Es LA evidencia.
                bruto = datos.encode("utf-8", "surrogateescape")
                info = tarfile.TarInfo("%s/%s" % (raiz, nombre))
                info.size = len(bruto)
                info.mtime = ahora
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(bruto))
            for nombre, ruta in piezas:
                try:
                    info = tar.gettarinfo(ruta, arcname="%s/%s" % (raiz, nombre))
                except OSError:
                    continue
                # Las muestras entran sin permiso de ejecucion y sin dueno.
                # Nadie va a "ejecutarlas por error" desde dentro de un tar,
                # pero un 0600 es una traba mas en ese camino y no cuesta nada.
                info.mode = 0o600
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                try:
                    with open(ruta, "rb") as fh:
                        tar.addfile(info, fh)
                except OSError:
                    continue
    except Exception as exc:                              # noqa: BLE001
        try:
            proc.stdin.close()
            proc.wait(timeout=10)
        except Exception:                                 # noqa: BLE001
            proc.kill()
        return "fallo al empaquetar: %s" % exc
    proc.stdin.close()
    if proc.wait() != 0:
        return "openssl salio con codigo %d" % proc.returncode
    return None


# ------------------------------------------------------------------ la orden
def preguntar_si(pregunta: str, detalle: list[str],
                 por_defecto: bool = True) -> bool:
    """Una pregunta de si o no, y su respuesta.

    Se contesta con s, si, y o yes ---en mayusculas o en minusculas--- y con n o
    no. El Enter vale por lo que este puesto por defecto, y eso va escrito en la
    propia pregunta: una pregunta con un defecto que no se ve obliga a leerse el
    codigo para saber que hace el Enter.

    Sin nadie que conteste ---un cron, una tuberia--- devuelve el defecto sin
    preguntar. Aqui eso solo puede pasar lanzandolo a mano de esa forma, pero el
    programa no puede quedarse esperando para siempre a una respuesta que no va
    a llegar.
    """
    print(pregunta)
    for linea in detalle:
        print("  %s" % linea)
    while True:
        try:
            r = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return por_defecto
        if not r:
            return por_defecto
        if r in ("s", "si", "sí", "y", "yes"):
            return True
        if r in ("n", "no"):
            return False
        print("  contesta s o n (Enter para %s)"
              % ("si" if por_defecto else "no"))


def preguntar_dias() -> int | None:
    """La ventana de tiempo: None es todo el log.

    Por defecto TODO, y no los ultimos dias, porque de un atacante lo que se
    quiere saber es desde cuando vuelve: una ventana corta contestaria "lleva
    aqui una semana" de uno que lleva tres meses.
    """
    print("De cuanto tiempo? El log se guarda rotado, asi que cabe todo.")
    print("  Enter       todo el log que haya")
    print("  un numero   solo los ultimos N dias (por ejemplo 7)")
    while True:
        try:
            r = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not r:
            return None
        try:
            dias = int(r)
        except ValueError:
            print("  un numero de dias, o Enter para todo")
            continue
        if dias <= 0:
            print("  una ventana de cero dias no es una ventana")
            continue
        return dias


def preguntar_ip() -> str | None:
    """La IP, preguntada. Tres intentos y se deja."""
    for _ in range(3):
        try:
            crudo = input("Cual es la IP de la que quieres sacar el log?: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        crudo = crudo.strip()
        if not crudo:
            continue
        try:
            return str(ipaddress.ip_address(crudo))
        except ValueError:
            print("  '%s' no es una direccion IP. Se escribe entera, como "
                  "198.51.100.23" % crudo, file=sys.stderr)
    return None


def home_de_quien_llama() -> str:
    """El home del usuario que hizo el sudo, no el de root.

    Los dos ficheros se dejan ahi para que se puedan bajar con `scp` sin sudo
    ---igual que el respaldo del 3.7.11--- y para que borrarlos despues tampoco
    pida permisos.
    """
    if os.environ.get("DIRTYLAND_SALIDA"):
        return os.environ["DIRTYLAND_SALIDA"]
    usuario = os.environ.get("SUDO_USER")
    if usuario:
        try:
            import pwd                                    # noqa: PLC0415
            return pwd.getpwnam(usuario).pw_dir
        except Exception:                                 # noqa: BLE001
            pass
    return os.path.expanduser("~")


def hacer_mio(ruta: str, avisos: list[str]) -> None:
    """600 y del usuario que hizo el sudo. Ver home_de_quien_llama."""
    try:
        os.chmod(ruta, 0o600)
    except OSError as exc:
        avisos.append("no se pudo poner el permiso 600 en %s: %s" % (ruta, exc))
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and hasattr(os, "chown"):
        try:
            os.chown(ruta, int(uid), int(gid))
        except (OSError, ValueError) as exc:
            avisos.append("no se pudo cambiar el dueno de %s: %s" % (ruta, exc))


# Lo que se dice al arrancar, antes de pedir la IP. Cuatro lineas: quien es y
# que va a dejar. Va SIEMPRE y no solo cuando pregunta, porque la duda de "que
# hacia este?" la tiene igual quien lo lanza con la IP puesta ---y el README ya
# no lo cuenta largo: lo cuenta la cabecera de este fichero---.
PRESENTACION = """\
que_hizo_esta_ip.py --- la ficha de UNA IP, con lo que hizo aqui.

  Saca todo lo que esa IP ha hecho contra el senuelo y deja dos ficheros en tu
  home: un .txt con el log HORA POR HORA, y aparte un tar CIFRADO (contrasena
  1234) con los binarios que bajo, las grabaciones del terminal y la evidencia
  en crudo. Solo LEE: no ejecuta ninguna muestra, no borra nada y no toca el
  senuelo. Las horas van en UTC, ya corregidas.
"""

def main() -> int:
    # NI UN PARAMETRO. Todo lo que hay que decidir ---la ventana, si se quiere el
    # log entero, si se quiere el tar--- lo PREGUNTA el guion, y se contesta con
    # s o con n. Una opcion en la linea de ordenes es una opcion que hay que
    # recordar, y esta carpeta existe justamente para no tener que recordar nada.
    #
    # Lo unico que se acepta escrito es la IP, que no es una opcion: es el sujeto
    # de la orden, y se pega tal cual del aviso de Telegram. Cualquier cosa que
    # empiece por un guion se rechaza DICIENDOLO, en vez de tragarsela o de
    # sacar una pantalla de ayuda que ya no tiene nada que explicar.
    # Lo vacio no cuenta como argumento: un `~/que_hizo_esta_ip.py "$IP"` con la
    # variable sin poner llega asi, y ahi lo util es preguntar la IP, no dar un
    # error por una cadena vacia que nadie escribio a mano.
    sueltos = [x for x in sys.argv[1:] if x.strip()]
    opciones = [x for x in sueltos if x.startswith("-")]
    if opciones:
        print("esto no lleva parametros, y %s lo parece."
              % " ".join(opciones), file=sys.stderr)
        print("Lo que hay que decidir se pregunta al arrancar; lo unico que se "
              "puede\nescribir en la orden es la IP.", file=sys.stderr)
        return 2
    if len(sueltos) > 1:
        print("de una IP cada vez: sobra %s" % " ".join(sueltos[1:]),
              file=sys.stderr)
        return 2

    # LA IP QUE VENGA EN LA ORDEN SE COMPRUEBA ANTES DE PRESENTARSE. Una IP mal
    # escrita se contesta en una linea, y siete de presentacion por delante solo
    # la esconden. Cuando hay que preguntarla, en cambio, la presentacion va
    # primero: es lo que explica que se esta a punto de pedir.
    ip = None
    if sueltos:
        try:
            ip = str(ipaddress.ip_address(sueltos[0].strip()))
        except ValueError:
            print("'%s' no es una direccion IP. Se escribe entera y solo con "
                  "numeros, como 198.51.100.23" % sueltos[0], file=sys.stderr)
            return 2

    print()
    print(PRESENTACION)

    if ip is None:
        ip = preguntar_ip()
        if not ip:
            print("Nada que hacer.")
            return 0

    dias = preguntar_dias()
    completo = preguntar_si(
        "Quieres tambien TODO EL LOG, con cada evento que anoto Cowrie?",
        ["Enter o s   las dos partes: los comandos y el log entero",
         "n           solo los comandos que tecleo, y nada mas"],
        por_defecto=True)
    con_tar = preguntar_si(
        "Y el tar con los hallazgos? (los binarios que bajo, las grabaciones)",
        ["Enter o s   si, empaquetado y cifrado con 1234",
         "n           solo la ficha de texto, sin tar"],
        por_defecto=True)
    print()

    r = rutas()
    tabla = mapa_puertos(r["cowrie_puertos_publicos"])
    tz = resolver_huso(r["cowrie_log_tz"])
    desde = (datetime.now(timezone.utc) - timedelta(days=dias)
             if dias else None)

    carpeta_log = r["cowrie_log_dir"]
    if os.path.isdir(carpeta_log) and not os.access(carpeta_log, os.R_OK):
        print("no se puede leer %s: los logs del senuelo son de root."
              % carpeta_log, file=sys.stderr)
        print("  sudo %s %s" % (sys.argv[0], ip), file=sys.stderr)
        return 1

    ficheros = ficheros_de_log(r)
    if not ficheros and not os.path.isfile(r["dionaea_sqlite"]):
        print("no hay ni logs de Cowrie en %s ni base de Dionaea en %s."
              % (carpeta_log, r["dionaea_sqlite"]), file=sys.stderr)
        # LO MAS PROBABLE NO ES QUE FALTE EL SENUELO: es que falte el sudo. Los
        # volumenes de Docker son 0700 de root, asi que un usuario normal no
        # puede ni ver que la carpeta existe ---ni siquiera falla al leerla, que
        # es lo que caza la comprobacion de arriba--- y esto tenia toda la pinta
        # de "aqui no hay nada que mirar". Se dice primero lo que suele ser.
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("Y esto no lo puede leer un usuario normal. Prueba:",
                  file=sys.stderr)
            print("  sudo %s %s" % (sys.argv[0], ip), file=sys.stderr)
        else:
            print("Si esta maquina no es la del senuelo, aqui no hay nada que "
                  "leer.", file=sys.stderr)
        return 2

    # LA BARRA. El log se lee DOS veces ---una para saber que sesiones son de
    # esa IP y otra para recoger sus eventos--- asi que el total es dos veces lo
    # que pesan los ficheros, mas una reserva para todo lo que viene despues.
    # Lo de despues se reparte en cinco trozos iguales, uno por etapa: no son
    # cinco tiempos iguales, pero la barra se mueve en cada una y llega al final.
    peso = sum(peso_de_log(f) for f in ficheros)
    reserva = max(peso * RESERVA_FINAL, 5.0)
    barra = Barra(2 * peso + reserva)
    trozo = reserva / 5.0
    print("  %d fichero(s) de log, %s" % (len(ficheros), tamano_legible(peso)))

    barra.etapa("leyendo el log del senuelo (1 de 2)")
    sesiones = sesiones_de(ficheros, ip, barra)
    barra.etapa("leyendo el log del senuelo (2 de 2)")
    eventos, crudas = eventos_cowrie(ficheros, ip, sesiones, tz, desde, barra)

    barra.etapa("mirando la base de Dionaea")
    ev_dionaea, desc_dionaea, puertos_d = eventos_dionaea(r, ip, desde)
    barra.avanza(trozo)

    if not eventos and not ev_dionaea:
        barra.cierra("nada que sacar")
        print()
        print("De %s no hay NADA en lo que se ha mirado." % ip)
        if dias:
            print("  La ventana era de %d dia(s): prueba con todo el log."
                  % dias)
        print("  No se escribe ninguna ficha: un fichero vacio solo sirve para")
        print("  que manana no se sepa si se miro o si no se miro.")
        return 1

    barra.etapa("buscando los binarios que bajo")
    # --- los hallazgos de Cowrie: lo que bajo, y si sigue en el disco.
    descargas: list[dict] = []
    ttylogs: list[str] = []
    grabaciones: dict[str, int | None] = {}
    # La carpeta de grabaciones es hermana de la de descargas. Se deduce de ella
    # y no se escribe aparte: asi el dia que cambie el volumen solo hay una ruta
    # que tocar, y encima esa ya la mantiene el config.ini.
    carpeta_tty = os.path.join(os.path.dirname(r["downloads_dir"]), "tty")
    for ts, ev in eventos:
        eid = str(ev.get("eventid", ""))
        if eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            sha = str(ev.get("shasum", "") or "").lower()
            if not sha:
                continue
            ruta = os.path.join(r["downloads_dir"], sha)
            hay = os.path.isfile(ruta)
            descargas.append({
                "sha": sha, "ruta": ruta if hay else None, "ts": ts,
                "url": (ev.get("url") or ev.get("filename")
                        or ev.get("destfile") or ""),
                "bytes": os.path.getsize(ruta) if hay else None})
        elif eid == "cowrie.log.closed" and ev.get("ttylog"):
            nombre = os.path.basename(str(ev["ttylog"]))
            ruta = os.path.join(carpeta_tty, nombre)
            hay = os.path.isfile(ruta)
            grabaciones[nombre] = os.path.getsize(ruta) if hay else None
            # Una grabacion de cero bytes no se mete en el tar: no hay nada que
            # reproducir, y en el tar solo serviria para hacer creer que si.
            if hay and grabaciones[nombre] and ruta not in ttylogs:
                ttylogs.append(ruta)
    shas_en_disco = {d["sha"] for d in descargas if d["ruta"]}

    # --- los de Dionaea. El binario se busca por hash, no por nombre.
    indice, tope = ({}, False)
    if desc_dionaea:
        indice, tope = indice_binarios(r["dionaea_binaries"])
    for d in desc_dionaea:
        d["ruta"] = indice.get(d["sha"]) or indice.get(d["md5"])
        d["bytes"] = (os.path.getsize(d["ruta"])
                      if d["ruta"] and os.path.isfile(d["ruta"]) else None)
        # EL HASH SE SACA DEL FICHERO, no de la fila de la base. La fila de
        # Dionaea puede traer solo el md5 ---o un sha512, que no le sirve a
        # nadie--- y el hash que hace falta para buscar la muestra en VirusTotal
        # o en MalwareBazaar es el sha256. Mismo criterio que el recolector.
        if d["ruta"]:
            pareja = hashes_de(d["ruta"])
            if pareja:
                d["md5"], d["sha"] = pareja

    barra.avanza(trozo)

    # --- el recuento de la cabecera.
    cuenta = collections.Counter(str(ev.get("eventid", ""))
                                 for _t, ev in eventos)
    logins_ok = ["%s / %s" % (ev.get("username", ""), ev.get("password", ""))
                 for _t, ev in eventos
                 if ev.get("eventid") == "cowrie.login.success"]
    clientes = sorted({str(ev.get("version", "")) for _t, ev in eventos
                       if ev.get("eventid") == "cowrie.client.version"
                       and ev.get("version")})
    hasshes = sorted({str(ev.get("hassh", "")) for _t, ev in eventos
                      if ev.get("eventid") == "cowrie.client.kex"
                      and ev.get("hassh")})
    puertos = sorted({puerto_publico(ev.get("dst_port"), tabla)
                      for _t, ev in eventos
                      if ev.get("eventid") == "cowrie.session.connect"
                      and ev.get("dst_port") is not None}, key=str)
    marcas = [t for t, _ev in eventos] + [t for t, _e, _c in ev_dionaea]
    comentario_baneo, elemento_nft = baneo_de(ip)
    etiqueta_pais = pais_de(ip)

    # --- la ficha.
    barra.etapa("escribiendo la ficha")
    ahora = datetime.now(timezone.utc)
    L: list[str] = []
    L.append("=" * 72)
    L.append("  QUE HIZO  %s" % ip)
    L.append("=" * 72)
    L.append("")
    L.append("  generada          : %s UTC" % ahora.strftime("%Y-%m-%d %H:%M"))
    L.append("  todas las horas   : UTC. Cowrie escribe hora de %s con una 'Z'"
             % r["cowrie_log_tz"])
    L.append("                      que miente; aqui ya esta corregido")
    L.append("  ventana           : %s"
             % ("ultimos %d dia(s)" % dias if dias
                else "todo el log disponible"))
    L.append("  ficheros leidos   : %d de %s" % (len(ficheros), carpeta_log))
    L.append("  esta ficha lleva  : %s"
             % ("los comandos y el log entero" if completo
                else "SOLO los comandos que tecleo"))
    if etiqueta_pais:
        L.append("  pais              : %s" % sin_banderas(etiqueta_pais))
    if es_nuestra(ip, r):
        L.append("  CUIDADO           : esta IP es NUESTRA (esta en la")
        L.append("                      [blocklist], o no es una direccion")
        L.append("                      publica)")
    L.append("  baneada ahora     : %s"
             % ("SI --- %s" % comentario_baneo if comentario_baneo
                else "no esta en el cortafuegos"))
    if marcas:
        L.append("  vista desde       : %s"
                 % min(marcas).strftime("%Y-%m-%d %H:%M:%S"))
        L.append("  vista hasta       : %s"
                 % max(marcas).strftime("%Y-%m-%d %H:%M:%S"))
    L.append("")
    L.append("  COWRIE    sesiones %d   logins OK %d   fallidos %d"
             % (len(sesiones), cuenta["cowrie.login.success"],
                cuenta["cowrie.login.failed"]))
    L.append("            ordenes %d   descargas %d   subidas %d   puertos %s"
             % (cuenta["cowrie.command.input"],
                cuenta["cowrie.session.file_download"],
                cuenta["cowrie.session.file_upload"],
                ", ".join(str(x) for x in puertos) or "-"))
    if cuenta["cowrie.command.failed"]:
        L.append("            %d orden(es) que el senuelo NO supo ejecutar, y"
                 % cuenta["cowrie.command.failed"])
        L.append("            eso lo delata: mira ~/que_le_falta_al_senuelo.py")
    if cuenta["cowrie.direct-tcpip.request"]:
        L.append("            %d intento(s) de usarnos de salto hacia otra "
                 "maquina" % cuenta["cowrie.direct-tcpip.request"])
    L.append("  DIONAEA   conexiones %d   binarios %d   puertos %s"
             % (sum(1 for _t, et, _c in ev_dionaea if et == "DIONAEA CONEXION"),
                len(desc_dionaea),
                ", ".join(str(x) for x in sorted(puertos_d, key=str)) or "-"))
    if logins_ok:
        L.append("")
        L.append("  LE FUNCIONARON estas parejas del cebo:")
        for par in sorted(set(logins_ok)):
            L.append("      %s" % par)
    if clientes or hasshes:
        L.append("")
        L.append("  CON QUE CLIENTE ENTRA:")
        for c in clientes:
            L.append("      %s" % c)
        for h in hasshes:
            L.append("      hassh %s" % h)
    todo = descargas + desc_dionaea
    if todo:
        L.append("")
        L.append("  HALLAZGOS (los que tienen fichero van en el tar cifrado):")
        # El hash va ENTERO y en su propia linea. Recortado a la mitad cabia
        # mejor en la columna y no servia para nada: este es justo el dato que
        # se pega en VirusTotal o en MalwareBazaar para buscar la muestra.
        for senuelo, d in ([("cowrie ", x) for x in descargas]
                           + [("dionaea", x) for x in desc_dionaea]):
            L.append("      %s  %s" % (senuelo, d["sha"] or d["md5"] or "?"))
            L.append("               %s   %s"
                     % ("%d bytes" % d["bytes"] if d["bytes"] is not None
                        else "SIN FICHERO en el disco", d["url"] or ""))
        if tope:
            L.append("      (aviso: la carpeta de binarios de Dionaea tiene mas")
            L.append("       de %d ficheros y solo se hashearon los primeros;"
                     % TOPE_HASHEO)
            L.append("       algun binario puede salir como 'sin fichero')")
    if ttylogs:
        L.append("")
        L.append("  GRABACIONES DEL TERMINAL: %d (van en el tar)" % len(ttylogs))
    L.append("")

    L.extend(solo_comandos(eventos))

    if completo:
        lineas_tiempo = [(ts,) + texto_evento(ev, tabla, shas_en_disco,
                                              grabaciones)
                         for ts, ev in eventos]
        lineas_tiempo += list(ev_dionaea)
        lineas_tiempo.sort(key=lambda x: x[0])
        L.append("=" * 72)
        L.append("TODO EL LOG".center(72))
        L.append("=" * 72)
        L.append("")
        L.append("  Hora por hora, y con todo dentro: la negociacion de telnet,")
        L.append("  las variables que manda el cliente, los parametros de cada")
        L.append("  sesion. Es el volcado, no el resumen.   (%d eventos)"
                 % len(lineas_tiempo))
        L.append("")
        L.extend(bloques_por_hora(lineas_tiempo))

    publicado = lo_publicado(r, ip, [d["sha"] for d in descargas if d["sha"]])
    L.append("=" * 72)
    L.append("  QUE SE HA PUBLICADO DE ESTA IP")
    L.append("=" * 72)
    L.append("")
    L.extend(publicado)
    L.append("")
    # Sin espacios al final: una columna vacia ---una descarga de Dionaea sin
    # URL, por ejemplo--- dejaba la linea acabada en blancos.
    # TODA la ficha pasa por texto_plano, y en un solo sitio: saneando cada
    # lugar por donde entra algo del atacante ---la orden, la URL, el usuario,
    # la contrasena, el nombre del fichero que subio--- se olvidaria uno, y
    # bastaria ese para que el .txt saliera ilegible.
    ficha = "\n".join(texto_plano(linea).rstrip() for linea in L) + "\n"

    # --- a escribir.
    salida = home_de_quien_llama()
    # La IP va en el nombre, y un IPv6 lleva ":" dentro: en Windows ---donde se
    # acaba bajando el fichero--- eso no es un nombre valido. Y la hora, para
    # que dos fichas de la misma IP el mismo dia no se pisen la una a la otra.
    sello = "%s-%s" % (ip.replace(":", "-"), ahora.strftime("%Y-%m-%d-%H%M"))
    ruta_ficha = os.path.join(salida, "ficha-%s.txt" % sello)
    ruta_tar = os.path.join(salida, "ficha-%s.tar.gz.enc" % sello)
    avisos: list[str] = []
    try:
        with open(ruta_ficha, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(ficha)
    except OSError as exc:
        print("no se pudo escribir %s: %s" % (ruta_ficha, exc), file=sys.stderr)
        return 1
    hacer_mio(ruta_ficha, avisos)

    barra.avanza(trozo)

    problema, n_bin = None, 0
    if con_tar:
        textos = [("FICHA.txt", ficha), ("LEEME.txt", LEEME),
                  ("eventos-cowrie.json", "\n".join(crudas) + "\n"),
                  ("reporter.txt", "\n".join(publicado) + "\n")]
        if ev_dionaea or desc_dionaea:
            d = ["Dionaea --- %s   (horas UTC, de su epoch)" % ip, ""]
            for ts, et, cu in ev_dionaea:
                d.append("[%s]  %s" % (ts.strftime("%Y-%m-%d %H:%M:%S"), et))
                d.append("    %s" % cu)
            d.append("")
            d.append("DESCARGAS:")
            for x in desc_dionaea:
                d.append("  md5 %s  sha %s  %s  %s"
                         % (x["md5"] or "-", x["sha"] or "-", x["url"] or "-",
                            "en el tar" if x["ruta"] else "sin fichero"))
            textos.append(("dionaea.txt", "\n".join(d) + "\n"))
        urls = sorted({d["url"] for d in todo if d.get("url")})
        if urls:
            textos.append(("urls.txt", "\n".join(urls) + "\n"))
        if todo:
            h = ["hash                                                        "
                 "      senuelo  origen", ""]
            for x in descargas:
                h.append("%-64s  cowrie   %s" % (x["sha"], x["url"] or "-"))
            for x in desc_dionaea:
                h.append("%-64s  dionaea  %s" % (x["sha"] or x["md5"] or "?",
                                                 x["url"] or "-"))
            textos.append(("hashes.txt", "\n".join(h) + "\n"))
        if elemento_nft:
            textos.append(("nftables.txt", elemento_nft + "\n"))

        piezas: list[tuple[str, str]] = []
        for d in descargas:
            if d["ruta"]:
                piezas.append(("binarios/cowrie/%s" % d["sha"], d["ruta"]))
        for d in desc_dionaea:
            if d["ruta"]:
                piezas.append(("binarios/dionaea/%s"
                               % os.path.basename(d["ruta"]), d["ruta"]))
        for ruta in ttylogs:
            piezas.append(("terminal/%s" % os.path.basename(ruta), ruta))
        # Sin repetir: el mismo binario bajado tres veces es UN fichero.
        vistos, unicas = set(), []
        for nombre, ruta in piezas:
            if nombre in vistos:
                continue
            vistos.add(nombre)
            unicas.append((nombre, ruta))
        n_bin = sum(1 for nombre, _r in unicas if nombre.startswith("binarios/"))

        barra.etapa("cifrando el tar con los hallazgos")
        problema = empaquetar(ruta_tar, "ficha-%s" % sello, textos, unicas)
        if problema:
            print("  %s" % problema, file=sys.stderr)
        else:
            hacer_mio(ruta_tar, avisos)

    # --- y lo que hay que saber al terminar.
    barra.cierra("hecho")
    print()
    print("  ficha : %s" % ruta_ficha)
    if not con_tar:
        print("  tar   : no, has dicho que no lo querias")
    elif problema:
        print("  tar   : NO se pudo crear (ver el aviso de arriba)")
    else:
        print("  tar   : %s" % ruta_tar)
        print("          CIFRADO, contrasena 1234, con %d binario(s) dentro"
              % n_bin)
        print()
        print("  Va cifrado para que Defender no mire dentro y te ponga las")
        print("  muestras en cuarentena al bajarlas: con la muestra en")
        print("  cuarentena ya no cuadra el hash de lo que se denuncio.")
        print("  La clave NO es un secreto: es para el antivirus.")
        print()
        print("  ver que lleva dentro el tar, sin extraerlo:")
        print("    openssl enc -d -aes-256-cbc -pbkdf2 -in %s -k 1234 | tar -tzf -"
              % os.path.basename(ruta_tar))

    # LOS DOS FICHEROS DE UNA VEZ, con un comodin y no con dos ordenes. La ficha
    # sin el tar deja el log sin las muestras de las que habla, y el tar sin la
    # ficha deja los binarios sin lo que explica de donde salieron: se bajan
    # juntos o no se bajan.
    #
    # El comodin va ENTRE COMILLAS a proposito: sin ellas lo expandiria el shell
    # de TU equipo ---donde no existe ese fichero--- y scp se quejaria de un
    # nombre que no encuentra. Entre comillas viaja tal cual y lo expande la VPS.
    #
    # "dirtyland" es el alias del ~/.ssh/config del apartado 3.2.6, el mismo del
    # respaldo del 3.7.11: si un relay del proxy esta caido, se cambia al alias
    # de uno de los de respaldo y la orden sigue valiendo.
    comodin = os.path.join(salida, "ficha-%s.*" % sello)
    print()
    if not con_tar or problema:
        print("  para traerte la ficha (desde TU equipo):")
        print("    scp dirtyland:%s ." % ruta_ficha)
    else:
        print("  para traerte los dos (desde TU equipo):")
        print("    scp 'dirtyland:%s' ." % comodin)
        print("  y cuando los tengas, aqui no se quedan:")
        print("    shred -u %s" % comodin)
    for aviso in avisos:
        print("  aviso: %s" % aviso, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
