# SPDX-License-Identifier: GPL-2.0-or-later
"""
Collector de Dionaea: lee dionaea.sqlite y produce el mismo modelo comun.

Dos decisiones que vienen del comportamiento real de Dionaea:

  - Solo se leen conexiones con connection_type='accept'. Un 'reject' no llego
    a establecerse y un 'listen' es un socket NUESTRO; ambos son ruido y el
    segundo seria ademas reportarnos a nosotros. 'accept' equivale a
    handshake TCP completado, que es justo lo que AbuseIPDB exige para no
    caer en su prohibicion de reportar SYN floods y UDP.

  - El esquema de la tabla 'downloads' cambia entre versiones, asi que las
    columnas se detectan en tiempo de ejecucion en lugar de darlas por hechas.

El hash con el que trabajamos (SHA-256, el de VirusTotal y MalwareBazaar) se
calcula SIEMPRE leyendo el fichero, sin fiarse del nombre.

Y el nombre tampoco se usa para adivinar nada mas. Este modulo daba por hecho
que Dionaea nombra los binarios por MD5 --- en esta version los nombra por
SHA-256 --- y sobre esa suposicion se ataba cada binario con su fila de
descarga. El enlace no podia acertar nunca. Ver _collect_binaries.

local_host se lee unicamente para auditar que nuestras propias IP estan en la
lista de bloqueo. Nunca se reporta.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common import log
from common.model import SERVICIO_DE_PUERTO, SOURCE_DIONAEA, AttackerIP, PayloadURL, Sample

from . import avisar_si_todo_descartado

_log = log.get("collector.dionaea")

# Evidencia de intento de inyeccion SQL. Solo decide la categoria del reporte:
# el texto capturado NUNCA se publica.
SQLI_PATTERNS = re.compile(
    r"(?i)(xp_cmdshell|sp_configure|union\s+select|;\s*drop\s+table|"
    r"openrowset|bulk\s+insert|exec\s*\(|waitfor\s+delay)")


class DionaeaSource:
    def __init__(self, sqlite_path: Path) -> None:
        sqlite_path = Path(sqlite_path)
        if not sqlite_path.is_file():
            raise FileNotFoundError(f"no existe la base de Dionaea: {sqlite_path}")
        # mode=ro: Dionaea esta escribiendo en esta base mientras la leemos.
        self.db = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
        self.db.row_factory = sqlite3.Row

    def _table_exists(self, name: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,)).fetchone() is not None

    def _columns(self, table: str) -> list[str]:
        try:
            return [r[1] for r in self.db.execute(f"PRAGMA table_info({table})")]
        except sqlite3.Error:
            return []

    def local_hosts(self, since_epoch: int) -> set[str]:
        """Nuestras propias IP. Solo para auditar la lista de bloqueo."""
        try:
            rows = self.db.execute(
                "SELECT DISTINCT local_host FROM connections"
                " WHERE connection_timestamp >= ?", (since_epoch,)).fetchall()
        except sqlite3.Error:
            return set()
        return {r["local_host"] for r in rows if r["local_host"]}

    # ------------------------------------------------------------------
    def attackers(self, since_epoch: int, guard) -> dict[str, AttackerIP]:
        attackers: dict[str, AttackerIP] = {}
        descartados: dict[str, int] = {}
        conn_to_ip: dict[int, str] = {}

        rows = self.db.execute(
            """SELECT connection, remote_host, remote_port, local_port,
                      connection_protocol, connection_timestamp
               FROM connections
               WHERE connection_type = 'accept' AND connection_timestamp >= ?""",
            (since_epoch,)).fetchall()

        for r in rows:
            ip = (r["remote_host"] or "").strip()
            if not ip:
                continue
            okay, reason = guard.check(ip)
            if not okay:
                descartados[reason] = descartados.get(reason, 0) + 1
                continue

            try:
                ts = datetime.fromtimestamp(int(r["connection_timestamp"]), tz=timezone.utc)
            except (TypeError, ValueError):
                ts = datetime.now(timezone.utc)

            att = attackers.get(ip)
            if att is None:
                att = attackers[ip] = AttackerIP(
                    ip=ip, source=SOURCE_DIONAEA, first_seen=ts, last_seen=ts,
                    handshake_ok=True)      # 'accept' = handshake completado
            att.first_seen = min(att.first_seen, ts)
            att.last_seen = max(att.last_seen, ts)
            conn_to_ip[r["connection"]] = ip

            if r["connection_protocol"]:
                att.protocols.add(str(r["connection_protocol"]))
            for key, target in (("local_port", att.ports), ("remote_port", att.source_ports)):
                try:
                    target.add(int(r[key]))
                except (TypeError, ValueError):
                    pass

        for reason, count in sorted(descartados.items()):
            _log.info("descartadas %d conexiones por IP no reportable: %s", count, reason)
        avisar_si_todo_descartado(_log, len(attackers), descartados)

        self._enrich_mssql(attackers, conn_to_ip)
        self._enrich_dcerpc(attackers, conn_to_ip)
        return attackers

    def _enrich_mssql(self, attackers: dict, conn_to_ip: dict) -> None:
        if not self._table_exists("mssql_commands"):
            return
        cols = self._columns("mssql_commands")
        text_col = next((c for c in ("cmd", "mssql_command_cmd", "command") if c in cols), None)
        try:
            sql = "SELECT m.connection AS conn"
            if text_col:
                sql += f", m.{text_col} AS body"
            rows = self.db.execute(sql + " FROM mssql_commands m").fetchall()
        except sqlite3.Error as exc:
            _log.debug("mssql_commands no consultable: %s", exc)
            return

        for r in rows:
            ip = conn_to_ip.get(r["conn"])
            if not ip or ip not in attackers:
                continue
            att = attackers[ip]
            att.commands += 1
            body = (r["body"] if text_col and "body" in r.keys() else "") or ""
            # sqlite puede devolver BLOB: sin decodificar, el .search() falla
            # con "cannot use a string pattern on a bytes-like object".
            if isinstance(body, (bytes, bytearray)):
                body = body.decode("utf-8", "replace")
            if SQLI_PATTERNS.search(body):
                att.sqli_evidence = True

    def _enrich_dcerpc(self, attackers: dict, conn_to_ip: dict) -> None:
        if not self._table_exists("dcerpcrequests"):
            return
        try:
            rows = self.db.execute("SELECT connection AS conn FROM dcerpcrequests").fetchall()
        except sqlite3.Error:
            return
        for r in rows:
            ip = conn_to_ip.get(r["conn"])
            if ip and ip in attackers:
                attackers[ip].commands += 1

    # ------------------------------------------------------------------
    def downloads(self, since_epoch: int | None = None) -> list[dict]:
        """Filas de descarga. Columnas detectadas al vuelo.

        since_epoch=None devuelve TODAS, y esa es la forma que usa el indice
        que ata cada binario con su origen. No es un descuido de la ventana:
        son dos preguntas distintas y estaban compartiendo un filtro que solo
        le corresponde a una.

        Los binarios se quedan en disco para siempre y se reevaluan durante
        dias; las filas de descarga, en cambio, salian de la ventana de 24 h.
        Pasado un dia, el fichero seguia ahi y su origen ya no se encontraba,
        asi que perdia la URL y la IP --- y con ella la campana. Medido tras
        arreglar el enlace de hashes: 3 de 46 binarios atados, y los 43
        restantes no era que no tuvieran fila, es que su fila era vieja.

        La ventana sigue aplicandose donde SI toca: a la lista de URL que va a
        URLhaus, cuya politica pide no enviar enlaces probablemente muertos.
        """
        if not self._table_exists("downloads"):
            return []
        cols = self._columns("downloads")
        url_col = next((c for c in cols if "url" in c.lower()), None)
        md5_col = next((c for c in cols if "md5" in c.lower()), None)
        sha_col = next((c for c in cols if "sha" in c.lower()), None)
        if not url_col:
            _log.warning("la tabla downloads no tiene columna de URL: %s", cols)
            return []

        select = [f"d.{url_col} AS url",
                  f"d.{md5_col} AS md5" if md5_col else "NULL AS md5",
                  f"d.{sha_col} AS sha512" if sha_col else "NULL AS sha512"]
        # c.local_port dice POR QUE SERVICIO entro el binario: 445 es SMB,
        # 1433 MSSQL y 135 RPC. Sin el habia que publicar "SMB/RPC/MSSQL" en
        # todas las muestras, que es falso en cuanto no fueran las tres. El
        # JOIN ya estaba; solo faltaba pedir la columna. Dionaea publica esos
        # puertos uno a uno, sin NAT, asi que el numero es el de verdad.
        sql = f"""SELECT {', '.join(select)}, c.remote_host AS src_ip,
                         c.local_port AS local_port,
                         c.connection_timestamp AS ts
                  FROM downloads d
                  LEFT JOIN connections c ON c.connection = d.connection"""
        params: tuple = ()
        if since_epoch is not None:
            sql += (" WHERE c.connection_timestamp IS NULL"
                    " OR c.connection_timestamp >= ?")
            params = (since_epoch,)
        try:
            rows = self.db.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            _log.error("no se pudo consultar downloads: %s", exc)
            return []

        # Se devuelven TAMBIEN las filas sin URL, y esto era el otro medio
        # fallo del enlace. Antes habia un "if r['url']" aqui que las tiraba,
        # y en esta Dionaea la inmensa mayoria de las descargas por SMB no
        # llevan URL ninguna: el fichero lo empuja el atacante, no se baja de
        # ningun sitio. Pero esa fila SI trae la IP de origen, que es lo unico
        # que hace falta para saber de que campana viene el binario.
        #
        # Tirandolas, arreglar el enlace de hashes servia de poco: seguian
        # atandose solo las tres que casualmente tenian pseudo-URL. Quien
        # necesite URL que la compruebe: aqui no se decide eso.
        return [{"url": r["url"] or "", "md5": r["md5"], "sha512": r["sha512"],
                 "src_ip": r["src_ip"], "ts": r["ts"],
                 "local_port": r["local_port"]} for r in rows]


# --------------------------------------------------------------------------
def hashes_of(path: Path) -> tuple[str, str] | None:
    """(md5, sha256) del fichero, en una sola lectura.

    Se calculan LOS DOS a proposito. El SHA-256 es la clave con la que
    trabajan VirusTotal y MalwareBazaar; el MD5 hace falta para reconocer la
    fila de descarga de Dionaea, que es lo unico que ata un binario con la URL
    y la IP de la que vino. Leer el fichero una vez y sacar ambos cuesta lo
    mismo que sacar uno.
    """
    md5, sha = hashlib.md5(), hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                md5.update(chunk)
                sha.update(chunk)
    except OSError as exc:
        _log.warning("no se pudo leer %s: %s", path, exc)
        return None
    return md5.hexdigest(), sha.hexdigest()


def sha256_of(path: Path) -> str | None:
    par = hashes_of(path)
    return par[1] if par else None


def collect(sqlite_path: Path, binaries_dir: Path, guard, lookback_hours: int = 24
            ) -> tuple[list[AttackerIP], list[Sample], list[PayloadURL]]:
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    since_epoch = int(since.timestamp())

    src = DionaeaSource(sqlite_path)
    attackers = src.attackers(since_epoch, guard)

    # Auditoria: si una IP nuestra no esta bloqueada, es un fallo de config
    # que hay que ver en el log antes de que se convierta en un autorreporte.
    for own in src.local_hosts(since_epoch):
        if guard.is_reportable(own):
            _log.critical(
                "IP LOCAL %s NO esta en la lista de bloqueo: anadela a [blocklist]", own)

    # TODAS las filas, sin ventana. El indice sirve para enriquecer binarios
    # que llevan dias en disco; recortarlo a 24 h dejaba sin origen a los que
    # llevaban mas de un dia esperando veredicto. La ventana se aplica abajo,
    # y solo a las URL que van a URLhaus.
    downloads = src.downloads()

    # Indexado por TODOS los hashes que traiga la fila, no solo por el MD5.
    # Ver el comentario de _collect_binaries: el nombre del fichero depende de
    # la version de Dionaea, y dar por hecho cual es fue un error que costo
    # caro.
    url_by_hash: dict[str, dict] = {}
    urls: dict[str, PayloadURL] = {}
    for dl in downloads:
        ip = (dl.get("src_ip") or "").strip()
        if ip and not guard.is_reportable(ip):
            ip = ""
        try:
            ts = datetime.fromtimestamp(int(dl["ts"]), tz=timezone.utc)
        except (TypeError, ValueError, KeyError):
            ts = datetime.now(timezone.utc)
        url = (dl.get("url") or "").strip()

        # La ventana de frescura vive AQUI, que es donde importa: URLhaus pide
        # no mandar enlaces que probablemente ya esten caidos. El indice de
        # enriquecimiento de abajo no tiene por que respetarla.
        if url and url not in urls and ts >= since:
            urls[url] = PayloadURL(url=url, source=SOURCE_DIONAEA,
                                   seen_at=ts, src_ip=ip or None)

        info = {"url": url, "src_ip": ip or None, "ts": ts}
        for clave in (dl.get("md5"), dl.get("sha512")):
            if clave:
                url_by_hash[str(clave).strip().lower()] = info

    samples = _collect_binaries(Path(binaries_dir), url_by_hash, urls)
    _log.info("dionaea: %d IP, %d muestras, %d URL",
              len(attackers), len(samples), len(urls))
    return list(attackers.values()), samples, list(urls.values())


def _collect_binaries(binaries_dir: Path, url_by_hash: dict[str, dict],
                      urls: dict[str, PayloadURL]) -> list[Sample]:
    """Recorre el directorio de binarios y ata cada uno con su fila de descarga.

    EL ENLACE SE BUSCA POR VARIOS HASHES, y no por el nombre del fichero dando
    por hecho cual es. Aqui hubo un fallo que estuvo activo toda la vida del
    sistema sin que nada lo delatara:

      nombre en disco    0647ab78...5f8f   64 hex  -> SHA-256
      download_md5_hash  1c7eb62e...5e34   32 hex  -> MD5

    El codigo hacia url_by_md5.get(path.name), o sea buscar una clave de 64
    caracteres en un diccionario cuyas claves son de 32. No fallaba "a veces":
    no podia acertar NUNCA, para ningun fichero. La cabecera del modulo decia
    "Dionaea nombra los binarios por MD5", y en esta version los nombra por
    SHA-256.

    Lo que se perdia no era solo la URL. Tambien src_ip, y con ella
    campaign_host(), que devuelve `download_host or src_ip or SIN_CAMPANA`.
    Con las dos a None, TODA muestra de Dionaea entraba como "campana
    desconocida", y eso arrastraba dos cosas:

      - La capa 5 (rafaga) se desactivaba, cosa que ya estaba prevista y
        registrada en el log.
      - La capa 4 metia todas las muestras en una sola campana ficticia, asi
        que de 34 WannaCry solo la primera podia subirse en 30 dias.
      - Y el bloque de IOC del orchestrator, que cuelga de `if
        muestra.download_url:`, no se ejecutaba jamas. De ahi que ThreatFox y
        URLhaus tuvieran CERO filas en la tabla de rechazos: no es que
        rechazaran mucho, es que nunca se les llego a preguntar nada.

    Por eso el enlace se prueba contra el nombre, el MD5 y el SHA-256, y por
    eso mas abajo se cuenta cuantos casan: un indice que no acierta ni una vez
    tiene que gritar, no seguir en silencio.
    """
    if not binaries_dir.is_dir():
        _log.warning("no existe el directorio de binarios: %s", binaries_dir)
        return []

    samples: list[Sample] = []
    enlazados = 0
    for path in sorted(binaries_dir.iterdir()):
        if not path.is_file() or path.stat().st_size == 0:
            continue
        par = hashes_of(path)
        if not par:
            continue
        md5, sha = par

        info: dict = {}
        for clave in (path.name.strip().lower(), md5, sha):
            info = url_by_hash.get(clave) or {}
            if info:
                enlazados += 1
                break
        url = info.get("url") or None
        host = None
        if url:
            m = re.match(r"[a-z]+://([^/:\s]+)", url, re.IGNORECASE)
            if m:
                host = m.group(1)
            if url in urls and not urls[url].sha256:
                urls[url].sha256 = sha

        stat = path.stat()
        samples.append(Sample(
            sha256=sha, path=path, size=stat.st_size, source=SOURCE_DIONAEA,
            seen_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            download_url=url, download_host=host, src_ip=info.get("src_ip"),
            protocol=SERVICIO_DE_PUERTO.get(info.get("local_port"))))

    # El guardian de este fallo. Un indice que no acierta NI UNA VEZ teniendo
    # binarios y filas de descarga no es mala suerte: es que las claves no son
    # del mismo tipo, que es exactamente lo que paso aqui durante meses sin
    # que nada lo dijera. Un CRITICAL en el log lo caza el resumen diario.
    if samples and url_by_hash and enlazados == 0:
        _log.critical(
            "NINGUNO de los %d binarios casa con las %d filas de descarga. "
            "Sin ese enlace se pierden la URL y la IP de origen, y con ellas "
            "la campana: las muestras se agrupan mal y no sale ni un IOC. "
            "Mira con que nombre esta guardando los ficheros esta version de "
            "Dionaea.", len(samples), len(url_by_hash))
    else:
        _log.info("dionaea: %d de %d binarios atados a su fila de descarga",
                  enlazados, len(samples))
    return samples
