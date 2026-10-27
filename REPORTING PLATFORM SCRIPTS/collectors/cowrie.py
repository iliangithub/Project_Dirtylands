# SPDX-License-Identifier: GPL-2.0-or-later
"""
Collector de Cowrie: lee cowrie.json y produce el modelo comun.

Los eventos y sus campos son los que Cowrie emite de verdad, comprobados
contra el log real del despliegue:

    cowrie.session.connect       src_ip, src_port, dst_port, protocol
    cowrie.login.failed          username, password
    cowrie.login.success         username, password
    cowrie.command.input         input
    cowrie.session.file_download url, shasum, outfile

Sobre handshake_ok: cualquier evento de sesion de Cowrie implica un TCP
completado, porque SSH y Telnet no llegan a generar sesion sin el. Es lo que
permite reportar a AbuseIPDB sin incumplir su prohibicion de denunciar SYN
floods y UDP, donde el origen puede ir falsificado. No se marca a partir de
otra cosa.

dst_ip se descarta siempre y en todos los eventos: es NUESTRA IP.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

from common import log
from common.model import SOURCE_COWRIE, AttackerIP, PayloadURL, Sample

from . import avisar_si_todo_descartado

_log = log.get("collector.cowrie")

# DE QUE PUERTO HABLAMOS CUANDO DECIMOS "PUERTO".
#
# Cowrie escribe en dst_port el puerto en el que EL ESCUCHA dentro del
# contenedor: 2222 y 2223. El atacante nunca marco esos numeros; marco el 22 y
# el 23, y el DNAT del anfitrion los tradujo. Reportar 2222 a AbuseIPDB es
# publicar un dato falso ---y ademas inutil, porque nadie busca ataques al
# 2222--- y de paso rompia la deteccion de "es SSH" del reporter, que
# comprobaba "22 in ports" y por tanto no se cumplia jamas.
#
# La traduccion se hace AQUI, al construir el modelo, y no en cada consumidor:
# asi el campo "ports" significa siempre lo mismo ---el puerto al que se
# conecto el atacante--- y no hay que acordarse de convertirlo en el reporter,
# en el resumen diario y en cualquier cosa que venga despues.
#
# Dionaea no lo necesita: publica 135, 445 y 1433 uno a uno, sin traduccion.
PUERTOS_PUBLICOS_POR_DEFECTO = {2222: 22, 2223: 23}


def puerto_publico(puerto: int, mapa: dict[int, int] | None) -> int:
    """El puerto que marco el atacante, a partir del que vio Cowrie.

    Lo que no este en el mapa se deja intacto: un despliegue que exponga
    Cowrie directamente en el 22 no necesita traducir nada.
    """
    tabla = PUERTOS_PUBLICOS_POR_DEFECTO if mapa is None else mapa
    return tabla.get(puerto, puerto)

# URL dentro de un comando (wget/curl). SOLO http y https, y es a proposito
# aunque los bots usen tambien tftp: de un tftp:// no se puede saber a que
# puerto se conectaron, y publicar un indicador con el puerto supuesto es
# justo lo que ThreatFox prohibe. Ver _ioc_de en orchestrator.py.
#
# El comentario decia "(wget/curl/tftp)" y la expresion nunca caso un tftp:
# el texto prometia una cosa y el codigo hacia otra. Se corrige el texto, no
# la expresion.
_CMD_URL_RE = re.compile(r"https?://[^\s'\"<>|;)]+", re.IGNORECASE)

SESSION_EVENTS = {
    "cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success",
    "cowrie.command.input", "cowrie.command.failed",
    "cowrie.session.file_download", "cowrie.session.file_upload",
}


# Un desfase NUMERICO al final de la cadena ("+03:00", "-0500"). La "Z" no
# cuenta a proposito: es justo la que Cowrie pone sin que sea verdad.
_CON_HUSO = re.compile(r"[+-]\d{2}:?\d{2}$")


def parse_timestamp(raw: str | None, tz: tzinfo = timezone.utc) -> datetime | None:
    """Convierte la marca de un evento de Cowrie a UTC.

    Cowrie firma sus marcas con una "Z" pero escribe la hora LOCAL del
    contenedor. Con el senuelo en Europe/Kyiv eso son tres horas de mas, y el
    fallo no se ve en ningun sitio: la cadena es ISO valida, se interpreta sin
    error, y lo unico que pasa es que AbuseIPDB recibe denuncias fechadas en
    el futuro. Dionaea no tiene el problema porque guarda epoch en su SQLite.

    Se intento arreglar en origen y no hay por donde: el JSON de Cowrie no
    trae el epoch (solo `timestamp`), y poner TZ=UTC en el contenedor haria
    que el `date` del senuelo dejara de verse en hora de Kyiv, que es parte de
    su identidad. Asi que se corrige al leer, diciendole al recolector en que
    huso escribe Cowrie.

    Una marca con desfase explicito (`+03:00`) se respeta tal cual: esa no
    miente. Solo se reinterpretan la "Z" y las marcas sin huso, que son
    justamente las que no se pueden creer.
    """
    if not raw:
        return None
    explicito = _CON_HUSO.search(raw) is not None
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if explicito:
        return ts.astimezone(timezone.utc)
    # "Z" o sin huso: la hora escrita es de `tz`, no de UTC.
    return ts.replace(tzinfo=None).replace(tzinfo=tz).astimezone(timezone.utc)


def resolver_huso(nombre: str) -> tzinfo:
    """Nombre IANA -> huso. Si no se reconoce, UTC y aviso; nunca revienta."""
    if not nombre or nombre.upper() == "UTC":
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(nombre)
    except Exception as exc:                          # noqa: BLE001
        _log.warning("cowrie_log_tz=%r no se reconoce (%s); se asume UTC",
                     nombre, exc)
        return timezone.utc


def comprobar_huso(log_dir: Path, glob: str, log_tz: str) -> str | None:
    """Verifica cowrie_log_tz contra el propio log, en vez de creerselo.

    La idea es sencilla y no depende de donde este el servidor: el sistema
    de ficheros pone la fecha de modificacion del cowrie.json en tiempo real
    (UTC de verdad, la del reloj), y la ultima linea del fichero se escribio
    en ese mismo instante. Si al convertir esa marca con el huso configurado
    no sale la hora del fichero, el huso esta mal, y la diferencia dice por
    cuanto.

    Hace falta porque el huso del contenedor y esta clave son dos mitades que
    tienen que estar de acuerdo, y hasta ahora solo se detectaba el error si
    caia hacia el futuro. Si caia hacia el pasado no se notaba nada: las
    denuncias salian fechadas horas antes y nadie se enteraba.

    Y resuelve el caso de mudar la maquina: el huso del senuelo es parte de
    su identidad (Kyiv) y viaja con el, no con el servidor. Montar la VPS en
    otro pais no cambia esta clave; lo que cambiaria seria el huso del
    contenedor, y entonces esto lo dice.

    Devuelve el problema como texto, o None si todo cuadra.
    """
    ficheros = [p for p in sorted(Path(log_dir).glob(glob)) if p.suffix != ".gz"]
    if not ficheros:
        return None                      # sin log no hay nada que comprobar
    reciente = max(ficheros, key=lambda p: p.stat().st_mtime)

    ultima = None
    try:
        with open(reciente, "r", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                if linea.startswith("{"):
                    ultima = linea
    except OSError:
        return None
    if not ultima:
        return None

    try:
        marca = json.loads(ultima).get("timestamp")
    except json.JSONDecodeError:
        return None

    ts = parse_timestamp(marca, resolver_huso(log_tz))
    if ts is None:
        return None

    escrito = datetime.fromtimestamp(reciente.stat().st_mtime, tz=timezone.utc)
    desfase = (ts - escrito).total_seconds()
    if abs(desfase) <= 300:              # cinco minutos de margen
        return None
    return (f"cowrie_log_tz={log_tz!r} no cuadra con el log: el ultimo evento "
            f"queda a {desfase / 3600:+.1f} h de cuando se escribio la linea. "
            f"Comprueba el huso del CONTENEDOR de Cowrie con: docker exec "
            f"dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
            f"\"import time; print(time.tzname)\"")


def _url_de_ip_privada(url: str, guard) -> bool:
    """True si el HOST de la URL es una IP no publicable (privada, loopback,
    multicast, reservada, o una de las nuestras).

    Un dominio NO es una IP privada: devuelve False y su reportabilidad se
    decide mas adelante (sin-muestra, antiguedad, etc). Esto solo caza las IP
    literales que no deben ni acercarse a una plataforma ---el caso tipico es
    el `wget http://192.168.1.1:8088/i` con el que Mirai tantea la puerta de
    enlace de la LAN de la victima---. Antes esas URL entraban en la tuberia y
    solo se paraban en la BARRERA, la ultima linea antes del POST; ahora se
    quedan fuera de entrada. Siguen en el cowrie.json para el analisis: lo que
    se quita es que compitan por publicarse.
    """
    from urllib.parse import urlsplit
    import ipaddress

    try:
        host = urlsplit(url).hostname
    except ValueError:
        return True
    if not host:
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False            # es un dominio, no una IP
    return not guard.is_reportable(host)


def read_events(log_dir: Path, glob: str, since: datetime,
                tz: tzinfo = timezone.utc) -> list[dict]:
    """Lee los cowrie.json, rotados incluidos, y filtra por antiguedad.

    Los .gz rotados se leen tambien: perder eventos por rotacion justo antes
    de la ejecucion del cron es un fallo silencioso y facil de no notar.
    """
    events: list[dict] = []
    adelantados = 0
    futuro = datetime.now(timezone.utc) + timedelta(minutes=5)
    files = sorted(Path(log_dir).glob(glob))
    if not files:
        _log.warning("no hay ficheros que casen con %s en %s", glob, log_dir)

    for path in files:
        try:
            if path.suffix == ".gz":
                import gzip
                handle = gzip.open(path, "rt", encoding="utf-8", errors="replace")
            else:
                handle = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.warning("no se pudo abrir %s: %s", path, exc)
            continue

        with handle:
            for line in handle:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue        # linea truncada por rotacion a mitad
                ts = parse_timestamp(ev.get("timestamp"), tz)
                if ts and ts >= since:
                    events.append(ev)
                if ts and ts > futuro:
                    adelantados += 1

    _log.info("leidos %d eventos de %d ficheros", len(events), len(files))
    if adelantados:
        # Una marca en el futuro solo puede venir de un huso mal interpretado,
        # y publicar con esa fecha es publicar datos falsos. Se dice en voz
        # alta porque la primera vez costo media tarde encontrarlo.
        _log.error("%d eventos con fecha en el FUTURO: revisa cowrie_log_tz "
                   "en el config.ini; no reportes hasta arreglarlo", adelantados)
    return events


def collect(log_dir: Path, glob: str, downloads_dir: Path, guard,
            lookback_hours: int = 24, log_tz: str = "UTC",
            puertos_publicos: dict[int, int] | None = None
            ) -> tuple[list[AttackerIP], list[Sample], list[PayloadURL]]:
    tz = resolver_huso(log_tz)
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    events = read_events(Path(log_dir), glob, since, tz)

    attackers: dict[str, AttackerIP] = {}
    urls: dict[str, PayloadURL] = {}
    hashes: dict[str, dict] = {}
    descartados: dict[str, int] = {}

    for ev in events:
        ip = ev.get("src_ip")
        if not ip:
            continue

        okay, reason = guard.check(ip)
        if not okay:
            descartados[reason] = descartados.get(reason, 0) + 1
            continue

        eid = ev.get("eventid", "")
        ts = parse_timestamp(ev.get("timestamp"), tz) or datetime.now(timezone.utc)

        att = attackers.get(ip)
        if att is None:
            att = attackers[ip] = AttackerIP(
                ip=ip, source=SOURCE_COWRIE, first_seen=ts, last_seen=ts)
        att.first_seen = min(att.first_seen, ts)
        att.last_seen = max(att.last_seen, ts)
        if eid in SESSION_EVENTS:
            att.handshake_ok = True
        if ev.get("protocol"):
            att.protocols.add(str(ev["protocol"]))

        if eid == "cowrie.session.connect":
            # dst_port se traduce; src_port es el puerto efimero del atacante y
            # se guarda tal cual.
            try:
                att.ports.add(puerto_publico(int(ev["dst_port"]), puertos_publicos))
            except (KeyError, TypeError, ValueError):
                pass
            try:
                att.source_ports.add(int(ev["src_port"]))
            except (KeyError, TypeError, ValueError):
                pass
        elif eid == "cowrie.login.failed":
            att.login_failures += 1
        elif eid == "cowrie.login.success":
            att.login_successes += 1
        elif eid in ("cowrie.command.input", "cowrie.command.failed"):
            att.commands += 1
            for found in _CMD_URL_RE.findall(ev.get("input") or ""):
                if _url_de_ip_privada(found, guard):
                    continue
                urls.setdefault(found, PayloadURL(
                    url=found, source=SOURCE_COWRIE, seen_at=ts, src_ip=ip))
        elif eid == "cowrie.session.file_download":
            sha = (ev.get("shasum") or "").strip().lower()
            url = (ev.get("url") or "").strip()
            if url and _url_de_ip_privada(url, guard):
                # No puede acreditar nada como origen: se conserva la muestra
                # (VirusTotal, MalwareBazaar) pero sin URL, asi no llega ni a
                # URLhaus ni al reporte de distribucion de AbuseIPDB.
                url = ""
            if url:
                existente = urls.get(url)
                if existente is None or not existente.sha256:
                    urls[url] = PayloadURL(url=url, source=SOURCE_COWRIE,
                                           seen_at=ts, sha256=sha or None, src_ip=ip)
            if sha and sha not in hashes:
                hashes[sha] = {"ts": ts, "url": url or None, "src_ip": ip,
                               "protocol": (ev.get("protocol") or None)}
            elif sha and url and not hashes[sha].get("url"):
                # Llego antes por una SUBIDA, que no trae URL. Ahora la
                # sabemos, y con URL se puede acreditar en URLhaus y derivar
                # el IOC de ThreatFox; sin ella, no. Se rellena.
                hashes[sha]["url"] = url

        elif eid == "cowrie.session.file_upload":
            # LO QUE SUBEN, NO SOLO LO QUE BAJAN.
            #
            # Un binario que entra por SFTP o SCP generaba este evento y no lo
            # miraba nadie: solo contaba para dar por buena la sesion. El
            # fichero quedaba en disco y no llegaba ni a VirusTotal ni a
            # MalwareBazaar. Se perdia la muestra, que es el motivo de existir
            # del senuelo.
            #
            # Cowrie las guarda en el mismo sitio que las descargas ---SFTP usa
            # directamente `download_path`, y SCP usa `download_path_uniq`, que
            # cae por defecto en `download_path` y nuestro cowrie.cfg no lo
            # redefine---, asi que _resolve_samples las encuentra sin cambiar
            # nada mas.
            #
            # OJO CON EL CAMPO `url`: el evento de SCP trae uno, pero **no es
            # una URL**, es la ruta de destino dentro del senuelo (algo como
            # "/tmp/x"). Publicarla como origen del payload seria inventarse un
            # indicador. Se fuerza a None: una subida no tiene procedencia que
            # podamos acreditar, y sin URL el orquestador ya se salta solo
            # URLhaus y ThreatFox.
            sha = (ev.get("shasum") or "").strip().lower()
            if sha and sha not in hashes:
                hashes[sha] = {"ts": ts, "url": None, "src_ip": ip,
                               "protocol": (ev.get("protocol") or None)}

    for reason, count in sorted(descartados.items()):
        _log.info("descartados %d eventos por IP no reportable: %s", count, reason)
    avisar_si_todo_descartado(_log, len(attackers), descartados)

    samples = _resolve_samples(hashes, Path(downloads_dir))
    _log.info("cowrie: %d IP, %d muestras en disco, %d URL",
              len(attackers), len(samples), len(urls))
    return list(attackers.values()), samples, list(urls.values())


def _resolve_samples(hashes: dict[str, dict], downloads_dir: Path) -> list[Sample]:
    """Empareja cada shasum con su fichero. Sin fichero no hay muestra.

    Cowrie registra el download aunque el binario ya no este en disco (limpieza,
    fallo a mitad de la descarga). Reportar un hash sin tener el fichero seria
    reportar algo que no podemos respaldar, asi que esos casos se saltan.
    """
    samples: list[Sample] = []
    for sha, info in hashes.items():
        path = downloads_dir / sha
        if not path.is_file():
            _log.debug("shasum %s sin fichero en %s", sha[:16], downloads_dir)
            continue
        host = None
        if info["url"]:
            m = re.match(r"https?://([^/:\s]+)", info["url"], re.IGNORECASE)
            if m:
                host = m.group(1)
        samples.append(Sample(
            sha256=sha, path=path, size=path.stat().st_size,
            source=SOURCE_COWRIE, seen_at=info["ts"],
            download_url=info["url"], download_host=host, src_ip=info["src_ip"],
            protocol=info.get("protocol")))
    return samples
