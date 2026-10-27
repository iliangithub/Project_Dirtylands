#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Orquestador: recoge de los dos honeypots y publica en el orden correcto.

El orden no es una preferencia, es lo que decide quien se lleva la autoria:

    VirusTotal (subida)  ->  espera  ->  veredicto  ->  comentario + voto
                                                    ->  MalwareBazaar
                                                    ->  ThreatFox / URLhaus

Los bots vigilan MalwareBazaar y corren a subir a VirusTotal lo que ven alli.
Si publicaramos primero en MalwareBazaar, les estariamos dando el aviso.

Por defecto NO envia nada: hace falta --live de forma explicita. Una
herramienta que publica por defecto es una herramienta que algun dia publica
algo que no debia.

Codigos de salida, distintos a proposito para que el cron y las alertas
puedan distinguirlos:

    0  todo bien
    1  error inesperado
    2  problema de configuracion
    3  fallo del self-test
    4  se completo, pero con errores de red o rechazos de plataforma
    5  cuota agotada en alguna plataforma
"""

from __future__ import annotations

import argparse
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common import ipguard, log
from common.config import Config, ConfigError, DEFAULT_CONFIG
from common.http import HttpClient
from common.model import (AttackerIP, C2Indicator, Sample, artefacto_inocuo,
                          campaign_host)
from common.ratelimit import QuotaExceeded, RateLimiter
from common.state import DISCARDED, PENDING_VERDICT, PUBLISHED, State
from reporters.abuseipdb import AbuseIPDB
from reporters.base import AbuseChReporter
from reporters.malwarebazaar import MalwareBazaar
from reporters.threatfox import ThreatFox
from reporters.urlhaus import URLhaus
from reporters.virustotal import VirusTotal

EXIT_OK, EXIT_ERROR, EXIT_CONFIG = 0, 1, 2
EXIT_SELFTEST, EXIT_PARTIAL, EXIT_QUOTA = 3, 4, 5

ABUSE_CH = AbuseChReporter.CUENTA

# Cuanto se espera antes de volver a mirar el veredicto, y cuando se rinde uno.
# El limite de 8 dias deja margen dentro de la ventana de 10 de MalwareBazaar.
RECHECK_HOURS = 12
# Reintento CORTO, para lo que solo se quedo fuera por un tope de ritmo. No se
# usa RECHECK_HOURS porque no estamos esperando a que VirusTotal cambie de
# opinion: el veredicto ya lo tenemos y lo unico que falta es sitio para
# publicar, que lo hay en la pasada siguiente.
REINTENTO_HOURS = 1
GIVE_UP_DAYS = 8


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Reporta a las plataformas lo capturado por los honeypots.")
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    p.add_argument("--live", action="store_true",
                   help="ENVIA DE VERDAD. Sin esta bandera solo simula.")
    p.add_argument("--self-test", action="store_true",
                   help="Comprueba configuracion y barreras, y sale.")
    p.add_argument("--only", choices=["cowrie", "dionaea"],
                   help="Recoger de un solo honeypot.")
    p.add_argument("--show-rejections", type=int, metavar="N", default=0,
                   help="Muestra los ultimos N rechazos con su motivo y sale.")
    p.add_argument("--reset-breaker", action="store_true",
                   help="Rearma el cortacircuitos de la cuenta de abuse.ch. "
                        "Hazlo solo despues de entender por que salto.")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


# --------------------------------------------------------------------------
def publicar_ips_propias(cfg: Config, logger) -> None:
    """Deja la [blocklist] donde el plugin de Cowrie pueda leerla.

    El plugin corre DENTRO del contenedor y necesita saber que IP somos
    nosotros: sin eso, una comprobacion propia llega como si fuera un ataque
    y --- peor --- el boton rojo ofrece banear nuestro propio nodo de VPN.

    No se resuelve montando el config.ini en el contenedor. Ese fichero lleva
    las tres claves de API, y meterlas dentro del honeypot para ahorrarse un
    volcado de texto es cambiar una comodidad por un riesgo. Lo que se publica
    aqui es SOLO la lista, sin un secreto dentro.

    Y se reescribe en cada pasada a proposito, en vez de generarse una vez al
    instalar: anadir un nodo de salida al config.ini tiene que llegar solo al
    plugin, sin acordarse de regenerar nada. El plugin lo relee cuando cambia
    la fecha del fichero.

    Si el directorio no existe --- una maquina sin la parte de Telegram --- no
    se hace nada y no se avisa: no es un error, es que ahi no hace falta.
    """
    destino = Path(cfg.section("paths").get(
        "ips_propias_out", "/opt/dirtyland/Telegram Reports/ips-propias.txt"))
    if not destino.parent.is_dir():
        return

    lineas = ["# Generado por el reporter en cada pasada. NO editar a mano:",
              "# la lista de verdad es la [blocklist] del config.ini.",
              *cfg.block_ips, *cfg.block_cidrs]
    try:
        tmp = destino.with_suffix(destino.suffix + ".tmp")
        tmp.write_text("\n".join(lineas) + "\n", encoding="utf-8")
        # Reemplazo atomico: el plugin puede estar leyendolo justo ahora, y
        # pillarlo a medio escribir le daria una lista incompleta --- o sea,
        # tratar una IP nuestra como ajena en el peor momento.
        tmp.replace(destino)
        destino.chmod(0o644)
    except OSError as exc:
        logger.warning("no se pudo publicar %s: %s", destino, exc)


def self_test(cfg: Config, logger) -> int:
    """Comprueba lo que se puede comprobar sin tocar la red."""
    fallos: list[str] = []

    logger.info("--- self-test ---")
    fallos += cfg.validate()

    # La barrera se prueba de verdad, no se da por buena. Una barrera rota no
    # se distingue de una que nunca tuvo que actuar.
    fallos += ipguard.self_test()

    # Comprobacion util de verdad tras una reinstalacion: que las IP que el
    # config declara como propias esten efectivamente bloqueadas.
    guard = ipguard.IPGuard(cfg.block_ips, cfg.block_cidrs)
    for propia in cfg.block_ips:
        if guard.is_reportable(propia):
            fallos.append(f"[blocklist] declara {propia} pero la barrera la dejaria pasar")

    # El huso de Cowrie se COMPRUEBA contra su propio log, no se da por bueno.
    # Es la unica de las dos mitades que se puede verificar desde aqui.
    paths = cfg.section("paths")
    if paths.get("cowrie_log_dir"):
        try:
            from collectors.cowrie import comprobar_huso
            problema = comprobar_huso(Path(paths["cowrie_log_dir"]),
                                      paths.get("cowrie_log_glob", "cowrie.json*"),
                                      cfg.cowrie_log_tz)
            if problema:
                fallos.append(problema)
        except Exception as exc:                 # noqa: BLE001
            logger.warning("no se pudo comprobar el huso de Cowrie: %s", exc)

    try:
        st = State(cfg.state_db)
        st.close()
    except Exception as exc:                     # noqa: BLE001
        fallos.append(f"no se pudo abrir la base de estado: {exc}")

    for nombre in ("virustotal", "malwarebazaar", "threatfox", "urlhaus", "abuseipdb"):
        logger.info("  %-14s %s", nombre,
                    "activado" if cfg.enabled(nombre) else "desactivado")

    # El cortacircuitos saltado no es un fallo de configuracion, pero callarselo
    # aqui seria peor: explicaria por que las tres plataformas no publican nada.
    try:
        st = State(cfg.state_db)
        salto = st.breaker(ABUSE_CH)
        st.close()
        if salto:
            logger.warning(
                "  cortacircuitos de %s SALTADO desde el %s (%s). Las tres "
                "plataformas de abuse.ch estan paradas; rearma con --reset-breaker",
                ABUSE_CH, salto["tripped_at"], salto["reason"])
    except Exception:                            # noqa: BLE001
        pass

    if fallos:
        logger.error("self-test: %d problemas", len(fallos))
        for f in fallos:
            logger.error("  - %s", f)
        return EXIT_SELFTEST

    logger.info("self-test: todo correcto")
    return EXIT_OK


# --------------------------------------------------------------------------
def _fusionar_atacantes(attackers: list[AttackerIP], logger) -> list[AttackerIP]:
    """Junta en una sola las mitades de evidencia de la misma IP."""
    # UNA IP, UN INFORME. Cada collector devuelve su lista ya agrupada por
    # IP, pero cada uno la suya: una IP que ataca a los DOS honeypots llegaba
    # aqui DOS VECES, con la evidencia partida en dos mitades.
    #
    # No era inofensivo, y cambiaba lo que se PUBLICA. El servicio de la
    # denuncia se nombra a partir de att.ports, y la categoria de escaneo pide
    # tres puertos distintos: con la evidencia partida se reportaba la mitad
    # que ordenase primero ---diciendo "SSH honeypot" de una IP que tambien
    # habia tocado el 445--- y la otra mitad moria en la ventana de
    # enfriamiento, que la tomaba por un duplicado. La promesa es que cuando
    # una IP entra por varios servicios se denuncien todos, y sin esto no se
    # cumplia.
    #
    # Se veia en --show-rejections: la misma IP con "enfriamiento" dos veces
    # en la misma pasada y con el mismo "reportada hace X h".
    #
    # Las fechas de los dos collectors son UTC con zona, asi que min/max no
    # mezcla naive con aware.
    fusionadas: dict[str, AttackerIP] = {}
    for a in attackers:
        previa = fusionadas.get(a.ip)
        if previa is None:
            fusionadas[a.ip] = a
            continue
        previa.first_seen = min(previa.first_seen, a.first_seen)
        previa.last_seen = max(previa.last_seen, a.last_seen)
        previa.handshake_ok = previa.handshake_ok or a.handshake_ok
        previa.sqli_evidence = previa.sqli_evidence or a.sqli_evidence
        previa.login_failures += a.login_failures
        previa.login_successes += a.login_successes
        previa.commands += a.commands
        previa.ports |= a.ports
        previa.source_ports |= a.source_ports
        previa.protocols |= a.protocols
        if a.source not in previa.source.split("+"):
            previa.source += "+" + a.source
        if a.note and a.note not in previa.note:
            previa.note = f"{previa.note} {a.note}".strip()
    if len(fusionadas) != len(attackers):
        logger.info("%d IP vistas por los dos honeypots: evidencia unificada",
                    len(attackers) - len(fusionadas))
    return list(fusionadas.values())


def collect_all(cfg: Config, guard, only: str | None, logger):
    """Recoge de los honeypots configurados. Un fallo en uno no tumba el otro."""
    attackers, samples, urls = [], [], []
    paths = cfg.section("paths")

    if only != "dionaea" and paths.get("cowrie_log_dir"):
        from collectors import cowrie
        try:
            a, s, u = cowrie.collect(
                Path(paths.get("cowrie_log_dir")),
                paths.get("cowrie_log_glob", "cowrie.json*"),
                Path(paths.get("downloads_dir", "")), guard, cfg.lookback_hours,
                cfg.cowrie_log_tz, cfg.cowrie_puertos_publicos)
            attackers += a; samples += s; urls += u
        except Exception as exc:                 # noqa: BLE001
            logger.error("collector de Cowrie: %s", exc)

    if only != "cowrie" and paths.get("dionaea_sqlite"):
        from collectors import dionaea
        try:
            a, s, u = dionaea.collect(
                Path(paths.get("dionaea_sqlite")),
                Path(paths.get("dionaea_binaries", "")), guard, cfg.lookback_hours)
            attackers += a; samples += s; urls += u
        except Exception as exc:                 # noqa: BLE001
            logger.error("collector de Dionaea: %s", exc)

    attackers = _fusionar_atacantes(attackers, logger)

    # Una muestra, un sha256. Cada repetida en esta lista es una consulta de
    # mas a VirusTotal en CADA pasada, y la cuota son 500 al dia.
    #
    # Que pasaba de verdad: en la pasada del 2026-08-20 el mismo hash aparecio
    # TRES veces seguidas en el log, y no era un despiste del log --- era la
    # lista. Dos ficheros con nombres distintos y el mismo contenido, o el
    # mismo binario recogido por los dos collectors, dan varios Sample con el
    # mismo sha256, y nada mas abajo lo miraba.
    #
    # Se queda el primero, que conserva el orden de recogida, y se avisa: si
    # esto crece hay algo que entender en los honeypots, no solo que
    # deduplicar aqui.
    unicas: dict[str, Sample] = {}
    repetidas = 0
    for s in samples:
        if s.sha256 in unicas:
            repetidas += 1
            continue
        unicas[s.sha256] = s
    if repetidas:
        logger.info("%d muestras repetidas descartadas (%d distintas de %d)",
                    repetidas, len(unicas), len(samples))
    samples = list(unicas.values())

    return attackers, samples, urls


# --------------------------------------------------------------------------
def stage_upload(vt: VirusTotal, state: State, samples: list[Sample], logger) -> None:
    """Momento 1: subir a VirusTotal cuanto antes. Nada mas.

    Aqui no se comenta ni se vota: la autoria se gana con la subida, y el
    juicio se deja para cuando los motores hayan tenido tiempo de opinar.
    """
    # Sin VirusTotal utilizable no hay nada que hacer con las muestras, y las
    # consultas se hacen tambien en simulacion: sin esta guarda, una clave sin
    # configurar significaria pegarle a la API cada 15 minutos para nada.
    if not vt.is_enabled():
        if samples:
            logger.warning("%d muestras en espera: VirusTotal no esta utilizable",
                           len(samples))
        return

    for sample in samples:
        state.upsert_sample(
            sample.sha256, source=sample.source, path=str(sample.path),
            arch=sample.elf_machine,
            campaign_key=campaign_host(sample))

        fila = state.get_sample(sample.sha256)
        if fila and fila["state"] in (PUBLISHED, DISCARDED):
            continue

        # UNA sola pregunta por muestra en toda su vida. Esta guarda es la que
        # sostiene la cuota de VirusTotal.
        #
        # is_new() existe para una cosa: llegar los primeros y ganar la
        # autoria. Preguntado una vez, la respuesta ya no puede volver a ser
        # "si" --- o era nueva y la subimos nosotros, o ya la tenian; en los
        # dos casos, a partir de ese momento VirusTotal la tiene. Volver a
        # preguntar es gastar una llamada para oir "no".
        #
        # Y no era una llamada: eran todas. Este bucle recorre los binarios
        # que hay EN DISCO, que no se borran, mientras que el rechequeo
        # diferido de stage_verdict si respeta next_check. Con 46 muestras
        # pendientes y el cron cada 15 minutos salian 46 x 96 = 4416 llamadas
        # al dia contra una cuota de 500. Por eso la pasada del 2026-08-20
        # llego a 497/500 y diecinueve muestras se quedaron sin juzgar: la
        # cuota se la comia preguntar por lo que ya sabiamos.
        #
        # attempts lo pone schedule_recheck y no lo lee nadie mas para
        # decidir, asi que sirve de marca de "ya hemos hablado con VirusTotal
        # de esta". Se marca ademas explicitamente mas abajo, para no depender
        # de que stage_verdict llegue a correr.
        if fila and (fila["attempts"] or 0) > 0:
            continue

        # ANTES de preguntar a VirusTotal, y por eso aqui: lo que claramente
        # no es un payload no merece ni la consulta ni, mucho menos, que se le
        # suba como primera aparicion.
        motivo = artefacto_inocuo(sample.path, sample.size)
        if motivo:
            logger.info("%s: %s; no se consulta ni se sube",
                        sample.sha256[:16], motivo)
            state.upsert_sample(sample.sha256, state=DISCARDED)
            continue

        nueva = vt.is_new(sample.sha256)
        if nueva is None:
            # Sin respuesta NO se marca: aqui no hemos averiguado nada, y la
            # proxima pasada tiene que volver a intentarlo. Es tambien lo que
            # pasa cuando la cuota esta agotada.
            logger.warning("%s: VirusTotal no responde, se reintenta en la "
                           "proxima pasada", sample.sha256[:16])
            continue

        # Respuesta firme: no se vuelve a preguntar por esta muestra nunca.
        state.upsert_sample(sample.sha256, attempts=1)

        if nueva:
            logger.info("%s: no esta en VirusTotal, subiendo para ser primeros",
                        sample.sha256[:16])
            vt.upload(sample)
            # Recien subida: los motores necesitan tiempo. Se juzga mas tarde.
            state.schedule_recheck(sample.sha256, RECHECK_HOURS)
        else:
            # Ya la tenian: el veredicto puede estar disponible AHORA, asi que
            # esperar 12 h no aporta nada y consume la ventana de frescura de
            # URLhaus. Se deja vencida para juzgarla en esta misma pasada.
            logger.info("%s: ya estaba en VirusTotal, se evalua ya",
                        sample.sha256[:16])
            state.upsert_sample(sample.sha256, next_check=None)


def stage_verdict(vt: VirusTotal, mb: MalwareBazaar, tf: ThreatFox, uh: URLhaus,
                  ab: AbuseIPDB,
                  state: State, samples_by_hash: dict, logger) -> None:
    """Momento 2: mirar el veredicto de lo que ya toca y publicar si procede."""
    if not vt.is_enabled():
        return

    # El censo va ANTES del bucle y se imprime SIEMPRE. Una pasada puede
    # acabar con 70 binarios recogidos, 0 enviados y 0 rechazos, y sin esto no
    # hay forma de saber si es que estan esperando o es que algo nuestro los
    # ha perdido. Cuesta dos consultas y ahorra la duda entera.
    censo = state.censo_muestras()
    if censo["por_estado"]:
        logger.info("muestras en el historial: %s",
                    ", ".join(f"{k}={v}" for k, v in sorted(censo["por_estado"].items())))
    tocan = state.due_samples()
    if not tocan and censo["esperando"]:
        logger.info("ninguna muestra que juzgar ahora: %d esperando su "
                    "rechequeo, la primera el %s UTC",
                    censo["esperando"], censo["proxima"])

    for fila in tocan:
        sha = fila["sha256"]
        muestra = samples_by_hash.get(sha)

        if muestra is None:
            ruta = Path(fila["path"] or "")
            if not ruta.is_file():
                state.upsert_sample(sha, state=DISCARDED)
                state.reject("virustotal", sha, "fichero",
                             "el binario ya no esta en disco")
                continue
            muestra = Sample(sha256=sha, path=ruta, size=ruta.stat().st_size,
                             source=fila["source"] or "cowrie",
                             seen_at=datetime.fromisoformat(fila["first_local"]))

        try:
            v = vt.verdict(sha)
        except LookupError:
            logger.warning("%s: sin respuesta de VirusTotal, se aplaza", sha[:16])
            state.schedule_recheck(sha, RECHECK_HOURS)
            continue

        state.upsert_sample(
            sha, vt_malicious=v["malicious"], vt_suspicious=v["suspicious"],
            family=(v["familias"][0] if v["familias"] else None),
            cluster_key=v.get("vhash") or v.get("ssdeep"),
            vt_first_sub=v["first_submission"].isoformat() if v["first_submission"] else None)

        motivo = vt.motivo_rechazo(sha, v)
        if motivo:
            edad = datetime.now(timezone.utc) - datetime.fromisoformat(fila["first_local"])
            if motivo in vt.DEFINITIVOS:
                # No todo rechazo mejora esperando. Reintentar uno que no puede
                # cambiar son dieciseis consultas a VirusTotal ---dos al dia
                # durante ocho--- para llegar al mismo no, y esa cuota es la
                # que limita todo lo demas.
                logger.info("%s: rechazada por '%s', que no cambia con el "
                            "tiempo; se descarta sin reintentar", sha[:16], motivo)
                state.upsert_sample(sha, state=DISCARDED)
            elif edad > timedelta(days=GIVE_UP_DAYS):
                logger.info("%s: %d dias sin alcanzar el umbral, se descarta",
                            sha[:16], edad.days)
                state.upsert_sample(sha, state=DISCARDED)
            else:
                state.schedule_recheck(sha, RECHECK_HOURS)
            continue

        familia = v["familias"][0] if v["familias"] else None
        logger.info("%s: veredicto firme (%d motores, familias: %s)",
                    sha[:16], v["malicious"], ", ".join(v["familias"]))

        # Orden fijo: primero comentar y votar en VirusTotal, y solo despues
        # MalwareBazaar. Al reves seria avisar a los bots.
        vt.comment_and_vote(muestra, v)

        # MalwareBazaar SI necesita el nombre: la muestra se sube etiquetada
        # con el. Por eso la puerta de familia se aplica AQUI y no antes ---si
        # se aplicara antes, como se hacia, un nombre que no supieramos poner
        # apagaria tambien el voto de VirusTotal, la URL de URLhaus y la
        # denuncia del servidor que sirvio el binario, que no piden ninguno---.
        if vt.familia_ok(mb, sha, v):
            mb.upload(muestra, v, familia)

        if muestra.download_url:
            uh.submit(_url_de(muestra))

            # EL SERVIDOR QUE SIRVIO EL BINARIO TAMBIEN SE DENUNCIA.
            #
            # Hasta ahora solo se denunciaba a AbuseIPDB la IP que ATACA. Pero
            # en un ataque de Mirai hay dos maquinas distintas y las dos son
            # malas: la que entra al senuelo y la que le sirve el payload. La
            # segunda no aparecia en ningun sitio salvo como IOC en ThreatFox.
            #
            # Se hace AQUI, dentro del bloque que ya paso `vt.passes_gate`, y
            # eso no es casualidad: es lo que convierte la denuncia en
            # defendible. Tenemos el fichero, lo bajamos de esa IP, y
            # VirusTotal confirma que es malware. Sin esas tres cosas no se
            # denuncia, porque haber visto una direccion escrita en un comando
            # no acredita nada contra su dueno.
            _host_dist = _distribuidor_de(muestra, v, familia)
            if _host_dist:
                ab.report_distribucion(_host_dist)

            ioc, ioc_type, motivo = _ioc_de(muestra.download_url)
            if ioc:
                tf.submit(C2Indicator(
                    ioc=ioc, ioc_type=ioc_type,
                    source=muestra.source, seen_at=muestra.seen_at,
                    threat_type="payload_delivery", malware=familia, sha256=sha,
                    reference=f"https://www.virustotal.com/gui/file/{sha}"), vetted=True)
            elif tf.is_enabled():
                # Se anota como rechazo en vez de desaparecer. Un descarte que
                # no se cuenta en ningun sitio es indistinguible de no tener
                # nada que enviar, y asi es como se puede pasar meses creyendo
                # que "no hay IOC" cuando lo que hay es una puerta cerrada.
                tf.gate(muestra.download_url, "ioc-no-derivable", False, motivo)

        # Solo se da por terminada si de verdad salio todo. Antes se marcaba
        # PUBLISHED pase lo que pase, asi que una muestra que no se subio por
        # haber alcanzado un tope quedaba como hecha y salia de la cola PARA
        # SIEMPRE: se perdia en silencio, que es la peor forma de perderla.
        aplazados = [r.name for r in (vt, mb, uh, tf) if r.diferido]
        if not aplazados:
            state.upsert_sample(sha, state=PUBLISHED)
        elif (datetime.now(timezone.utc)
              - datetime.fromisoformat(fila["first_local"])) > timedelta(days=GIVE_UP_DAYS):
            logger.warning("%s: %d dias aplazandose por topes, se abandona",
                           sha[:16], GIVE_UP_DAYS)
            state.upsert_sample(sha, state=DISCARDED)
        else:
            logger.info("%s: aplazada por el tope de %s, se reintenta en %d h",
                        sha[:16], ", ".join(aplazados), REINTENTO_HOURS)
            state.schedule_recheck(sha, REINTENTO_HOURS)


def anotar_urls_sin_muestra(uh: URLhaus, urls: list, samples: list[Sample]) -> None:
    """Deja constancia de las URL que se recogieron y NO se van a publicar.

    URLhaus solo recibe las URL que produjeron una muestra capturada, y eso es
    deliberado: sin binario no hay veredicto de VirusTotal, y sin veredicto no
    se puede acreditar que la URL sirviera malware. Es la regla de oro
    ---VirusTotal primero, apartado 3.5.3 del README--- aplicada aqui.

    Lo que estaba mal era el silencio. El colector devuelve estas URL, se
    cuentan en la linea de "recogido" y ahi desaparecian: ningun rechazo, ningun
    motivo. Y eso es exactamente lo que este proyecto ya escribio en otro sitio
    ---"un descarte que no se cuenta en ningun sitio es indistinguible de no
    tener nada que enviar"--- porque asi es como se pasan meses creyendo que no
    hay material cuando lo que hay es una puerta cerrada.

    No publica nada nuevo. Solo hace visible en --show-rejections una decision
    que ya se estaba tomando.
    """
    if not urls or not uh.is_enabled():
        return
    con_muestra = {s.download_url for s in samples if s.download_url}
    for u in urls:
        direccion = getattr(u, "url", None) or str(u)
        if direccion in con_muestra:
            continue

        # NO todas las que quedan fuera son iguales, y decir que de todas
        # ellas "no se capturo el binario" era MENTIRA en la mitad de los
        # casos. Un servidor que sirve el mismo payload en /bin.sh y en /i
        # deja dos URL con el MISMO sha; el colector le da la muestra a la
        # primera que vio ---guarda `if sha not in hashes`--- y la segunda
        # caia aqui con un motivo que afirmaba lo contrario de lo que pasó.
        #
        # Caso real del 2026-08-22: de http://42.177.102.201:45262/i se
        # capturo binario CINCO veces, con su hash, y el log decia que no se
        # habia llegado a capturar.
        sha = getattr(u, "sha256", None)
        if sha:
            uh.gate(direccion, "muestra-compartida", False,
                    f"SI se capturo binario de esta URL ({sha[:16]}), pero ese "
                    f"mismo hash habia llegado antes por otra URL y es esa la "
                    f"que lleva la muestra: el servidor sirve el mismo payload "
                    f"en varias rutas. No se publica, aunque se podria "
                    f"acreditar igual que la otra")
        else:
            uh.gate(direccion, "sin-muestra", False,
                    "se vio la URL pero no se llego a capturar el binario: sin "
                    "muestra no hay veredicto de VirusTotal, y sin veredicto no "
                    "se publica")


def _url_de(sample: Sample):
    from common.model import PayloadURL
    return PayloadURL(url=sample.download_url, source=sample.source,
                      seen_at=sample.seen_at, sha256=sample.sha256,
                      src_ip=sample.src_ip)


def _distribuidor_de(sample, verdict, familia):
    """Construye el host de distribucion, o None si no se puede acreditar.

    Solo devuelve algo cuando el HOST de la URL es una direccion IP literal.
    Si es un dominio no se denuncia a AbuseIPDB: ahi la IP la resuelve el DNS
    en un momento dado y puede cambiar, o ser una CDN compartida con miles de
    sitios legitimos. Denunciar la IP de un dominio es acusar a quien tenga esa
    direccion HOY, que no tiene por que ser el mismo de ayer.
    """
    from urllib.parse import urlsplit
    import ipaddress

    from common.model import HostDistribucion

    if not sample.download_url:
        return None
    try:
        partes = urlsplit(sample.download_url)
        host = partes.hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        _ip = ipaddress.ip_address(host)
    except ValueError:
        return None            # es un dominio: no se denuncia la IP

    # Y ADEMAS tiene que ser una IP publica de verdad. Sin esto, un
    # `wget http://192.168.1.1/x` habria construido una denuncia contra la
    # puerta de enlace de una LAN. La barrera de AbuseIPDB la para igual, pero
    # aqui se corta antes: no se fabrica un informe que solo puede morir.
    if not _ip.is_global or _ip.is_multicast:
        return None

    try:
        puerto = partes.port or (443 if partes.scheme == "https" else 80)
    except ValueError:
        puerto = None

    return HostDistribucion(
        ip=host, url=sample.download_url, sha256=sample.sha256,
        seen_at=sample.seen_at, source=sample.source, familia=familia,
        motores=verdict.get("malicious", 0), puerto=puerto)


def _ioc_de(url: str) -> tuple[str | None, str, str]:
    """Construye el IOC de ThreatFox a partir de la URL de descarga.

    Devuelve (ioc, tipo, motivo). Si no se puede derivar un indicador del que
    respondamos, ioc es None y `motivo` dice por que --- y ese motivo se
    registra como rechazo, para que se vea. Antes esto devolvia None a secas y
    quien llamaba hacia "if ioc:", asi que el descarte no quedaba en ninguna
    parte: ni en --show-rejections ni en el resumen diario. Parte de "no
    reportamos casi ningun IOC" era simplemente que no se veia por que.

    LA REGLA: el puerto se OBSERVA, nunca se supone.

    Aqui habia un fallo serio. El puerto que faltaba se rellenaba con
    "443 si https, si no 80", y eso solo es cierto para http y https, donde
    ese es de verdad el puerto al que se conecto el cliente. Para cualquier
    otro esquema era inventarselo:

        smb://46.46.121.73/transaction/\\PIPE\\  ->  46.46.121.73:80
        tftp://10.0.0.5/mips                    ->  10.0.0.5:80

    A ese puerto 80 no se conecto nadie jamas. La primera es ademas un caso
    real del 2026-08-20: no es ni siquiera una URL de distribucion, es la
    pseudo-URL que Dionaea se inventa para nombrar una subida por SMB, que
    entro por el 445. Habriamos afirmado ante ThreatFox que un puerto que
    nunca se toco es infraestructura de entrega de payload.

    Y la unica regla de ThreatFox es "Please do only submit confirmed / vetted
    IOCs". Un indicador con un puerto fabricado es exactamente lo contrario, y
    la cuenta es la misma que la de MalwareBazaar y URLhaus: un baneo por esto
    se lleva las tres por delante.

    Por eso solo se derivan IOC de http y https, igual que hace la puerta
    "esquema" de URLhaus. Lo demas se descarta con su motivo.
    """
    import ipaddress
    from urllib.parse import urlsplit

    try:
        partes = urlsplit(url)
        host = partes.hostname
    except ValueError:
        return None, "domain", "URL ilegible"
    if not host:
        return None, "domain", "la URL no tiene host"

    esquema = (partes.scheme or "").lower()
    if esquema not in ("http", "https"):
        return None, "domain", (
            f"esquema {esquema or '?'}: solo http/https permiten saber a que "
            f"puerto se conecto de verdad; suponerlo seria publicar un "
            f"indicador sin verificar")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host, "domain", ""

    # Aqui el puerto por defecto SI es el que se contacto: es el del protocolo,
    # no una suposicion nuestra.
    puerto = partes.port or (443 if esquema == "https" else 80)
    return f"{host}:{puerto}", "ip:port", ""


# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    args = build_args().parse_args(argv)

    try:
        cfg = Config(args.config)
    except ConfigError as exc:
        print(f"[config] {exc}", file=sys.stderr)
        return EXIT_CONFIG

    logger = log.setup(cfg.log_file, "DEBUG" if args.verbose else cfg.log_level)

    if args.show_rejections:
        state = State(cfg.state_db)
        filas = state.recent_rejections(args.show_rejections)
        for row in filas:
            print(f"{row['ts']}  {row['platform']:<14} {row['gate']:<16} "
                  f"{row['key'][:24]:<24} {row['reason']}")
        if not filas:
            # Imprimir cero lineas parece que la herramienta esta rota. Y hay
            # una distincion que conviene explicar aqui: esta tabla recoge lo
            # que rechazaron los REPORTERS. Lo que descarta un collector (una
            # IP no reportable, por ejemplo) no llega nunca a esta tabla,
            # porque ocurre un paso antes; eso sale en el log.
            print("No hay ningun rechazo registrado.")
            print("Esta lista recoge lo que rechazaron los reporters. Lo que")
            print("descartan los collectors (IP propias, privadas o no globales)")
            print("ocurre antes y aparece en el log:")
            print(f"  sudo grep descartad {cfg.log_file}")
        state.close()
        return EXIT_OK

    if args.reset_breaker:
        state = State(cfg.state_db)
        salto = state.breaker(ABUSE_CH)
        if salto:
            print(f"El cortacircuitos salto el {salto['tripped_at']}:")
            print(f"  {salto['reason']}")
            state.clear_breaker(ABUSE_CH)
            print("Rearmado. Las tres plataformas de abuse.ch vuelven a estar activas.")
        else:
            print("El cortacircuitos no estaba saltado; no hay nada que rearmar.")
        state.close()
        return EXIT_OK

    if args.self_test:
        return self_test(cfg, logger)

    if args.live:
        logger.warning("=== MODO REAL: se enviara a las plataformas ===")
    else:
        logger.info("modo simulacion: no se enviara nada (usa --live para enviar)")

    publicar_ips_propias(cfg, logger)

    guard = ipguard.IPGuard(cfg.block_ips, cfg.block_cidrs)
    # Se exige que el CONFIG aporte algo, no solo la capa fija del codigo: la
    # IP de administracion vive unicamente aqui, porque no puede viajar en el
    # repositorio. Un config con [blocklist] vacia la dejaria sin proteger.
    if not cfg.block_ips and not cfg.block_cidrs:
        logger.critical("[blocklist] del config esta vacia: la IP de administracion "
                        "quedaria sin proteger. Aborto.")
        return EXIT_CONFIG

    state = State(cfg.state_db)
    http = HttpClient(state, timeout=cfg.http_timeout,
                      dry_run=not args.live, limiter=RateLimiter())

    vt = VirusTotal(cfg.section("virustotal"), http, state, guard, not args.live)
    mb = MalwareBazaar(cfg.section("malwarebazaar"), http, state, guard, not args.live)
    tf = ThreatFox(cfg.section("threatfox"), http, state, guard, not args.live)
    uh = URLhaus(cfg.section("urlhaus"), http, state, guard, not args.live)
    ab = AbuseIPDB(cfg.section("abuseipdb"), http, state, guard, not args.live)
    todos = [vt, mb, tf, uh, ab]

    salida = EXIT_OK
    try:
        # Lo primero, cerrar lo que quedo a medias en la ejecucion anterior.
        for r in todos:
            r.resolve_orphans()

        attackers, samples, urls = collect_all(cfg, guard, args.only, logger)
        logger.info("recogido: %d IP, %d muestras, %d URL",
                    len(attackers), len(samples), len(urls))

        ab.run(attackers)
        stage_upload(vt, state, samples, logger)
        stage_verdict(vt, mb, tf, uh, ab, state,
                      {s.sha256: s for s in samples}, logger)
        anotar_urls_sin_muestra(uh, urls, samples)

        # Si la cuota de VirusTotal se agoto, hay que decirlo con un codigo
        # propio. Toda la cadena depende de su veredicto: sin el no se sube
        # nada a MalwareBazaar ni se publica ningun IOC, y las muestras se
        # quedan en la cola esperando. Sin este aviso, la ejecucion terminaria
        # en 0 como si hubiera hecho su trabajo.
        try:
            RateLimiter.check_quota(state, vt.name)
        except QuotaExceeded as exc:
            esperando = len(state.due_samples(limit=1000))
            logger.warning(
                "%s. Quedan %d muestras en espera; no se publicara nada hasta "
                "que la cuota se renueve, y eso es lo correcto: sin veredicto "
                "de VirusTotal no se puede acreditar que algo sea malware.",
                exc, esperando)
            salida = EXIT_QUOTA

    except QuotaExceeded as exc:
        logger.warning("cuota agotada: %s", exc)
        salida = EXIT_QUOTA
    except KeyboardInterrupt:
        logger.warning("interrumpido por el usuario")
        salida = EXIT_PARTIAL
    except Exception:                            # noqa: BLE001
        logger.error("error inesperado:\n%s", traceback.format_exc())
        salida = EXIT_ERROR
    finally:
        logger.info("--- resumen ---")
        for r in todos:
            logger.info("  %s", r.summary())
        # Al final del todo: si algo fallo antes, mejor no haber tocado el
        # historial. La retencion es generosa a proposito --- lo que se borra
        # es ruido de auditoria, pero es el ruido que se lee cuando algo va
        # mal, y un mes da margen de sobra para enterarse.
        state.purge(cfg.retention_days)

        if not args.live and http.simulated_calls:
            logger.info("  %d peticiones se habrian enviado en modo real",
                        len(http.simulated_calls))
        rechazos = sum(r.rejected for r in todos)
        if rechazos:
            logger.info("  %d rechazos; consultalos con --show-rejections 30", rechazos)
        state.close()

    return salida


if __name__ == "__main__":
    sys.exit(main())
