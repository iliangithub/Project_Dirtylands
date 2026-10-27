# SPDX-License-Identifier: GPL-2.0-or-later
"""
IPGuard: el control mas importante del sistema.

Reportar por error una IP propia significa denunciarnos a nosotros mismos ante
AbuseIPDB, y quemar la reputacion de la infraestructura que estamos intentando
proteger. Por eso hay tres capas independientes y una barrera final:

  Capa 1  lista fija en el codigo, sobrevive a un config mal editado
  Capa 2  lista del config.ini
  Capa 3  ip.is_global mas multicast y sin especificar. Descarta privadas,
          loopback, link-local, reservadas y CGNAT sin enumerarlas. Las
          MULTICAST hay que ponerlas aparte: is_global las da por buenas

  assert_safe()  barrera fail-closed, obligatoria justo antes de CADA POST

La barrera lanza excepcion en vez de devolver False a proposito: un valor de
retorno se puede ignorar por descuido; una excepcion no.

Sobre el reconocimiento de IP en texto libre: se busca de forma PERMISIVA y se
valida despues con ipaddress. Un patron estricto es justo el que deja escapar
la forma que no habias previsto, y aqui una fuga silenciosa es peor que una
coincidencia de mas. Al final de este fichero hay un self_test() que comprueba
que la barrera salta de verdad; se ejecuta desde --self-test, porque una
barrera rota no se distingue de una barrera que nunca tuvo que actuar.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from . import log

_log = log.get("ipguard")

# Capa 1. Va hardcodeada ADEMAS del config porque es un control de seguridad,
# no un ajuste: si el config se corrompe o alguien lo edita mal, esto sigue.
# Se rellena en el despliegue con las IP reales del proyecto.
HARDCODED_NEVER_REPORT: set[str] = {
    # MARCADORES: sustituir por las dos IP publicas reales en el
    # despliegue. Las de aqui son del rango de documentacion RFC 5737 y
    # no protegen nada hasta que se cambien.
    "198.51.100.146",        # VPS, IP publica 1
    "198.51.100.161",        # VPS, IP publica 2
    # La IP de administracion por VPN NO se escribe aqui a proposito: este
    # fichero viaja en el repositorio. Va en [blocklist] del config.ini, que
    # se queda en la maquina.
}


# IPv4, e IPv6 incluyendo las formas comprimidas con "::". Los grupos vacios
# estan permitidos en la parte IPv6 precisamente para que "2001:db8::1" case;
# lo que salga de aqui puede ser basura, y por eso siempre se valida despues.
_IP_TOKENS = re.compile(
    r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])"
    r"|(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"
)


def _parse(token: str):
    """Devuelve la IP o None. Un token que no es IP (una hora, una MAC) no lo es."""
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


# El motivo se declara aqui porque los collectors lo comparan para detectar el
# enmascaramiento de IP. Como texto suelto en dos ficheros, bastaria reescribir
# la frase para que ese aviso dejara de saltar sin que nadie se enterara.
MOTIVO_NO_GLOBAL = "direccion no global (privada, reservada o loopback)"


class UnsafeTarget(Exception):
    """Se intento enviar algo que no debe salir. Aborta la operacion."""


class IPGuard:
    def __init__(self, extra_ips: Iterable[str] = (),
                 extra_cidrs: Iterable[str] = ()) -> None:
        self.blocked: set = set()
        self.networks: list = []

        for raw in list(HARDCODED_NEVER_REPORT) + list(extra_ips):
            raw = (raw or "").strip()
            if not raw:
                continue
            ip = _parse(raw)
            if ip is None:
                _log.warning("lista de bloqueo: %r no es una IP valida", raw)
            else:
                self.blocked.add(ip)

        for raw in extra_cidrs:
            raw = (raw or "").strip()
            if not raw:
                continue
            try:
                self.networks.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                _log.warning("lista de bloqueo: %r no es una red valida", raw)

    # ------------------------------------------------------------------
    def check(self, ip_str: str) -> tuple[bool, str]:
        """(reportable, motivo). Cualquier duda se resuelve como NO reportable."""
        ip = _parse((ip_str or "").strip())
        if ip is None:
            return False, "no es una IP valida"
        if ip in self.blocked:
            return False, "en la lista de bloqueo (infraestructura propia)"
        for net in self.networks:
            if ip in net:
                return False, f"dentro de la red bloqueada {net}"
        # OJO: is_global NO basta. Devuelve True para las MULTICAST, tanto
        # IPv4 (224.0.0.0/4) como IPv6 (ff00::/8), y para 0.0.0.0 en algunas
        # versiones. Este fichero llego a afirmar en su cabecera que esa capa
        # descartaba multicast, y era falso.
        #
        # Importa desde que se denuncian tambien los servidores que sirven el
        # binario: ese host sale de una URL que TECLEA EL ATACANTE, asi que un
        # `wget http://224.0.0.1/x` bastaria para que publicaramos una denuncia
        # absurda contra una direccion que no pertenece a nadie. Encontrado
        # auditando ese camino el 2026-08-23.
        if ip.is_multicast or ip.is_unspecified or not ip.is_global:
            return False, MOTIVO_NO_GLOBAL
        return True, "ok"

    def is_reportable(self, ip_str: str) -> bool:
        return self.check(ip_str)[0]

    def assert_safe(self, ip_str: str, context: str) -> None:
        """Barrera fail-closed. Va inmediatamente antes de cada POST."""
        okay, reason = self.check(ip_str)
        if not okay:
            _log.critical("BARRERA: %s bloqueada en %s (%s)", ip_str, context, reason)
            raise UnsafeTarget(f"{ip_str} no es reportable en {context}: {reason}")

    def assert_text_safe(self, text: str, context: str) -> None:
        """Equivalente para contenido libre (comentarios, tags, referencias).

        Existe porque el requisito de "barrera antes de cada POST" no se cumplia
        en los envios de fichero: alli no viaja una IP suelta, pero si metadatos
        donde puede colarse una.

        Usa el MISMO criterio que check() y que redact(), o sea que tambien
        para una direccion no global. Antes miraba solo la lista de bloqueo y
        las redes, y eso dejaba una incoherencia con dientes: redact() tachaba
        un 172.17.0.2 de un log, pero esta barrera lo dejaba salir en un
        comentario publico. Son la topologia interna de los contenedores, y
        publicarla no aporta nada a nadie salvo a quien nos mire.

        Ademas cubre el caso de una URL de descarga hacia una IP privada, algo
        normal en malware que se propaga por la LAN: eso no es infraestructura
        publicable y no tiene por que llegar a URLhaus.

        Un token que no llega a ser una IP se ignora: una hora como 12:34:56
        casa con el patron pero no es una direccion, y bloquear por eso
        convertiria la barrera en un estorbo hasta que alguien la quitara.
        """
        for token in _IP_TOKENS.findall(text or ""):
            ip = _parse(token)
            if ip is None:
                continue
            okay, motivo = self.check(str(ip))
            if not okay:
                _log.critical("BARRERA: %s aparece en el texto de %s (%s)",
                              token, context, motivo)
                raise UnsafeTarget(
                    f"direccion no publicable en el texto de {context}: {motivo}")

    def redact(self, text: str) -> str:
        """Sustituye por [redacted] toda IP no reportable de un texto.

        Un token que no llega a ser una IP se deja intacto: si no, una hora
        como 12:34:56 acabaria redactada y el log quedaria ilegible.
        """
        def _sub(match):
            token = match.group(0)
            if _parse(token) is None:
                return token
            return token if self.is_reportable(token) else "[redacted]"
        return _IP_TOKENS.sub(_sub, text or "")


# --------------------------------------------------------------------------
def self_test() -> list[str]:
    """Comprueba que la barrera actua. Devuelve la lista de fallos."""
    fails: list[str] = []

    # La capa fija tiene que estar poblada. Si alguien la vacia al reinstalar,
    # la unica proteccion que queda es el config, y el config se puede editar
    # mal. Esto lo detecta antes de que importe.
    if not HARDCODED_NEVER_REPORT:
        fails.append("HARDCODED_NEVER_REPORT esta vacio: las IP publicas del "
                     "honeypot deben ir tambien en el codigo, no solo en el config")
    vacio = IPGuard()
    for propia in HARDCODED_NEVER_REPORT:
        if vacio.is_reportable(propia):
            fails.append(f"la capa fija no bloquea {propia}")
    g = IPGuard(extra_ips=["203.0.113.7", "2001:db8:dead::1"],
                extra_cidrs=["198.51.100.0/24"])

    debe_bloquear = ["203.0.113.7", "2001:db8:dead::1", "198.51.100.42",
                     "10.0.0.1", "127.0.0.1", "192.168.1.1", "::1",
                     "100.64.0.1", "no-es-una-ip", ""]
    for ip in debe_bloquear:
        if g.is_reportable(ip):
            fails.append(f"deberia bloquear {ip!r} y no lo hace")

    debe_permitir = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]
    for ip in debe_permitir:
        if not g.is_reportable(ip):
            fails.append(f"deberia permitir {ip!r}: {g.check(ip)[1]}")

    # La barrera de texto tiene que saltar en las tres formas, y ademas con
    # las direcciones no globales: la topologia interna tampoco se publica.
    for texto in ["descargado desde 203.0.113.7/bin.sh",
                  "callback a 2001:db8:dead::1",
                  "escaneo desde 198.51.100.42:4444",
                  "http://172.17.0.2/x.sh",
                  "propagacion a 192.168.1.50"]:
        try:
            g.assert_text_safe(texto, "self-test")
            fails.append(f"la barrera de texto NO salto con: {texto!r}")
        except UnsafeTarget:
            pass

    # Y NO tiene que saltar con trafico legitimo
    try:
        g.assert_text_safe("descargado desde 8.8.8.8 a las 12:34:56", "self-test")
    except UnsafeTarget:
        fails.append("la barrera de texto salta con una IP ajena legitima")

    salida = g.redact("atacante 8.8.8.8 contra 203.0.113.7 y 2001:db8:dead::1 a las 12:34:56")
    if "203.0.113.7" in salida or "2001:db8:dead::1" in salida:
        fails.append(f"redact() no elimino la infraestructura propia: {salida}")
    if "8.8.8.8" not in salida or "12:34:56" not in salida:
        fails.append(f"redact() borro lo que no debia: {salida}")

    return fails
