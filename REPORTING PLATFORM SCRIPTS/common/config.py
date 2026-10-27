# SPDX-License-Identifier: GPL-2.0-or-later
"""
Carga y validacion del config.ini compartido.

El fichero contiene claves de API, asi que el arranque se aborta si es legible
por alguien que no sea su propietario. No es una manía: un config 644 con las
claves dentro es una fuga silenciosa que nadie nota hasta que es tarde.

Todas las claves cargadas se registran como secretas en el modulo de log, de
modo que no puedan aparecer en una traza ni en el cuerpo de un error.
"""

from __future__ import annotations

import configparser
import ipaddress
import os
import stat
from pathlib import Path

from . import log

_log = log.get("config")

DEFAULT_CONFIG = "/opt/dirtyland/platform-reporter/config.ini"


class ConfigError(Exception):
    """Problema de configuracion. Codigo de salida propio: no es fallo de red."""


class Config:
    def __init__(self, path: Path | str, require_secure_perms: bool = True) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise ConfigError(f"no existe el fichero de configuracion: {self.path}")

        mode = self.path.stat().st_mode
        if require_secure_perms and (mode & (stat.S_IRWXG | stat.S_IRWXO)):
            raise ConfigError(
                f"permisos inseguros en {self.path} ({oct(mode & 0o777)}). "
                f"Contiene claves de API: ejecuta  chmod 600 {self.path}")

        cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
        cp.read(self.path, encoding="utf-8")
        self.cp = cp

        for section in cp.sections():
            for key in ("api_key", "auth_key", "token"):
                if cp.has_option(section, key):
                    log.register_secret(cp.get(section, key))
        # Y las de [api_keys], que no se llaman "api_key" sino por plataforma.
        if cp.has_section("api_keys"):
            for _, valor in cp.items("api_keys"):
                log.register_secret(valor)

        self.claves_heredadas = self._resolver_claves()

        # Handle publico con el que se firma lo que se publica. Vive en
        # [general] y se reparte a las plataformas igual que las claves.
        self.attribution_tag = self.section("general").get(
            "attribution_tag", "").strip()
        for plataforma in self.ORIGEN_CLAVE:
            seccion = self.section(plataforma)
            if not seccion.get("attribution_tag", "").strip():
                seccion["attribution_tag"] = self.attribution_tag

        g = self.section("general")
        self.state_db = Path(g.get("state_db", "/var/lib/dirtyland-reporter/state.sqlite3"))
        self.log_file = Path(g.get("log_file", "/var/log/dirtyland-reporter/reporter.log"))
        self.log_level = g.get("log_level", "INFO")
        self.http_timeout = g.getint("http_timeout", 30)
        self.lookback_hours = g.getint("lookback_hours", 24)
        self.retention_days = g.getint("retention_days", 30)

        # En que huso escribe Cowrie sus marcas de tiempo. Ver la nota del
        # config.ini.example: firma con "Z" pero escribe hora local.
        self.cowrie_log_tz = self.section("paths").get("cowrie_log_tz", "UTC").strip()

        # Traduccion del puerto interno de Cowrie al que marco el atacante.
        # Formato "2222:22, 2223:23". Vacio = el de por defecto del collector,
        # que es justo ese: asi funciona sin tocar nada y sigue siendo
        # cambiable si algun dia el compose publica otros puertos.
        self.cowrie_puertos_publicos = _mapa_puertos(
            self.section("paths").get("cowrie_puertos_publicos", ""))

        b = self.section("blocklist")
        self.block_ips = _split(b.get("ips", ""))
        self.block_cidrs = _split(b.get("cidrs", ""))

    # ------------------------------------------------------------------
    # Plataformas que cuelgan de la MISMA cuenta de abuse.ch. Comparten clave
    # y comparten sancion: si una cae, caen las tres.
    ABUSECH = ("malwarebazaar", "threatfox", "urlhaus")

    # De donde saca su clave cada plataforma dentro de [api_keys]. Solo hay
    # tres cuentas: VirusTotal, abuse.ch (que cubre las tres suyas) y AbuseIPDB.
    ORIGEN_CLAVE = {
        "virustotal": "virustotal",
        "abuseipdb": "abuseipdb",
        "malwarebazaar": "abusech",
        "threatfox": "abusech",
        "urlhaus": "abusech",
    }

    def _resolver_claves(self) -> dict[str, str]:
        """Reparte las claves de [api_keys] entre las plataformas.

        Todo lo que hay que rellenar vive en una sola seccion y al principio
        del fichero, en vez de repartido por cinco sitios: quien instala no
        tiene que ir buscando donde va cada cosa, y quien audita ve de un
        vistazo todos los secretos que contiene.

        Una plataforma puede llevar su propia api_key en su seccion y entonces
        manda la suya; es la valvula para el dia que una necesite una cuenta
        distinta, no el camino normal.

        Devuelve, por plataforma, de que entrada saco la clave, para que
        validate() se queje una sola vez y senalando donde hay que escribir.
        """
        fuente = self.section("api_keys")
        heredadas: dict[str, str] = {}

        for plataforma, entrada in self.ORIGEN_CLAVE.items():
            seccion = self.section(plataforma)
            if seccion.get("api_key", "").strip():
                continue                       # la suya manda
            compartida = fuente.get(entrada, "").strip()
            if compartida:
                seccion["api_key"] = compartida
                heredadas[plataforma] = entrada
        return heredadas

    def section(self, name: str) -> configparser.SectionProxy:
        if not self.cp.has_section(name):
            self.cp.add_section(name)
        return self.cp[name]

    def enabled(self, name: str) -> bool:
        return self.cp.has_section(name) and self.cp[name].getboolean("enabled", False)

    def api_key(self, name: str) -> str:
        return self.section(name).get("api_key", "").strip()

    def validate(self) -> list[str]:
        """Comprueba coherencia y devuelve la lista de problemas encontrados.

        No lanza excepcion: la usa --self-test para enumerarlos todos de una
        vez en lugar de ir descubriendolos de uno en uno.
        """
        problems: list[str] = []

        if not self.block_ips and not self.block_cidrs:
            problems.append(
                "[blocklist] esta vacia: deberia contener las IP publicas del "
                "honeypot y la IP de administracion")

        # Marcadores <ASI> sin sustituir. Es el fallo mas probable al instalar
        # de cero, y antes pasaba desapercibido: la entrada no valida solo
        # dejaba un aviso en el log y el self-test decia que todo estaba bien,
        # con la IP de administracion sin proteger de verdad.
        for raw in self.block_ips:
            if raw.startswith("<") or raw.endswith(">"):
                problems.append(
                    f"[blocklist] {raw} es un marcador sin sustituir: pon ahi la "
                    "IP real o quitalo, porque tal cual NO protege nada")
            else:
                try:
                    ipaddress.ip_address(raw)
                except ValueError:
                    problems.append(f"[blocklist] {raw!r} no es una IP valida")
        for raw in self.block_cidrs:
            try:
                ipaddress.ip_network(raw, strict=False)
            except ValueError:
                problems.append(f"[blocklist] {raw!r} no es una red valida")

        # Las tres de abuse.ch comparten clave, asi que un unico problema no
        # debe aparecer tres veces ni senalar a la seccion equivocada: si la
        # heredaron, el sitio que hay que arreglar es [abusech].
        avisados: set[str] = set()
        for platform in ("virustotal", *self.ABUSECH, "abuseipdb"):
            if not self.enabled(platform):
                continue

            clave = self.api_key(platform)
            # Si la clave viene de su propia seccion, el problema es de esa
            # seccion; si viene (o deberia venir) de [api_keys], hay que
            # senalar alli, que es donde se escribe.
            propia = self.section(platform).get("api_key", "").strip()
            if propia and platform not in self.claves_heredadas:
                donde = f"[{platform}] api_key"
            else:
                donde = f"[api_keys] {self.ORIGEN_CLAVE[platform]}"
            if donde in avisados:
                continue

            if not clave:
                problems.append(f"{donde}: falta la clave y la plataforma esta activada")
                avisados.add(donde)
            elif clave.startswith("<") or clave.endswith(">"):
                problems.append(f"{donde}: sigue siendo el marcador del ejemplo")
                avisados.add(donde)

        if self.cowrie_log_tz.upper() != "UTC":
            try:
                from zoneinfo import ZoneInfo
                ZoneInfo(self.cowrie_log_tz)
            except Exception as exc:                  # noqa: BLE001
                problems.append(
                    f"[paths] cowrie_log_tz={self.cowrie_log_tz!r} no es un huso "
                    f"valido ({exc}); las marcas de Cowrie se leerian como UTC")

        if self.attribution_tag.startswith("<") or self.attribution_tag.endswith(">"):
            problems.append(
                "[general] attribution_tag sigue siendo el marcador del ejemplo: "
                "pon tu handle o dejalo vacio, porque tal cual se publicaria "
                "literalmente en los comentarios")

        # Las listas de exclusion de MalwareBazaar viven en el config y no en el
        # codigo, porque abuse.ch no publica catalogo y avisa por correo. Esa
        # decision tiene una contrapartida: un borrado accidental las
        # desactiva sin que nada falle. Vaciarlas puede ser deliberado, asi que
        # no se aborta, pero no puede pasar en silencio.
        if self.enabled("malwarebazaar"):
            for clave in ("familias_vetadas", "infectores_de_fichero"):
                if not self.section("malwarebazaar").get(clave, "").strip():
                    problems.append(
                        f"[malwarebazaar] {clave} esta vacia: no se filtrara "
                        "nada por ese veto. Si es a proposito, ignora este "
                        "aviso; si no, mira el config.ini.example")

        if self.enabled("malwarebazaar") and not self.enabled("virustotal"):
            problems.append(
                "[malwarebazaar] enabled sin [virustotal]: la puerta de maliciosidad "
                "depende del veredicto de VirusTotal, no se puede publicar sin el")

        gate = self.section("gate")
        if gate.getint("min_malicious", 12) < 5:
            problems.append(
                f"[gate] min_malicious={gate.getint('min_malicious', 12)} es peligrosamente "
                "bajo: se publicarian muestras sin consenso")

        for name, path in (("state_db", self.state_db), ("log_file", self.log_file)):
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                if not os.access(path.parent, os.W_OK):
                    problems.append(f"[general] {name}: sin permiso de escritura en {path.parent}")
            except OSError as exc:
                problems.append(f"[general] {name}: no se pudo preparar {path.parent}: {exc}")

        return problems


def _mapa_puertos(raw: str) -> dict[int, int] | None:
    """Convierte "2222:22, 2223:23" en {2222: 22, 2223: 23}.

    Devuelve None si no hay nada escrito, para que el collector use su tabla
    por defecto. Un par mal escrito se ignora en vez de tumbar la pasada: no
    reportar por un error de sintaxis en una clave opcional seria cambiar un
    problema pequeno por uno grande.
    """
    if not raw.strip():
        return None
    mapa: dict[int, int] = {}
    for par in raw.replace(";", ",").split(","):
        if ":" not in par:
            continue
        interno, publico = par.split(":", 1)
        try:
            mapa[int(interno.strip())] = int(publico.strip())
        except ValueError:
            continue
    return mapa or None


def _split(raw: str) -> list[str]:
    import re
    return [x.strip() for x in re.split(r"[,\s]+", raw or "") if x.strip()]
