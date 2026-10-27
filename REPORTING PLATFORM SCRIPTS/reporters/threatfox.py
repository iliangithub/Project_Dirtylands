# SPDX-License-Identifier: GPL-2.0-or-later
"""
ThreatFox. Infraestructura de distribucion y mando.

Su politica es de una sola linea y manda sobre todo lo demas:
"Please do only submit confirmed / vetted IOCs to ThreatFox."

Traducido a codigo: un IOC solo sale de aqui si la muestra asociada ya paso la
puerta de VirusTotal. Nada se publica por sospecha.

El campo `malware` debe ser un nombre de Malpedia. El codigo anterior enviaba
"unknown" cuando no sabia la familia, y NO esta verificado que ThreatFox lo
acepte: bien podria ser un rechazo silencioso, o peor, ruido en su base. Aqui
la decision es la contraria y es deliberada: sin familia identificada, no se
publica. Preferimos reportar de menos.

confidence_level se fija en 75. La documentacion da el rango 0-100 y el valor
por defecto, pero NO define que significa cada tramo: 75 es criterio propio y
consta como tal.

DESPUES DE PUBLICAR SE COMPRUEBA QUE HAY. `submit_ioc` responde
query_status=ok tanto si crea un indicador nuevo como si funde el nuestro con
uno que ThreatFox ya tenia, y su API no documenta la diferencia. El resumen
diario decia "1 publicadas" y el perfil no subia de 9 contribuciones; ninguna
de las dos cosas era mentira, pero juntas no habia forma de saber cual habia
pasado. Asi que se pregunta a `search_ioc` y se mira quien figura como
`reporter`: si somos nosotros, el indicador es nuevo; si es otro, lo nuestro
fue un refresco de una entrada ajena. Cuesta una consulta por publicacion
--- tres como mucho por pasada --- y a cambio el dato es un dato.
"""

from __future__ import annotations

from common.model import C2Indicator
from .base import AbuseChReporter

API = "https://threatfox-api.abuse.ch/api/v1/"

# Nombre de familia -> nombre de Malpedia. Solo entradas comprobadas; lo que
# no este en este mapa no se publica, en vez de enviar un nombre inventado.
MALPEDIA = {
    "mirai": "elf.mirai",
    "gafgyt": "elf.bashlite",
    "bashlite": "elf.bashlite",
    "tsunami": "elf.tsunami",
    "xorddos": "elf.xorddos",
    "dofloo": "elf.dofloo",
    "mozi": "elf.mozi",
    "hajime": "elf.hajime",
    "muhstik": "elf.muhstik",
    "kinsing": "elf.kinsing",
    "xmrig": "elf.xmrig",
}


class ThreatFox(AbuseChReporter):
    name = "threatfox"
    # Comparte cuenta con MalwareBazaar y URLhaus: un baneo aqui apaga las
    # tres. Mismo criterio conservador.
    MAX_PER_RUN = 3

    def __init__(self, section, http, state, guard, dry_run=True):
        super().__init__(section, http, state, guard, dry_run)
        self.confidence = section.getint("confidence_level", 75)
        # Nombre de usuario en ThreatFox. Sin el no se puede decidir si un
        # indicador es nuestro, asi que la verificacion se limita a dejar
        # constancia de que no se pudo comprobar. NO se adivina: un marcador
        # sin sustituir (<ASI>) cuenta como no puesto.
        usuario = (section.get("usuario", "") or "").strip()
        if usuario.startswith("<") or usuario.lower() in ("", "tu-usuario"):
            usuario = ""
        self.usuario = usuario

    def _headers(self) -> dict:
        return {"Auth-Key": self.api_key, "Accept": "application/json"}

    def submit(self, ioc: C2Indicator, vetted: bool) -> bool:
        if not self.is_enabled():
            return False

        clave = f"{ioc.ioc_type}:{ioc.ioc}"

        if not self.gate(clave, "vetado", vetted,
                         "la muestra asociada no ha pasado la puerta de "
                         "VirusTotal: la politica exige IOC confirmados"):
            return False

        malpedia = MALPEDIA.get((ioc.malware or "").lower())
        if not self.gate(clave, "familia", bool(malpedia),
                         f"familia {ioc.malware!r} sin equivalente confirmado en "
                         "Malpedia: no se envia un nombre sin verificar"):
            return False

        cuerpo = {
            "query": "submit_ioc",
            "threat_type": ioc.threat_type,
            "ioc_type": ioc.ioc_type,
            "malware": malpedia,
            "confidence_level": self.confidence,
            "iocs": [ioc.ioc],          # la API espera un array
            "anonymous": 0,
            "tags": ["honeypot", ioc.source],
        }
        if ioc.reference:
            cuerpo["reference"] = ioc.reference

        # Si el IOC es una IP, la barrera la valida como tal; si es un dominio
        # o una URL, la barrera de texto busca IP propias dentro.
        ip_context = ioc.ioc.split(":")[0] if ioc.ioc_type == "ip:port" else None

        resp = self.send(
            clave,
            lambda: self.http.request(self.name, "POST", API,
                                      headers=self._headers(), json_body=cuerpo,
                                      crea_recurso=True),
            ip_context=ip_context, texts=(ioc.ioc, ioc.reference or ""),
            detail=malpedia)

        if resp and resp.ok and not resp.simulated:
            self._verificar(clave, ioc.ioc, malpedia)
        return bool(resp and resp.ok)

    # ------------------------------------------------------------------
    def _verificar(self, clave: str, indicador: str, malpedia: str) -> None:
        """Pregunta a ThreatFox que quedo publicado y lo anota en el envio.

        No cambia nada de lo que ya se hizo ni puede deshacerlo: si la
        consulta falla, el envio sigue contando como publicado ---que lo
        esta--- y el detalle dice que no se pudo comprobar. Un fallo aqui no
        debe tumbar la pasada: lo que se pierde es una anotacion.
        """
        marca = "sin-verificar"
        try:
            if not self.usuario:
                marca = "sin-verificar (falta usuario en el config)"
            else:
                consulta = self.http.request(
                    self.name, "POST", API, headers=self._headers(),
                    json_body={"query": "search_ioc", "search_term": indicador},
                    allow_in_dry_run=True)
                marca = self._leer_busqueda(consulta, indicador)
        except Exception as exc:                          # noqa: BLE001
            self.log.warning("%s: no se pudo verificar %s: %s",
                             self.name, indicador[:40], exc)
            marca = "sin-verificar (la consulta fallo)"

        self.state.set_detail(self.name, clave, f"{malpedia} | {marca}")

    # ------------------------------------------------------------------
    def resolve_orphans(self) -> None:
        """Aqui SI se puede saber si el envio llego: search_ioc lo dice.

        La regla, y es la que evita hacer dano: solo se decide cuando la
        respuesta es inequivoca.

          esta        -> llego, se da por enviado
          no_result   -> no llego, se libera para reintentarlo
          cualquier   -> se deja como esta y se avisa. Abortarlo por una
          otra cosa      respuesta que no se entiende reenviaria algo que si
                         pudo entrar, que es justo el duplicado que se
                         intenta evitar.
        """
        for row in self.state.orphans(self.name):
            key = row["key"]
            indicador = self._ioc_de_clave(key)
            if not indicador:
                continue
            try:
                consulta = self.http.request(
                    self.name, "POST", API, headers=self._headers(),
                    json_body={"query": "search_ioc", "search_term": indicador},
                    allow_in_dry_run=True)
            except Exception as exc:                      # noqa: BLE001
                self.log.warning("huerfano %s: no se pudo consultar (%s)",
                                 indicador[:40], exc)
                continue

            estado = (consulta.json() or {}).get("query_status") if consulta.ok else None
            if estado == "ok":
                self.log.info("huerfano %s: si llego a ThreatFox, se da por "
                              "enviado", indicador[:40])
                self.state.commit_send(self.name, key, "enviado",
                                       "confirmado con search_ioc tras corte")
            elif estado == "no_result":
                self.log.info("huerfano %s: no llego, se libera para reintento",
                              indicador[:40])
                self.state.abort_send(self.name, key)
            else:
                self.log.warning(
                    "huerfano %s: search_ioc contesto %r; se deja en vuelo, "
                    "que reenviar a ciegas es como se duplica",
                    indicador[:40], estado)

    @staticmethod
    def _ioc_de_clave(key: str) -> str:
        """El indicador que hay dentro de la clave "<tipo>:<ioc>".

        Se recorta por el TIPO y no por el primer ":", porque el propio tipo
        lleva uno dentro ("ip:port") y el indicador tambien
        ("ip:port:1.2.3.4:80"). Partir por el primero devolveria "port:...".
        """
        for tipo in ("ip:port", "domain", "url"):
            if key.startswith(tipo + ":"):
                return key[len(tipo) + 1:]
        return ""

    def _leer_busqueda(self, resp, indicador: str) -> str:
        if not resp.ok:
            return "sin-verificar (HTTP %d)" % resp.status
        cuerpo = resp.json() or {}
        estado = cuerpo.get("query_status")
        if estado == "no_result":
            # Digno de mirarse: el submit dijo que si y no hay nada. Se avisa
            # pero no se marca como rechazo, porque el POST fue aceptado.
            self.log.warning(
                "%s: %s se publico pero search_ioc no lo encuentra",
                self.name, indicador[:40])
            return "publicado pero no aparece en la busqueda"
        if estado != "ok":
            return "sin-verificar (query_status=%s)" % estado

        datos = cuerpo.get("data") or []
        if not isinstance(datos, list) or not datos:
            return "sin-verificar (respuesta sin data)"

        # La busqueda puede devolver varios: se queda con el que coincide.
        entrada = next((d for d in datos
                        if isinstance(d, dict) and d.get("ioc") == indicador),
                       datos[0] if isinstance(datos[0], dict) else {})
        quien = (entrada.get("reporter") or "").strip()
        ident = entrada.get("id") or "?"
        if not quien:
            return "sin-verificar (la entrada no dice reporter), id=%s" % ident
        if quien.lower() == self.usuario.lower():
            return "nuevo, id=%s" % ident
        return "refresco de %s, id=%s" % (quien, ident)
