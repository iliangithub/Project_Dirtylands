# SPDX-License-Identifier: GPL-2.0-or-later
"""
URLhaus. Cubre un hueco real: hasta ahora las URL desde las que se descargaba
el binario no se reportaban a ninguna plataforma especializada.

Ojo con la autenticacion, porque las dos fuentes oficiales se contradicen:

  - La pagina https://urlhaus.abuse.ch/api/ dice que la Auth-Key va en el
    cuerpo JSON, y nombra los campos en mayusculas (URL, Threat, Tags).
  - El script de referencia que esa misma pagina enlaza,
    github.com/abusech/URLhaus/blob/master/submit_url.py, la manda en la
    CABECERA HTTP y usa los campos en minusculas (url, threat, tags), con
    anonymous como la cadena "0".

Aqui se sigue el script, y en 2026-08-22 se descargo para comprobarlo: dice
exactamente lo que hacemos ---campos en minusculas, tags como LISTA, anonymous
como la cadena "0" y la Auth-Key en la cabecera junto a Content-Type---. La
prosa de la pagina es lo que esta desactualizado, no nuestro formato.

Lo que sigue SIN VERIFICAR es la RESPUESTA: esta plataforma no ha contestado
nunca a una peticion nuestra, asi que no se sabe si trae "query_status" ni con
que valores. Por eso response_ok mira solo el codigo HTTP.

Reglas de la plataforma y como se cumplen:

  "Malware URLs that are down and/or have already been cleaned should not be
  submitted". Comprobar si la URL sigue viva obligaria al honeypot a hacer una
  peticion saliente al servidor del atacante, y eso es exactamente lo que no
  se hace: revelaria la infraestructura y podria interpretarse como contacto
  con el C2. En su lugar se aplica un criterio que no requiere tocar nada:
  solo se envian URL de las que SI capturamos el binario, y vistas dentro de
  una ventana corta. Que el fichero este en disco es la prueba de que la URL
  servia el payload cuando la vimos.

  Nada de acortadores ni redirecciones, nada de adware, phishing ni exploit
  kits: solo la URL que sirvio el binario que tenemos.

  threat solo admite un valor: malware_download.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from common.model import PayloadURL
from common.http import Response
from .base import AbuseChReporter

API = "https://urlhaus.abuse.ch/api/"
# La de CONSULTA es otra maquina y otra ruta, no la misma con otro parametro.
# Solo se usa para resolver envios que quedaron sin respuesta. NO VERIFICADO:
# igual que la de envio, esta plataforma no ha recibido nunca una peticion
# nuestra, y por eso la resolucion de mas abajo es asimetrica.
API_CONSULTA = "https://urlhaus-api.abuse.ch/v1/url/"

THREAT = "malware_download"

# Acortadores y servicios de redireccion. La politica los excluye porque la
# URL final no es la que sirve el payload.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "s.id", "tiny.cc",
    "t.ly", "bit.do", "soo.gd", "clck.ru", "u.to", "v.gd",
}

_HOST_RE = re.compile(r"^[a-z][a-z0-9+.-]*://([^/:\s?#]+)", re.IGNORECASE)


class URLhaus(AbuseChReporter):
    name = "urlhaus"
    # Misma cuenta que las otras dos, y ademas su formato no se ha probado
    # nunca contra la API real.
    MAX_PER_RUN = 3

    def resolve_orphans(self) -> None:
        """Comprueba si la URL llego, y SOLO actua si dice que si.

        La asimetria es a proposito y es lo importante de este metodo.

        Un "ok" ---URLhaus conoce la URL--- basta para dar el envio por bueno:
        equivocarse ahi no publica nada, como mucho deja sin reintentar algo
        que ya esta.

        Un "no_results" NO se toma como "no llego". Nunca hemos usado esta API
        y no sabemos si una URL recien enviada aparece al momento o pasa antes
        por una revision; si no apareciera aun y lo tomaramos por perdido, la
        reenviariamos y estariamos publicando dos veces, que es justo lo que
        se intenta evitar. Se deja en vuelo y lo recoge la purga.

        En cuanto haya un envio real y se vea como se comporta, esto se puede
        volver simetrico como el de ThreatFox.
        """
        for row in self.state.orphans(self.name):
            url = row["key"]
            try:
                consulta = self.http.request(
                    self.name, "POST", API_CONSULTA,
                    headers={"Auth-Key": self.api_key},
                    data={"url": url}, allow_in_dry_run=True)
            except Exception as exc:                      # noqa: BLE001
                self.log.warning("huerfano %s: no se pudo consultar (%s)",
                                 url[:60], exc)
                continue

            estado = (consulta.json() or {}).get("query_status") if consulta.ok else None
            if estado == "ok":
                self.log.info("huerfano %s: URLhaus ya la tiene, se da por "
                              "enviada", url[:60])
                self.state.commit_send(self.name, url, "enviado",
                                       "confirmado con la consulta tras corte")
            else:
                self.log.warning(
                    "huerfano %s: la consulta dijo %r. NO se libera: no sabemos "
                    "si una URL recien enviada aparece al momento, y reenviarla "
                    "por si acaso es como se duplica", url[:60], estado)

    def response_ok(self, resp: Response) -> tuple[bool, str]:
        """Solo el codigo HTTP, a diferencia de sus dos hermanas.

        No se ha visto nunca una respuesta real de URLhaus, asi que no se sabe
        si trae `query_status` ni con que valores. Validarlo a ciegas rechazaria
        envios buenos. Hereda de AbuseChReporter igualmente, y eso es lo que
        importa: comparte el cortacircuitos de la cuenta.

        En cuanto se conozca la forma de la respuesta, esto se borra y se pasa
        a la validacion de la clase base. Y para que ese dia llegue, se anota
        la respuesta entera: es la unica forma de saber que contesta.
        """
        if resp.ok:
            self.log.info("%s: respuesta de %s: %s",
                          self.name, self.CUENTA, resp.text[:400])
            return True, ""
        return False, f"HTTP {resp.status}"

    def __init__(self, section, http, state, guard, dry_run=True):
        super().__init__(section, http, state, guard, dry_run)
        self.max_age_hours = section.getint("max_url_age_hours", 48)

    @staticmethod
    def host_of(url: str) -> str | None:
        m = _HOST_RE.match(url or "")
        return m.group(1).lower() if m else None

    def submit(self, item: PayloadURL, tags: list[str] | None = None) -> bool:
        if not self.is_enabled():
            return False

        url = (item.url or "").strip()
        clave = url

        # Solo con binario capturado: es la unica prueba de que servia el
        # payload, y evita tener que sondear la URL.
        if not self.gate(clave, "sin-muestra", bool(item.sha256),
                         "no capturamos el binario desde esta URL, asi que no "
                         "podemos acreditar que sirviera un payload"):
            return False

        edad = datetime.now(timezone.utc) - item.seen_at
        if not self.gate(clave, "antiguedad", edad <= timedelta(hours=self.max_age_hours),
                         f"vista hace {edad.total_seconds() / 3600:.0f} h; "
                         f"probablemente ya este caida y la politica pide no "
                         f"enviar URL muertas"):
            return False

        host = self.host_of(url)
        if not self.gate(clave, "url", bool(host), "no se pudo extraer el host"):
            return False
        if not self.gate(clave, "acortador", host not in SHORTENERS,
                         f"{host} es un acortador o servicio de redireccion"):
            return False
        if not self.gate(clave, "esquema", url.lower().startswith(("http://", "https://")),
                         "solo se envian URL http/https"):
            return False

        cuerpo = {
            "anonymous": "0",
            "submission": [{
                "url": url,
                "threat": THREAT,
                "tags": tags or ["honeypot", item.source],
            }],
        }

        resp = self.send(
            clave,
            lambda: self.http.request(
                self.name, "POST", API,
                headers={"Auth-Key": self.api_key,
                         "Content-Type": "application/json"},
                json_body=cuerpo, crea_recurso=True),
            texts=(url,), detail=item.sha256[:16] if item.sha256 else "")

        # La respuesta se registra entera para que el primer envio real revele
        # su forma. En cuanto se sepa, se borra el response_ok de arriba y pasa
        # a validarse como las otras dos.
        if resp is not None and not resp.simulated:
            self.log.info("respuesta de URLhaus (sin validar aun): HTTP %d %s",
                          resp.status, resp.text[:300])

        return bool(resp and resp.ok)
