# SPDX-License-Identifier: GPL-2.0-or-later
"""
Transporte HTTP unico para todos los reporters.

El modo de simulacion se aplica AQUI, en el transporte, y no en cada reporter.
Es la diferencia entre "ningun reporter envia porque todos se acuerdan de
comprobar la bandera" y "ningun reporter puede enviar". Con la comprobacion
repartida, basta un olvido en un camino poco frecuente para que se escape una
peticion real; con la comprobacion en el unico punto que abre el socket, no hay
camino que se escape.

Politica de reintentos, deliberadamente estrecha:

  429  se respeta Retry-After si viene; si no, retroceso exponencial
  5xx  retroceso exponencial: el fallo es del servidor
  red  retroceso exponencial: timeout o conexion cortada
  4xx  NO se reintenta. Un 400 o un 403 no mejoran repitiendo, y reintentar
       peticiones rechazadas es justo el patron que las plataformas leen como
       abuso.

Y UNA EXCEPCION QUE MANDA SOBRE TODO LO ANTERIOR: crea_recurso=True.

Reintentar es seguro cuando la peticion solo LEE. Cuando CREA algo ---una
denuncia en AbuseIPDB, una muestra en MalwareBazaar, un IOC en ThreatFox---
deja de serlo, porque un timeout o un 500 no significan "no llego": significan
"no se sabe". El servidor puede haberla procesado y haberse caido al
contestar. Repetirla entonces publica lo mismo dos veces.

No es teorico. El 2026-08-28 salio una denuncia duplicada a AbuseIPDB, que
contesto "You can only report the same IP once in 15 minutes": la primera
habia entrado, y el reintento la volvio a mandar. Y publicar por duplicado es
justo lo que estas plataformas penalizan.

Asi que con crea_recurso=True:

  429  se sigue reintentando. Un 429 se emite ANTES de procesar, asi que no
       se ha creado nada y repetir es seguro.
  5xx  NO se reintenta. Ambiguo.
  red  NO se reintenta. Ambiguo del todo.

En los dos casos ambiguos la respuesta vuelve marcada con incierto=True, y
send() sabe lo que eso significa: NO se retira la intencion de la tabla
inflight, para que resolve_orphans pueda preguntarle luego a la plataforma si
aquello llego. Preguntar cuesta una consulta; reenviar por si acaso cuesta la
cuenta.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

from . import log
from .ratelimit import RateLimiter

_log = log.get("http")

try:
    import requests
except ImportError as exc:      # pragma: no cover
    raise SystemExit(
        "falta el modulo 'requests'. Instalalo con:  sudo apt install -y python3-requests"
    ) from exc

USER_AGENT = "dirtyland-reporter/2.0 (honeypot; contacto en el perfil de la plataforma)"

MAX_ATTEMPTS = 4
BACKOFF_BASE = 2.0
MAX_BACKOFF = 120.0


@dataclass
class Response:
    status: int
    text: str
    json_body: Any = None
    headers: dict = field(default_factory=dict)
    simulated: bool = False
    # "La peticion creaba algo y no se sabe si llego." Ni exito ni rechazo:
    # una tercera cosa, y tratarla como cualquiera de las dos hace dano ---
    # darla por buena pierde el envio, darla por fallida lo duplica.
    incierto: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return self.json_body


class HttpClient:
    def __init__(self, state, timeout: int = 30, dry_run: bool = True,
                 limiter: RateLimiter | None = None) -> None:
        # `state` es obligatorio y va el primero a proposito. Si fuera
        # opcional, olvidarlo dejaria de contar las llamadas y la proteccion de
        # cuota no saltaria nunca, sin un solo error que lo delatara: el mismo
        # tipo de fallo silencioso que este proyecto ya ha pagado varias veces.
        if state is None:
            raise ValueError("HttpClient necesita el estado para contar las "
                             "llamadas y respetar la cuota diaria")
        self.timeout = timeout
        self.dry_run = dry_run
        self.limiter = limiter or RateLimiter()
        # El estado se pasa para contar las llamadas AQUI, en el unico sitio
        # que abre un socket. Contarlas en cada reporter significaria que la
        # que se olvide gasta cuota sin que nadie la sume, y el limite de
        # VirusTotal incluye las consultas, que son la mayoria.
        self.state = state
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        # Contador de lo que se HABRIA enviado. Es lo que revisa el usuario
        # antes de autorizar una ejecucion real.
        self.simulated_calls: list[dict] = []

    # ------------------------------------------------------------------
    def request(self, platform: str, method: str, url: str, *,
                headers: dict | None = None, data: Any = None,
                json_body: Any = None, files: Any = None,
                allow_in_dry_run: bool = False,
                crea_recurso: bool = False) -> Response:
        """Lanza una peticion respetando ritmo, reintentos y simulacion.

        `allow_in_dry_run` es solo para consultas de lectura que no publican
        nada (por ejemplo, preguntar a VirusTotal si un hash ya existe). Sin
        ella, una simulacion no podria comprobar las puertas de decision, que
        es precisamente lo que se quiere validar.

        `crea_recurso` marca las peticiones que PUBLICAN. Ver la cabecera del
        fichero: con ella, un timeout o un 5xx no se reintentan, porque no
        dicen que la peticion no llegara, solo que no se sabe.
        """
        self.limiter.wait(platform)

        if self.dry_run and not allow_in_dry_run:
            return self._simulate(platform, method, url, headers, data, json_body, files)

        self.state.note_call(platform)

        last: Response | None = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                r = self.session.request(
                    method.upper(), url, headers=headers, data=data,
                    json=json_body, files=files, timeout=self.timeout)
            except requests.RequestException as exc:
                _log.warning("%s: fallo de red (%d/%d): %s",
                             platform, attempt, MAX_ATTEMPTS, exc)
                if crea_recurso:
                    # WARNING y no ERROR: es una condicion ESPERADA y
                    # controlada. A volumen alto ---AbuseIPDB publica miles al
                    # dia--- la red se corta cada tanto; el envio queda en
                    # inflight, no se reintenta (podria duplicar) y la clave con
                    # fecha evita repetirlo hoy. Marcarlo ERROR enterraba los
                    # fallos de verdad (excepciones, colectores rotos) entre
                    # decenas de estos al dia.
                    _log.warning(
                        "%s: la peticion publicaba algo y se corto la red; NO se "
                        "reintenta porque pudo llegar. Queda en inflight.",
                        platform)
                    return Response(status=0, text=f"error de red: {exc}",
                                    incierto=True)
                if attempt == MAX_ATTEMPTS:
                    return Response(status=0, text=f"error de red: {exc}")
                self._sleep(attempt)
                continue

            resp = Response(status=r.status_code, text=r.text[:20000],
                            headers=dict(r.headers))
            try:
                resp.json_body = r.json()
            except ValueError:
                resp.json_body = None

            if resp.status == 429:
                delay = self._retry_after(r.headers) or self._backoff(attempt)
                _log.warning("%s: 429, esperando %.0fs (%d/%d)",
                             platform, delay, attempt, MAX_ATTEMPTS)
                if attempt == MAX_ATTEMPTS:
                    return resp
                time.sleep(min(delay, MAX_BACKOFF))
                continue

            if resp.status >= 500:
                _log.warning("%s: HTTP %d del servidor (%d/%d)",
                             platform, resp.status, attempt, MAX_ATTEMPTS)
                if crea_recurso:
                    # WARNING, por lo mismo que el corte de red de arriba: un
                    # 5xx a mitad de una publicacion es una condicion prevista
                    # ---queda en inflight y se resuelve sola---, no un fallo
                    # que pida mirar el log.
                    _log.warning(
                        "%s: la peticion publicaba algo y contesto %d; NO se "
                        "reintenta porque pudo procesarla antes de caerse. "
                        "Queda en inflight.", platform, resp.status)
                    resp.incierto = True
                    return resp
                if attempt == MAX_ATTEMPTS:
                    return resp
                self._sleep(attempt)
                last = resp
                continue

            return resp        # 2xx, 3xx y 4xx se devuelven tal cual

        return last or Response(status=0, text="agotados los reintentos")

    # ------------------------------------------------------------------
    def _simulate(self, platform, method, url, headers, data, json_body, files) -> Response:
        record = {
            "platform": platform,
            "method": method.upper(),
            "url": url,
            "headers": sorted((headers or {}).keys()),   # nunca los valores
            "json": log.redact(repr(json_body)[:800]) if json_body is not None else None,
            "data": log.redact(repr(data)[:800]) if data is not None else None,
            "files": sorted(files.keys()) if isinstance(files, dict) else bool(files),
            # El CONTENIDO de las partes que no son el fichero. Sin esto, la
            # simulacion solo guardaba los nombres de las partes, asi que la
            # prueba de "forma exacta de lo que se envia" no miraba el
            # json_data por dentro: un campo mal puesto ahi pasaba todas las
            # comprobaciones y solo fallaba contra la plataforma de verdad,
            # que es exactamente lo que esa prueba existe para evitar.
            "multipart": {
                nombre: log.redact(str(parte[1])[:600])
                for nombre, parte in (files or {}).items()
                if isinstance(parte, tuple) and parte and parte[0] is None
            } if isinstance(files, dict) else {},
        }
        self.simulated_calls.append(record)
        _log.info("SIMULADO %s %s %s", record["method"], url,
                  record["json"] or record["data"] or "")
        return Response(status=200, text="", json_body={"simulado": True}, simulated=True)

    @staticmethod
    def _retry_after(headers) -> float | None:
        raw = headers.get("Retry-After")
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None        # forma con fecha HTTP: caemos al retroceso normal

    @staticmethod
    def _backoff(attempt: int) -> float:
        # Con dispersion aleatoria, para que dos ejecuciones que fallan a la vez
        # no vuelvan a coincidir en el reintento.
        return min(BACKOFF_BASE ** attempt + random.uniform(0, 1.5), MAX_BACKOFF)

    def _sleep(self, attempt: int) -> None:
        time.sleep(self._backoff(attempt))
