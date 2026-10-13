# SPDX-License-Identifier: GPL-2.0-or-later
"""
Limitador de ritmo por plataforma.

Dos controles distintos que se confunden a menudo:

  - ritmo instantaneo: peticiones por minuto. Vive en memoria, se reinicia con
    el proceso, y basta con eso porque el proceso corre unos segundos.
  - cuota diaria: vive en la base de estado, porque tiene que sobrevivir entre
    ejecuciones del cron. Un contador en memoria daria vuelta a cero en cada
    arranque y la cuota real se dispararia sin que nadie lo viera.

Los limites por defecto son los publicados por cada plataforma, con margen. El
margen es intencionado: apurar el limite exacto es como se acaba con un 429
repetido, y un 429 repetido es lo que precede a una suspension.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from . import log

_log = log.get("ratelimit")

# (peticiones por minuto, cuota diaria). None = sin limite documentado.
# Los valores por minuto llevan margen sobre lo publicado a proposito.
LIMITS: dict[str, tuple[float | None, int | None]] = {
    "virustotal":    (4.0, 500),      # 4/min y 500/dia del plan publico
    "malwarebazaar": (10.0, None),
    "threatfox":     (10.0, None),
    "urlhaus":       (10.0, None),
    "abuseipdb":     (20.0, 1000),    # 1000/dia del plan gratuito
}


class QuotaExceeded(Exception):
    """Se agoto la cuota diaria. No es un error: es el sistema funcionando."""


class RateLimiter:
    """Ventana deslizante por plataforma. Duerme lo justo para no pasarse."""

    def __init__(self) -> None:
        self._calls: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def wait(self, platform: str) -> float:
        """Bloquea hasta que sea seguro lanzar la peticion. Devuelve la espera."""
        per_min = LIMITS.get(platform, (None, None))[0]
        if not per_min:
            return 0.0

        with self._lock:
            window = self._calls.setdefault(platform, deque())
            now = time.monotonic()
            while window and now - window[0] > 60.0:
                window.popleft()

            slept = 0.0
            if len(window) >= per_min:
                slept = 60.0 - (now - window[0]) + 0.25
                if slept > 0:
                    _log.debug("ritmo %s: esperando %.1fs", platform, slept)
                    time.sleep(slept)
                    now = time.monotonic()
                    while window and now - window[0] > 60.0:
                        window.popleft()
            window.append(now)
            return max(slept, 0.0)

    @staticmethod
    def daily_limit(platform: str) -> int | None:
        return LIMITS.get(platform, (None, None))[1]

    @staticmethod
    def check_quota(state, platform: str, reserve: int = 0) -> None:
        """Comprueba la cuota diaria de LLAMADAS contra el estado persistente.

        Cuenta llamadas y no publicaciones porque es lo que cuentan ellos: el
        limite de VirusTotal son 500 peticiones al dia e incluye las consultas
        de hash, que son la mayoria con diferencia. Mirando solo lo publicado,
        se agota la cuota real mucho antes de que el contador se acerque.

        `reserve` deja un colchon sin usar para operaciones que no se pueden
        dejar a medias: subir una muestra consume cuota, pero comentarla y
        votarla despues tambien, y quedarse sin cuota entre medias deja el
        trabajo incompleto.
        """
        limit = RateLimiter.daily_limit(platform)
        if limit is None:
            return
        used = state.calls_today(platform)
        if used + reserve >= limit:
            raise QuotaExceeded(
                f"{platform}: {used}/{limit} llamadas hoy"
                + (f" (reserva de {reserve})" if reserve else ""))
