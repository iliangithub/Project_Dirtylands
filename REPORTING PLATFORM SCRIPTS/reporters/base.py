# SPDX-License-Identifier: GPL-2.0-or-later
"""
Maquinaria comun de los reporters: puertas, cuota, barrera e idempotencia.

Toda publicacion pasa por send(), y send() hace siempre la misma secuencia:

    1. cuota diaria      -> si no queda, no se envia
    2. ya enviado?       -> si lo esta, no se repite
    3. barrera IPGuard   -> ultima linea antes de abrir el socket
    4. begin_send()      -> la intencion queda en disco ANTES del POST
    5. POST
    6. commit_send() si salio bien, abort_send() si fallo

Esta centralizado por el mismo motivo que el modo simulacion vive en el
transporte: una comprobacion que cada reporter tiene que acordarse de hacer es
una comprobacion que algun dia no se hara. Aqui no hay forma de publicar
saltandose la secuencia.

Todo rechazo se registra con su motivo, asi que "por que no se reporto esto"
siempre tiene respuesta consultable.
"""

from __future__ import annotations

from typing import Callable

from common import log
from common.http import HttpClient, Response
from common.ipguard import IPGuard, UnsafeTarget
from common.ratelimit import QuotaExceeded, RateLimiter
from common.state import State


# A que grupo pertenece cada motivo de no-envio. Lo que no aparezca aqui se
# cuenta como "descartadas".
#
# Existe porque el resumen daba UN numero para veinte motivos distintos, y
# metia en el mismo saco cosas que no se parecen en nada: "la plataforma nos
# lo rechazo" y "esa IP ya la reportamos hace tres horas". Leer
# "283 rechazados" de AbuseIPDB alarma, y resulta que eran 280 IP que ya
# estaban cubiertas por la ventana de 24 h --- o sea, el sistema funcionando.
GRUPOS_MOTIVO = {
    # Lo unico que es de verdad un rechazo AJENO. Si esto no es cero, hay algo
    # que mirar hoy: es lo que alimenta el cortacircuitos de abuse.ch.
    "rechazo-plataforma": "rechazadas por la plataforma",

    # No se envio AHORA, pero se enviara: vuelve en la siguiente pasada o
    # manana. No se pierde nada.
    "tope-por-pasada": "aplazadas",
    "cuota": "aplazadas",
    "tope-diario": "aplazadas",
    "tope-semanal": "aplazadas",

    # Ni exito ni rechazo: la peticion publicaba algo y no se sabe si llego.
    # Tiene grupo propio porque no se parece a ninguno de los otros y porque
    # exige mirar: la intencion se queda en inflight hasta que resolve_orphans
    # ---o una persona--- averigue que paso.
    "resultado-incierto": "sin confirmar",

    # Ya esta cubierto: o lo mandamos nosotros, o lo tiene la plataforma, o
    # cae dentro de una ventana de enfriamiento. No hay nada que hacer.
    "duplicado": "ya cubiertas",
    "enfriamiento": "ya cubiertas",
    "capa1-local": "ya cubiertas",
    "capa2-remota": "ya cubiertas",
    "capa3-similitud": "ya cubiertas",
    "capa4-campana": "ya cubiertas",
    "capa5-rafaga": "ya cubiertas",
}

ORDEN_GRUPOS = ("ya cubiertas", "descartadas", "aplazadas",
                "rechazadas por la plataforma")


class Reporter:
    name = "base"

    # Cuantas cosas COMO MUCHO publica esta plataforma en una sola pasada.
    #
    # No es la cuota de la plataforma ni un limite tecnico: es un freno de
    # mano. Las puertas de calidad deciden QUE se puede publicar; esto decide
    # CUANTO de una vez. Si una noche caen cincuenta binarios validos, subir
    # los cincuenta de golpe es indistinguible de un volcado automatico, y eso
    # es justo lo que las plataformas penalizan. Goteando, lo que hoy no sale
    # sale en la pasada siguiente: el cron corre cada 15 minutos.
    #
    # Se cuenta por pasada y no por dia a proposito. Un tope diario deja pasar
    # la rafaga entera de una vez y luego calla; este reparte siempre.
    MAX_PER_RUN = 3

    def __init__(self, section, http: HttpClient, state: State,
                 guard: IPGuard, dry_run: bool = True) -> None:
        self.cfg = section
        self.http = http
        self.state = state
        self.guard = guard
        self.dry_run = dry_run
        self.log = log.get(f"reporter.{self.name}")
        self.sent = 0
        self.rejected = 0
        # Por motivo, para que el resumen pueda decir QUIEN no lo envio.
        self.motivos: dict[str, int] = {}
        self.max_per_run = section.getint("max_per_run", self.MAX_PER_RUN)
        # Algo se quedo fuera por un tope TEMPORAL (el de la pasada o el de
        # cuota), no por un rechazo de fondo. Quien orquesta lo mira para no
        # dar por terminada una muestra que en realidad no llego a publicarse.
        # La distincion importa: reintentar lo aplazado es correcto,
        # reintentar lo rechazado por antiguedad es gastar cuota en balde.
        self.diferido = False
        # Cuantas se han quedado fuera SOLO por el tope de la pasada.
        self.aplazados = 0
        # Handle con el que se firma lo publicado. Vacio = no se firma.
        self.attribution = section.get("attribution_tag", "").strip()

    @property
    def attribution_tag(self) -> str:
        """El handle en forma de etiqueta, o cadena vacia si no hay ninguno.

        Se comprueba el marcador `<ASI>` ademas de la cadena vacia: publicar
        "#<TU-HANDLE>" en un comentario permanente de VirusTotal seria peor
        que no firmar nada.
        """
        h = self.attribution
        if not h or h.startswith("<") or h.endswith(">"):
            return ""
        return "#" + h.lstrip("#")

    # ------------------------------------------------------------------
    @property
    def api_key(self) -> str:
        return self.cfg.get("api_key", "").strip()

    def is_enabled(self) -> bool:
        if not self.cfg.getboolean("enabled", False):
            return False
        if not self.api_key:
            self.log.warning("%s: activado pero sin api_key, se omite", self.name)
            return False
        # Un marcador del ejemplo sin sustituir cuenta como NO configurado. Sin
        # esto, el cron se pondria a consultar la plataforma cada 15 minutos con
        # una clave invalida en cuanto hubiera algo que mirar, acumulando 401
        # desde nuestra IP hasta que alguien se diera cuenta.
        if self.api_key.startswith("<") or self.api_key.endswith(">"):
            self.log.warning(
                "%s: la api_key sigue siendo el marcador del ejemplo, se omite",
                self.name)
            return False
        return True

    def response_ok(self, resp: Response) -> tuple[bool, str]:
        """(salio bien, motivo del fallo). Por defecto basta el codigo HTTP.

        Existe para que cada plataforma decida que es "correcto", porque no
        todas lo dicen en el codigo HTTP. Las de abuse.ch responden 200 con el
        error dentro del JSON, asi que mirar solo el HTTP daria por publicado
        algo que fue rechazado, y ademas lo dejaria marcado como enviado para
        siempre.
        """
        return (True, "") if resp.ok else (False, f"HTTP {resp.status}")

    def _anotar(self, key: str, gate: str, reason: str) -> None:
        """Registra un no-envio: en el estado, en el total y por motivo."""
        self.state.reject(self.name, key, gate, reason)
        self.rejected += 1
        self.motivos[gate] = self.motivos.get(gate, 0) + 1

    def gate(self, key: str, gate: str, passes: bool, reason: str) -> bool:
        """Evalua una puerta. Si no pasa, deja constancia del motivo."""
        if not passes:
            self._anotar(key, gate, reason)
        return passes

    # ------------------------------------------------------------------
    def send(self, key: str, do_post: Callable[[], Response], *,
             ip_context: str | None = None, texts: tuple[str, ...] = (),
             detail: str = "") -> Response | None:
        """Publica una cosa. Devuelve la respuesta, o None si no se envio."""
        # Lo primero, porque es lo mas barato y lo mas restrictivo. Lo que se
        # queda fuera NO se pierde: sigue en la ventana de recogida y sale en
        # la pasada siguiente.
        if self.sent >= self.max_per_run:
            self._anotar(key, "tope-por-pasada",
                         f"ya van {self.sent} en esta pasada, el maximo son "
                         f"{self.max_per_run}; se reintenta en la siguiente")
            self.diferido = True
            self.aplazados += 1
            return None

        try:
            RateLimiter.check_quota(self.state, self.name)
        except QuotaExceeded as exc:
            self._anotar(key, "cuota", str(exc))
            self.diferido = True
            return None

        if self.state.already_sent(self.name, key,
                                   contar_simulados=self.dry_run):
            self._anotar(key, "duplicado", "ya enviado anteriormente")
            return None

        # LO QUE QUEDO SIN CONFIRMAR TAMPOCO SE REENVIA. Esta comprobacion va
        # ANTES del begin_send() de esta pasada, asi que si hay fila es de una
        # anterior: aquel envio salio y no sabemos si entro.
        #
        # Sin esto, marcar el resultado como incierto no bastaba. Al no
        # anotarse en `sent`, el enfriamiento de AbuseIPDB no tenia de que
        # agarrarse y la pasada siguiente denunciaba la misma IP ---que es
        # justo el fallo que se arreglo el 2026-08-27 con 103.29.185.162, dos
        # denuncias en catorce minutos---. Se cambiaria un duplicado por otro.
        #
        # No se queda bloqueado para siempre: la clave de AbuseIPDB lleva la
        # fecha, asi que manana vuelve a salir; y quien sepa preguntar a su
        # plataforma lo resuelve en resolve_orphans y retira la fila.
        desde = self.state.en_vuelo(self.name, key)
        if desde:
            self._anotar(key, "resultado-incierto",
                         f"salio el {desde} y no se sabe si llego; no se "
                         "reenvia a ciegas")
            return None

        # Barrera final. Fail-closed: cualquier duda aborta el envio.
        try:
            if ip_context:
                self.guard.assert_safe(ip_context, f"{self.name}:{key[:16]}")
            for text in texts:
                self.guard.assert_text_safe(text, f"{self.name}:{key[:16]}")
        except UnsafeTarget as exc:
            self._anotar(key, "barrera", str(exc))
            return None

        self.state.begin_send(self.name, key)
        try:
            resp = do_post()
        except Exception as exc:                      # noqa: BLE001
            self.state.abort_send(self.name, key)
            self.log.error("%s: fallo al enviar %s: %s", self.name, key[:16], exc)
            return None

        # PRIMERO LO INCIERTO, antes de juzgar la respuesta. Un timeout o un
        # 500 en una peticion que publica no dicen "no llego", dicen "no se
        # sabe", y las dos salidas normales hacen dano aqui: darlo por bueno
        # pierde el envio de verdad, y darlo por fallido lo reenvia y lo
        # duplica ---que es como salio la denuncia repetida a AbuseIPDB del
        # 2026-08-28---.
        #
        # Asi que NO se llama a abort_send(): la fila se queda en inflight, que
        # es exactamente para lo que existe esa tabla, y resolve_orphans le
        # preguntara a la plataforma si aquello entro. Tampoco cuenta como
        # rechazo de la plataforma: la plataforma no ha dicho nada.
        if resp.incierto:
            self._anotar(key, "resultado-incierto",
                         f"no se sabe si llego: {resp.text[:120]}")
            # WARNING y no ERROR: el resultado incierto es una salida PREVISTA
            # de send() ---la fila queda en inflight y la clave con fecha evita
            # repetir hoy---, no un fallo. El ERROR se reserva para lo que de
            # verdad pide accion (la excepcion de mas abajo, un colector que no
            # lee). resolve_orphans ya resume cuantas quedan.
            self.log.warning(
                "%s: %s quedo SIN CONFIRMAR y sigue en inflight; no se "
                "reenvia a ciegas", self.name, key[:32])
            return resp

        salio_bien, motivo = self.response_ok(resp)
        if salio_bien:
            self.state.commit_send(self.name, key,
                                   "simulado" if resp.simulated else "enviado", detail)
            self.sent += 1
            self.log.info("%s: %s %s", self.name,
                          "SIMULADO" if resp.simulated else "publicado", key[:32])
        else:
            self.state.abort_send(self.name, key)
            self._anotar(key, "rechazo-plataforma", motivo)
            self.log.warning("%s: la plataforma rechazo %s: %s (%s)",
                             self.name, key[:16], motivo, resp.text[:200])
            self.on_rejected(key, motivo)
        return resp

    def on_rejected(self, key: str, motivo: str) -> None:
        """Gancho para reaccionar a un rechazo de la plataforma. No hace nada
        por defecto; lo usa la cuenta compartida de abuse.ch."""

    # ------------------------------------------------------------------
    def resolve_orphans(self) -> None:
        """Envios cuyo resultado quedo sin conocer al morir el proceso.

        No se reintentan a ciegas. Cada plataforma que sepa consultar si algo
        llego sobreescribe este metodo; el resto se limita a avisar, porque
        reenviar por si acaso es exactamente como se generan los duplicados
        que las plataformas penalizan.

        UNA sola linea de resumen, no una por fila. AbuseIPDB puede acumular
        decenas de huerfanos ---cada corte de red deja uno y el purgado los
        guarda un mes---, y esto corre cada 15 min: una linea por fila eran
        miles al dia, y eran las que llenaban el log y lo hacian rotar tres
        veces al dia (lo que a su vez rompia el conteo de 24 h del resumen).
        """
        filas = self.state.orphans(self.name)
        if not filas:
            return
        mas_viejo = min(f["started_at"] for f in filas)
        self.log.warning(
            "%s: %d envio(s) en vuelo sin resolver, el mas viejo del %s. "
            "No se reintentan automaticamente; la clave con fecha evita "
            "repetirlos y el purgado se lleva los muy viejos.",
            self.name, len(filas), mas_viejo[:10])

    def summary(self) -> str:
        """Una linea que distingue QUIEN no lo envio y por que.

        Solo se nombran los grupos con algo dentro: una linea con cuatro
        ceros no dice nada y se lee peor.
        """
        grupos: dict[str, int] = {}
        for motivo, n in self.motivos.items():
            etiqueta = GRUPOS_MOTIVO.get(motivo, "descartadas")
            grupos[etiqueta] = grupos.get(etiqueta, 0) + n

        partes = [f"{self.sent} enviados"]
        for etiqueta in ORDEN_GRUPOS:
            n = grupos.get(etiqueta, 0)
            if not n:
                continue
            # En mayusculas porque es la unica que pide accion.
            if etiqueta == "rechazadas por la plataforma":
                partes.append(f"{n} RECHAZADAS POR LA PLATAFORMA")
            else:
                partes.append(f"{n} {etiqueta}")
        return f"{self.name}: " + ", ".join(partes)


class AbuseChReporter(Reporter):
    """Base de MalwareBazaar, ThreatFox y URLhaus.

    Dos cosas las unen, y las dos son criticas.

    La primera es tecnica: responden 200 con el resultado dentro del JSON, en
    `query_status`. Comprobar solo el codigo HTTP daria por bueno un rechazo, y
    el envio quedaria marcado como enviado para siempre sin haberlo estado.

    La segunda es de riesgo: **las tres cuelgan de la misma cuenta de
    abuse.ch**. Una sancion en cualquiera de ellas se lleva por delante las
    tres, asi que no tiene sentido que cada una vigile solo sus propios
    rechazos. Por eso hay un CORTACIRCUITOS de cuenta: unos pocos rechazos
    seguidos, vengan de donde vengan, y las tres se apagan.

    Se apagan y se quedan apagadas. No se rearma solo al cabo de un rato: si la
    plataforma nos esta rechazando envios, seguir insistiendo automaticamente
    es precisamente el patron que acaba en baneo. Lo rearma una persona con
    --reset-breaker, despues de mirar por que paso.
    """

    ESTADOS_OK: set[str] = {"ok"}

    # Las tres plataformas que comparten cuenta.
    CUENTA = "abuse.ch"
    HERMANAS = ("malwarebazaar", "threatfox", "urlhaus")
    MAX_RECHAZOS = 3
    VENTANA_HORAS = 24

    def is_enabled(self) -> bool:
        if not super().is_enabled():
            return False
        salto = self.state.breaker(self.CUENTA)
        if salto:
            self.log.critical(
                "%s DESACTIVADA: el cortacircuitos de la cuenta %s salto el %s "
                "(%s). Las tres plataformas de abuse.ch comparten cuenta, asi "
                "que ninguna publica hasta rearmarlo con --reset-breaker.",
                self.name, self.CUENTA, salto["tripped_at"], salto["reason"])
            return False
        return True

    def on_rejected(self, key: str, motivo: str) -> None:
        recientes = self.state.count_rejections(
            self.HERMANAS, "rechazo-plataforma", self.VENTANA_HORAS)
        if recientes >= self.MAX_RECHAZOS:
            self.state.trip_breaker(
                self.CUENTA,
                f"{recientes} rechazos de abuse.ch en {self.VENTANA_HORAS} h; "
                f"el ultimo, en {self.name}: {motivo}")

    def response_ok(self, resp: Response) -> tuple[bool, str]:
        if not resp.ok:
            return False, f"HTTP {resp.status}"
        if resp.simulated:
            return True, ""
        cuerpo = resp.json() or {}
        estado = cuerpo.get("query_status")
        if estado is None:
            return False, f"respuesta sin query_status: {resp.text[:120]}"
        if estado in self.ESTADOS_OK:
            # SE DEJA CONSTANCIA DE LA RESPUESTA ENTERA, aunque haya salido
            # bien. En abuse.ch "query_status=ok" no significa necesariamente
            # "se ha anadido": el detalle de que paso con cada indicador va en
            # `data`, y su API NO documenta la respuesta de submit_ioc.
            #
            # Sin esto no se puede distinguir "publicado" de "aceptado pero
            # ignorado por duplicado", que es exactamente la duda que aparecio
            # el 2026-08-28: el parte decia "threatfox: 1 publicadas" y en el
            # perfil no habia nada nuevo. Anotandola, la proxima vez la
            # respuesta esta ahi y se decide sobre un dato, no sobre una
            # suposicion.
            self.log.info("%s: respuesta de %s: %s",
                          self.name, self.CUENTA, resp.text[:400])
            return True, ""
        return False, f"query_status={estado}"
