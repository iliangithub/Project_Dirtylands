# SPDX-License-Identifier: GPL-2.0-or-later
"""
AbuseIPDB. El unico reporter que publica direcciones IP, y por eso el que mas
cuidado exige: aqui un error no es un duplicado, es acusar a alguien.

Dos reglas de su politica que condicionan todo el modulo:

  - Prohibido reportar SYN floods y trafico UDP, porque el origen puede ir
    falsificado. Traduccion practica: sin handshake TCP completado, no se
    reporta. Cowrie solo genera sesion si el TCP se completo, y en Dionaea el
    equivalente es connection_type='accept'. Esa es la condicion necesaria y
    no se deduce de ninguna otra cosa.
  - Prohibido incluir datos personales en el comentario. El comentario que se
    envia esta compuesto por nosotros a partir de contadores; nunca lleva
    texto escrito por el atacante, que podria contener credenciales de
    terceros o datos de un equipo comprometido.

El comentario no incluye la IP reportada ni la nuestra: la primera ya va en su
campo y la segunda no debe salir jamas.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from common.http import Response
from common.model import AttackerIP
from .base import Reporter

API = "https://api.abuseipdb.com/api/v2/report"

# Categorias oficiales, con su definicion literal de
# https://www.abuseipdb.com/categories. La definicion importa: son acusaciones
# publicas sobre una IP ajena, y varias dicen cosas mas concretas de lo que
# sugiere su nombre.
#
#   14 Port Scan   "Scanning for open ports and vulnerable services."
#   15 Hacking     (sin descripcion oficial)
#   16 SQL Inj.    "Attempts at SQL injection."
#   18 Brute-Force "Credential brute-force attacks on webpage logins and
#                   services like SSH, FTP, SIP, SMTP, RDP, etc."
#   22 SSH         "Secure Shell (SSH) abuse. Use this category in combination
#                   with more specific categories."
CAT_PORT_SCAN = 14
CAT_HACKING = 15
CAT_SQL_INJECTION = 16
CAT_BRUTE_FORCE = 18
CAT_SSH = 22
# "Host is likely infected with malware and being used for other attacks or to
# HOST MALICIOUS CONTENT". Es la unica de las 23 que describe a un servidor que
# sirve payloads, y lo dice con esas palabras. Ninguna categoria de AbuseIPDB
# cubre "distribucion de malware" de forma explicita, asi que esta es la que
# corresponde y se usa SOLA: un servidor de descargas no ha hecho fuerza bruta
# contra nosotros ni ha tocado nuestro SSH, y ponerle esas etiquetas seria
# acusarlo de algo que no hizo.
CAT_EXPLOITED_HOST = 20

# DOS CATEGORIAS QUE SE USABAN Y NO SE PUEDEN SOSTENER. No se marcan nunca, y
# quedan escritas aqui para que nadie las vuelva a anadir por parecer obvias:
#
#   20 Exploited Host  "Host is likely infected with malware and being used for
#                       other attacks or to host malicious content."
#       Se anadia por tocar el 445, el 1433 o el 135. Eso dice que alguien
#       sondeo SMB, no que la maquina de origen este infectada. Es una
#       afirmacion sobre el estado del equipo del OTRO, y no tenemos ni una
#       prueba de ello.
#
#   23 IoT Targeted    "Abuse was targeted at an 'Internet of Things' type
#                       device. Include information about what type of device
#                       was targeted in the comments."
#       Se anadia a TODO atacante de SSH o telnet. Nuestro senuelo se presenta
#       como un PC de trabajo con Debian 13, un i5-12400 y 16 GB: no es un
#       dispositivo IoT ni de lejos. Y la propia categoria exige decir QUE
#       aparato se ataco, cosa que no podriamos contestar. Era una acusacion
#       falsa repetida en cada denuncia.

MAX_COMMENT = 1024


class AbuseIPDB(Reporter):
    name = "abuseipdb"
    # Mas alto que las demas, y no por capricho. Es la unica plataforma cuya
    # politica cuenta con recibir denuncias de honeypots en volumen: el
    # limite son 1000 al dia. Y hay una razon tecnica: solo se recogen las
    # ultimas lookback_hours, asi que si el tope va por debajo del ritmo al
    # que llegan atacantes, la cola nunca se vacia y los mas antiguos se
    # caen de la ventana sin haberse reportado jamas. Con 25 por pasada y
    # el cron cada 15 minutos hay margen de sobra para cualquier ritmo
    # razonable, y sigue estando muy por debajo de lo que ellos permiten.
    MAX_PER_RUN = 25

    def __init__(self, section, http, state, guard, dry_run=True):
        super().__init__(section, http, state, guard, dry_run)
        self.cooldown_hours = section.getint("min_hours_between_reports", 24)
        self.min_conns_bruteforce = section.getint("min_events_for_bruteforce", 5)

    def _headers(self) -> dict:
        return {"Key": self.api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    def categories(self, att: AttackerIP) -> list[int]:
        cats: set[int] = set()

        if att.login_failures >= self.min_conns_bruteforce:
            cats.add(CAT_BRUTE_FORCE)
        if att.login_successes:
            # Entro con credenciales robadas o por defecto: eso es intrusion,
            # no solo intento.
            cats.add(CAT_HACKING)
        if att.commands:
            cats.add(CAT_HACKING)
        if att.sqli_evidence:
            cats.add(CAT_SQL_INJECTION)
        if len(att.ports) >= 3:
            cats.add(CAT_PORT_SCAN)
        # La 22 es SSH, no "SSH y telnet". Antes entraba tambien por telnet, y
        # una sesion de telnet no es abuso de SSH: es otro protocolo. Con el
        # puerto ya traducido en el collector, "22 in ports" por fin significa
        # algo (antes valia 2222 y no se cumplia nunca).
        protocolos = {p.lower() for p in att.protocols}
        if "ssh" in protocolos or 22 in att.ports:
            cats.add(CAT_SSH)

        if not cats:
            # Un accept sin nada mas sigue siendo un escaneo: es lo minimo
            # defendible, y no se reporta nada por debajo de eso.
            cats.add(CAT_PORT_SCAN)
        return sorted(cats)

    @staticmethod
    def _servicio(att: AttackerIP) -> str:
        """El servicio que ATACO de verdad, no una etiqueta generica.

        Antes ponia "SSH/Telnet" en toda denuncia de Cowrie, aunque la sesion
        hubiera sido solo de telnet. En una base de datos publica eso es un
        dato inventado en la mitad de los casos, y encima el que mas se mira:
        quien consulta una IP quiere saber que estaba atacando.
        """
        nombres = {22: "SSH", 23: "Telnet", 135: "RPC", 445: "SMB",
                   1433: "MSSQL", 3306: "MySQL", 21: "FTP"}
        vistos = [nombres[p] for p in sorted(att.ports) if p in nombres]
        if not vistos:
            # Sin puerto reconocido, se cae en el protocolo que anoto el
            # honeypot; y si tampoco, en algo neutro y cierto.
            vistos = [p.upper() for p in sorted(att.protocols)]
        return "/".join(vistos) if vistos else "Network"

    def comment(self, att: AttackerIP) -> str:
        """Comentario factual construido por nosotros. Sin texto del atacante.

        EN INGLES, igual que el de VirusTotal y por el mismo motivo: es un
        texto publico en una plataforma internacional, y escribirlo en
        castellano ata el honeypot a un operador hispanohablante cuando la
        maquina se presenta como ucraniana. La lengua identifica tanto como
        una IP, y aqui ademas se publica una vez por atacante.
        """
        # El plural, bien. Es un texto que se publica y que lee gente: un
        # "1 logins" delata que lo escribe una plantilla sin cuidado, y en una
        # denuncia la forma tambien cuenta.
        def n(cantidad: int, singular: str, plural: str) -> str:
            return f"{cantidad} {singular if cantidad == 1 else plural}"

        piezas = [f"{self._servicio(att)} honeypot."]
        if att.login_failures:
            piezas.append(n(att.login_failures,
                            "failed login attempt.", "failed login attempts."))
        if att.login_successes:
            piezas.append(n(att.login_successes,
                            "login with weak credentials.",
                            "logins with weak credentials."))
        if att.commands:
            piezas.append(n(att.commands,
                            "command executed after access.",
                            "commands executed after access."))
        if att.sqli_evidence:
            piezas.append("SQL injection attempt detected.")
        if att.ports:
            # Son los puertos PUBLICOS, ya traducidos por el collector: los
            # que marco el atacante, no los que Cowrie escucha por dentro.
            puertos = ", ".join(str(p) for p in sorted(att.ports)[:8])
            etiqueta = "Target port" if len(att.ports) == 1 else "Target ports"
            piezas.append(f"{etiqueta}: {puertos}.")
        piezas.append(f"Window: {att.first_seen:%Y-%m-%d %H:%M} to "
                      f"{att.last_seen:%Y-%m-%d %H:%M} UTC.")
        return " ".join(piezas)[:MAX_COMMENT]

    # ------------------------------------------------------------------
    def report(self, att: AttackerIP) -> bool:
        if not self.is_enabled():
            return False

        ip = att.ip

        # Condicion necesaria: sin handshake, la politica prohibe reportar.
        if not self.gate(ip, "handshake", att.handshake_ok,
                         "sin handshake TCP confirmado: la politica prohibe "
                         "reportar SYN floods y UDP, donde el origen puede ir "
                         "falsificado"):
            return False

        if not self.gate(ip, "evidencia",
                         bool(att.login_failures or att.login_successes
                              or att.commands or att.ports),
                         "conexion sin ninguna evidencia de ataque"):
            return False

        # Ventana de enfriamiento propia, mas estricta que la de la plataforma:
        # no tiene sentido volver a denunciar la misma IP cada hora.
        clave = f"{ip}@{datetime.now(timezone.utc):%Y-%m-%d}"
        visto = self.state.last_sent_at(self.name, f"{ip}@%",
                                        contar_simulados=self.dry_run)
        if visto is not None:
            horas = (datetime.now(timezone.utc) - visto).total_seconds() / 3600
            if not self.gate(ip, "enfriamiento", horas >= self.cooldown_hours,
                             f"reportada hace {horas:.1f} h, el minimo son "
                             f"{self.cooldown_hours} h"):
                return False

        comentario = self.comment(att)
        cuerpo = {
            "ip": ip,
            "categories": ",".join(str(c) for c in self.categories(att)),
            "comment": comentario,
            "timestamp": att.last_seen.isoformat(),
        }

        resp = self.send(
            clave,
            lambda: self.http.request(self.name, "POST", API,
                                      headers=self._headers(), data=cuerpo,
                                      crea_recurso=True),
            ip_context=ip, texts=(comentario,),
            detail=cuerpo["categories"])
        return bool(resp and resp.ok)

    # ------------------------------------------------------------------
    def resolve_orphans(self) -> None:
        """Aqui NO se consulta nada, y es deliberado.

        AbuseIPDB tiene endpoint para mirar una IP, pero saber si una de las
        denuncias que devuelve es NUESTRA obliga a reconocer nuestro propio
        identificador de denunciante entre los demas, y gasta cuota de la que
        hace falta para denunciar. No compensa, porque el problema se resuelve
        solo:

        LA CLAVE LLEVA LA FECHA ("ip@2026-08-29"). Mientras la fila siga en
        vuelo, esa IP no se vuelve a denunciar HOY ---que es exactamente lo
        que haria la ventana de enfriamiento de 24 h si el envio hubiera
        salido bien---. Y manana la clave es otra, asi que la denuncia vuelve
        a salir con normalidad.

        O sea que dejarlo en vuelo se comporta igual que resolverlo bien, sin
        gastar una consulta. Lo unico que hay que evitar es que la fila se
        quede ahi para siempre, y de eso se encarga la purga.

        Se avisa igual, con el metodo de la clase base, porque una fila en
        vuelo sigue siendo algo que paso y que conviene poder mirar.
        """
        super().resolve_orphans()

    def response_ok(self, resp: Response) -> tuple[bool, str]:
        """Un 429 de "ya la reportaste hace 15 minutos" NO es un rechazo.

        AbuseIPDB contesta asi:

            HTTP 429 {"errors":[{"detail":"You can only report the same IP
                      address once in 15 minutes.", ...}]}

        Y lo que esta diciendo es que LA DENUNCIA ESTA PUESTA. Pasa cuando
        ellos aceptan el POST y la respuesta se pierde por el camino ---un
        timeout de lectura, un 502 de un intermediario--- y el cliente HTTP
        reintenta: el reintento se encuentra con su propia denuncia.

        Darlo por fallido tenia una consecuencia mucho peor que una alarma
        falsa. Como no se anotaba en `sent`, el enfriamiento de 24 h no tenia
        de que agarrarse, y la pasada siguiente volvia a denunciar LA MISMA IP.
        Paso el 2026-08-27 con 103.29.185.162: rechazo a las 21:31 y denuncia
        de nuevo a las 21:45. Acabamos mandandoles la misma IP dos veces, que
        es exactamente lo que esa regla suya existe para evitar.

        Anotandolo como enviado se corta de raiz: el enfriamiento arranca, la
        pasada siguiente calla, y la alarma de "rechazo de plataforma" vuelve
        a significar lo que dice.

        OJO: solo ESE 429. El de haber agotado la cuota diaria es un rechazo
        de verdad y tiene que seguir siendolo.
        """
        if resp.status == 429 and "once in 15 minutes" in resp.text:
            return True, ""
        return super().response_ok(resp)

    def report_distribucion(self, host) -> bool:
        """Denuncia una IP que SIRVIO un binario malicioso confirmado.

        Camino aparte del de los atacantes, y a proposito. Cambian las tres
        cosas: la evidencia (una muestra nuestra en vez de un apreton de
        manos), la categoria (20 y solo la 20) y el texto, que tiene que decir
        de que se le acusa exactamente.

        El liston es el mismo que el de ThreatFox: no basta con haber visto la
        direccion escrita en un comando. Hace falta que nos hayamos bajado el
        fichero de ahi Y que ese fichero haya pasado la puerta de VirusTotal.
        Sin eso, un atacante que teclee `wget http://<victima>/x` en el senuelo
        conseguiria que denunciaramos a un inocente.
        """
        if not self.is_enabled():
            return False

        ip = host.ip
        if not self.gate(ip, "sin-muestra", bool(host.sha256),
                         "no nos bajamos ningun fichero de esa IP: haber visto "
                         "su direccion escrita en un comando no es evidencia"):
            return False
        if not self.gate(ip, "veredicto", host.motores > 0,
                         "la muestra no tiene veredicto firme de VirusTotal"):
            return False

        clave = f"{ip}@{datetime.now(timezone.utc):%Y-%m-%d}"
        visto = self.state.last_sent_at(self.name, f"{ip}@%",
                                        contar_simulados=self.dry_run)
        if visto is not None:
            horas = (datetime.now(timezone.utc) - visto).total_seconds() / 3600
            if not self.gate(ip, "enfriamiento", horas >= self.cooldown_hours,
                             f"reportada hace {horas:.1f} h, el minimo son "
                             f"{self.cooldown_hours} h"):
                return False

        comentario = self.comment_distribucion(host)
        cuerpo = {
            "ip": ip,
            "categories": str(CAT_EXPLOITED_HOST),
            "comment": comentario,
            "timestamp": host.seen_at.isoformat(),
        }
        resp = self.send(
            clave,
            lambda: self.http.request(self.name, "POST", API,
                                      headers=self._headers(), data=cuerpo,
                                      crea_recurso=True),
            ip_context=ip, texts=(comentario, host.url),
            detail=f"distribucion:{CAT_EXPLOITED_HOST}")
        return bool(resp and resp.ok)

    def comment_distribucion(self, host) -> str:
        """El texto de la denuncia de un servidor de distribucion.

        EN INGLES, como el resto de lo que se publica, y por el mismo motivo:
        es un texto publico en una plataforma internacional y la lengua
        identifica tanto como una IP.

        Dice exactamente de que se le acusa y con que prueba ---el hash y
        cuantos motores lo marcan--- porque quien lea la denuncia tiene que
        poder comprobarla. Y NO se copia la URL entera: la ruta la elige el
        atacante y podria llevar texto suyo, que es justo lo que no publicamos.
        """
        familia = f" ({host.familia})" if host.familia else ""
        puerto = f" on port {host.puerto}" if host.puerto else ""
        return (
            f"Malware distribution host{puerto}. This IP served a confirmed "
            f"malicious binary{familia} that was downloaded into our honeypot "
            f"by an attacker during a session on "
            f"{host.seen_at.strftime('%Y-%m-%d')} (UTC). "
            f"Sample SHA-256: {host.sha256}, flagged by {host.motores} "
            f"engines on VirusTotal. Reported for hosting malicious content, "
            f"not for connecting to us."
        )

    def run(self, attackers: list[AttackerIP]) -> int:
        """Reporta el lote, de mas activo a menos, hasta el tope por ejecucion."""
        if not self.is_enabled():
            return 0
        orden = sorted(attackers, key=lambda a: (
            a.login_failures + a.login_successes + a.commands), reverse=True)
        # La lista NO se recorta antes de mirarla. El tope lo aplica send(),
        # que cuenta ENVIOS; recortar aqui contaba CANDIDATAS, y la diferencia
        # no es teorica: veinticinco IP que iban a caer por la ventana de
        # enfriamiento se llevaban el cupo entero y se reportaban CERO con
        # sesenta y nueve esperando. Peor aun, el orden es estable, asi que las
        # mismas veinticinco se lo comian en cada pasada y las de mas abajo no
        # llegaban a mirarse nunca: acababan cayendose de lookback_hours sin
        # haberse reportado jamas.
        for att in orden:
            self.report(att)
        if self.aplazados:
            self.log.info("%d IP quedan para la proxima pasada (tope por ejecucion)",
                          self.aplazados)
        return self.sent
