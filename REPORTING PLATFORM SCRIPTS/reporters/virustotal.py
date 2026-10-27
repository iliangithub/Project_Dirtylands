# SPDX-License-Identifier: GPL-2.0-or-later
"""
VirusTotal. Primer eslabon de la cadena y el unico que decide si algo es
malware; MalwareBazaar depende de su veredicto.

El orden importa y no es arbitrario. Los bots vigilan MalwareBazaar y corren a
subir a VirusTotal lo que aparece alli para llevarse la autoria. Por eso:

    1. subir a VirusTotal en cuanto se captura   -> la autoria ya es nuestra
    2. esperar al veredicto (rechequeo diferido) -> nada de comentar en caliente
    3. comentar y votar solo si pasa la puerta 12 + 3
    4. y solo entonces, MalwareBazaar

Separar 1 de 3 es lo que resuelve la tension entre "solo malware confirmado" y
"muestra fresca": la subida es inmediata, el juicio espera.

La puerta de maliciosidad, criterio propio (NO VERIFICADO: ni VirusTotal ni
MalwareBazaar publican un umbral oficial):

    analisis en estado completed
    >= 12 motores en malicious
    >= 3 de ellos con nombre de familia concreto, no un generico
    sin senal dominante de adware/PUP

Tres motores diciendo "Mirai" valen mas que doce diciendo "Trojan.Generic":
los doce genericos pueden ser la misma heuristica repetida; los tres concretos
significan que alguien ha reconocido QUE es.

La antiguedad se toma SIEMPRE de first_submission_date de VirusTotal, nunca de
la fecha del fichero en disco. Confundir "cuando lo capture yo" con "que
antiguedad tiene el malware" es lo que provoco el baneo anterior.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from common.http import Response
from common.model import Sample, servicio_de
from common.ratelimit import QuotaExceeded, RateLimiter
from .base import Reporter

API = "https://www.virustotal.com/api/v3"

# Umbral por encima del cual VirusTotal exige una URL de subida dedicada.
BIG_FILE_BYTES = 32 * 1024 * 1024

# Palabras que NO cuentan como nombre de familia: son etiquetas genericas de
# clasificador, no una identificacion.
_GENERIC = {
    "generic", "trojan", "agent", "malware", "malicious", "heur", "heuristic",
    "ml", "attribute", "unsafe", "variant", "suspicious", "elf", "linux",
    "unix", "riskware", "hacktool", "packed", "obfuscated", "confidence",
    "score", "gen", "a", "b", "c", "test", "eldorado", "susgen", "trojanx",
}

# Familias reconocidas en botnets de IoT y Linux. Si un motor devuelve una de
# estas, cuenta como identificacion concreta.
# Familias que damos por buenas siempre. Desde que el filtro es una lista
# negra (ver GENERICOS) esto ya NO es la unica forma de que un nombre cuente:
# es un atajo, y la constancia de cuales son las habituales por aqui.
KNOWN_FAMILIES = {
    "mirai", "gafgyt", "bashlite", "tsunami", "kaiten", "xorddos", "dofloo",
    "hajime", "mozi", "ddostf", "sora", "okiru", "chalubo", "lightaidra",
    "hydra", "pnscan", "rakos", "shellbot", "sshdkit", "coinminer", "xmrig",
    "prometei", "kinsing", "skidmap", "outlaw", "perlbot", "muhstik",
    "ngioweb", "bpfdoor", "winnti", "conficker", "wannacry", "ramnit",
    "sality", "virut", "emotet", "qakbot", "cobaltstrike", "metasploit",
}

# Lo que NO es un nombre de familia aunque venga en el veredicto de un motor.
#
# Es una lista NEGRA, y antes esto era al reves: solo contaba lo que estuviera
# en KNOWN_FAMILIES, y cualquier otra cosa valia cero por unanimes que fueran
# los motores. Aquello descartaba en silencio malware evidente. El caso que lo
# destapo fue RedTail ---capturado el 2026-08-22, cinco binarios---:
# treinta motores diciendo "redtail" daban consenso 0, y
# el rechazo se leia "solo 0 motores coinciden en la familia ninguna", que
# suena a falta de consenso cuando lo que faltaba era una entrada en la lista.
#
# El filtro sigue haciendo falta, y por eso no basta con quitarlo: sin el, el
# token mas contado seria "trojan" y publicariamos `malware: trojan`, que es
# peor que no publicar. Lo que cambia es el sentido, no la existencia.
#
# ANTE LA DUDA, EL NOMBRE VA AQUI. Los dos errores no cuestan lo mismo: uno
# bloqueado de mas es una muestra que no se publica ---el comportamiento de
# siempre---, y uno de menos es una etiqueta falsa en una plataforma publica.
#
# El grupo que mas importa es el ultimo. Son nombres de deteccion GENERICA que
# varias casas comparten porque licencian el mismo motor (Bitdefender esta
# dentro de GData, Emsisoft, Arcabit, MAX y varios mas), asi que llegan a tres
# motores "de acuerdo" sin que eso signifique nada. Los sufijos de variante no
# hacen falta ponerlos: son propios de cada casa y nunca reunen tres.
GENERICOS = {
    # plataforma, formato y arquitectura
    "linux", "unix", "win", "win32", "win64", "windows", "macos", "osx", "dos",
    "android", "ios", "elf", "exe", "dll", "sys", "msil", "java", "jar",
    "class", "script", "shell", "bash", "perl", "python", "php", "jsp", "asp",
    "vbs", "vba", "ps1", "powershell", "html", "htm", "xml", "swf", "pdf",
    "doc", "docx", "xls", "rtf", "apk", "deb", "rpm", "bat", "cmd", "lnk",
    "arm", "arm5", "arm6", "arm7", "arm8", "mips", "mipsel", "ppc", "powerpc",
    "sparc", "riscv", "x86", "x64", "i386", "i486", "i586", "i686", "amd64",
    "aarch64", "m68k", "intel", "renesas", "motorola",

    # clase de amenaza
    "trojan", "troj", "trj", "virus", "worm", "backdoor", "rootkit", "bootkit",
    "ransom", "ransomware", "spyware", "adware", "riskware", "hacktool",
    "hktl", "exploit", "expl", "dropper", "downloader", "downldr", "loader",
    "injector", "banker", "stealer", "infostealer", "keylogger", "miner",
    "cryptominer", "ddos", "flooder", "bot", "botnet", "rat", "proxy", "spam",
    "phish", "phishing", "scam", "fraud", "dialer", "packer", "packed",
    "obfuscated", "obfus", "cryptor", "crypted", "encoder", "patcher",
    "patched", "cracked", "keygen", "nuker", "killav", "filecoder", "wiper",
    "webshell", "shellcode", "agent", "clicker", "joke", "hoax", "flood",

    # marcadores genericos, heuristicos y de confianza
    "generic", "generick", "genericml", "generickd", "genkryptik", "gen",
    "genpack", "heur", "heuristic", "heuristics", "cloud", "static",
    "dynamic", "behaveslike", "behavior", "suspicious", "suspect",
    "malicious", "malware", "malwaregen", "malwarex", "threat", "unsafe",
    "unwanted", "potentially", "application", "program", "tool", "utility",
    "test", "sample", "eicar", "variant", "family", "unknown", "unclassified",
    "other", "misc", "multi", "attribute", "highconfidence", "confidence",
    "score", "detected", "detection", "reputation", "trusted", "probably",
    "possible", "corrupt", "damaged", "artificial", "machinelearning",

    # nombres de deteccion generica que comparten varias casas por licenciar
    # el mismo motor. Son los que de verdad pueden colarse: llegan a tres
    # motores de acuerdo sin identificar nada.
    "artemis", "kryptik", "wacatac", "sabsik", "occamy", "fugrafa", "ulise",
    "zusy", "graftor", "barys", "symmi", "midie", "razy", "strictor",
    "convagent", "injuke", "chapak", "deyma", "zenpak", "bsymem", "bulz",
    "malex", "presenoker", "tiggre", "casdet", "disgen", "jaik", "sonbokli",
    "cerbu", "siggen", "eldorado", "susgen", "filerepmalware", "scarsi",
    "ekstak", "starter", "banload", "autorun", "small", "startpage",
}

_ADWARE_HINTS = {"adware", "pup", "pua", "unwanted", "bundler", "notaviru"}

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{2,}")

# Largo minimo para que un nombre DESCONOCIDO cuente como familia. Los de
# KNOWN_FAMILIES entran siempre, midan lo que midan.
#
# Es el agujero que abre la lista negra, y no es teorico: casi todos los
# motores pegan un sufijo de variante al nombre, y suele ser de tres letras
# ---"ELF:Mirai-ABC", "Trojan.Linux.Mirai.abc"---. Ese sufijo aparece en la
# misma cadena que la familia, asi que empata con ella en numero de motores, y
# al desempatar por orden alfabetico "abc" le ganaba a "mirai": la muestra se
# habria publicado etiquetada como familia "abc". Ninguna de las familias
# conocidas baja de cuatro letras, asi que el corte no se lleva nada por
# delante.
MIN_LARGO_FAMILIA = 4


class VirusTotal(Reporter):
    name = "virustotal"
    # Cada muestra gasta hasta tres: subida, comentario y voto. Seis son dos
    # muestras completas por pasada, ocho al dia. Es la plataforma menos
    # delicada --- esta hecha para recibir subidas --- pero la autoria de
    # ser primeros no compensa parecer un volcado.
    MAX_PER_RUN = 6

    # Motivos de rechazo que NO mejoran esperando, asi que reintentarlos es
    # gastar cuota de VirusTotal para llegar dias despues al mismo no.
    #
    # "veredicto" y "deteccion" SI mejoran: los motores se ponen al dia y una
    # muestra recien vista pasa de 3 a 30 detecciones en unas horas. Ese es el
    # motivo de que exista el rechequeo diferido.
    #
    # "adware" no. Se comprueba DESPUES del umbral de detecciones, o sea con
    # doce motores o mas ya opinando, asi que la proporcion que lo declara
    # adware ya es significativa y no se va a dar la vuelta.
    DEFINITIVOS = frozenset({"adware"})

    def __init__(self, section, http, state, guard, dry_run=True):
        super().__init__(section, http, state, guard, dry_run)
        self.min_malicious = section.getint("min_malicious", 12)
        self.min_families = section.getint("min_named_families", 3)

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    def lookup(self, sha256: str) -> dict | None:
        """Informe de un hash, o None si VirusTotal no lo conoce (404).

        Es una lectura: se permite tambien en modo simulacion, porque si no,
        una simulacion no podria comprobar las puertas, que es justo lo que se
        quiere validar antes de autorizar una ejecucion real.
        """
        # La consulta tambien gasta cuota, asi que se comprueba ANTES. Sin
        # esto, al agotarla seguiriamos preguntando y acumulando 429, que es
        # el patron que precede a una suspension.
        #
        # Se reservan 3 llamadas: si una muestra pasa la puerta hay que
        # comentarla y votarla, y quedarse sin cuota a mitad dejaria la muestra
        # subida pero sin comentario, que es lo que los bots aprovechan.
        try:
            RateLimiter.check_quota(self.state, self.name, reserve=3)
        except QuotaExceeded as exc:
            self.log.warning("no se consulta %s: %s", sha256[:16], exc)
            raise LookupError(str(exc)) from exc

        resp = self.http.request(self.name, "GET", f"{API}/files/{sha256}",
                                 headers=self._headers(), allow_in_dry_run=True)
        if resp.status == 404:
            return None
        if not resp.ok:
            # Fail-closed: sin informe no se decide nada. Devolver un dict
            # vacio haria que la puerta lo tomara por "0 detecciones" y la
            # muestra se descartaria por el motivo equivocado.
            self.log.warning("consulta de %s: HTTP %d", sha256[:16], resp.status)
            raise LookupError(f"VirusTotal no respondio para {sha256[:16]}")
        return (resp.json() or {}).get("data", {})

    def is_new(self, sha256: str) -> bool | None:
        """True si VirusTotal no lo tiene. None si no se pudo averiguar."""
        try:
            return self.lookup(sha256) is None
        except LookupError:
            return None

    # ------------------------------------------------------------------
    def resolve_orphans(self) -> None:
        """Las SUBIDAS se pueden comprobar: si VirusTotal tiene el hash, llego.

        Ojo con lo que esto afirma y lo que no. Que VirusTotal tenga el fichero
        no demuestra que lo subieramos nosotros ---pudo subirlo otro---, pero
        para lo unico que se usa esta respuesta si es suficiente: la pregunta
        no es "quien lo subio" sino "hace falta volver a subirlo", y si ya
        esta, no.

        Los comentarios y los votos NO se resuelven aqui: no hay forma barata
        de saber si el nuestro entro, y equivocarse dejaria un comentario
        repetido en una muestra ajena. Se quedan en vuelo y los recoge la
        purga al cabo de un mes.
        """
        for row in self.state.orphans(self.name):
            key = row["key"]
            if not key.startswith("upload:"):
                continue
            sha = key.split(":", 1)[1]
            existe = self.is_new(sha)
            if existe is None:
                self.log.warning("huerfano %s: no se pudo consultar; se deja "
                                 "en vuelo", sha[:16])
                continue
            if existe:
                self.log.info("huerfano %s: no llego, se libera para reintento",
                              sha[:16])
                self.state.abort_send(self.name, key)
            else:
                self.log.info("huerfano %s: VirusTotal ya lo tiene, se da por "
                              "enviado", sha[:16])
                self.state.commit_send(self.name, key, "enviado",
                                       "confirmado con la consulta tras corte")

    # ------------------------------------------------------------------
    def upload(self, sample: Sample) -> bool:
        """Sube la muestra. Es el paso que nos hace first submitter."""
        if not self.is_enabled():
            return False

        if sample.size > BIG_FILE_BYTES:
            # Ficheros grandes necesitan una URL dedicada. No se inventa el
            # flujo: se pide y, si no llega, no se sube.
            resp = self.http.request(self.name, "GET", f"{API}/files/upload_url",
                                     headers=self._headers(), allow_in_dry_run=True)
            url = (resp.json() or {}).get("data") if resp.ok else None
            if not url:
                self.state.reject(self.name, sample.sha256, "tamano",
                                  f"{sample.size} bytes y no se obtuvo upload_url")
                return False
        else:
            url = f"{API}/files"

        def _post():
            with open(sample.path, "rb") as fh:
                return self.http.request(
                    self.name, "POST", url, headers={"x-apikey": self.api_key},
                    files={"file": (sample.sha256, fh, "application/octet-stream")},
                    crea_recurso=True)

        resp = self.send(f"upload:{sample.sha256}", _post,
                         detail=f"{sample.size} bytes de {sample.source}")
        return bool(resp and resp.ok)

    # ------------------------------------------------------------------
    def verdict(self, sha256: str) -> dict:
        """Resume el informe: detecciones, familias, antiguedad y estado.

        Lanza LookupError si VirusTotal no responde, para que quien llame no
        confunda "no lo se" con "no es malware".
        """
        data = self.lookup(sha256)
        if data is None:
            return {"conocido": False, "completed": False, "malicious": 0,
                    "suspicious": 0, "familias": [], "consenso": 0, "adware": False,
                    "etiquetas": [], "first_submission": None,
                    "vhash": None, "ssdeep": None}

        attrs = data.get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        results = attrs.get("last_analysis_results", {}) or {}

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

        # Un motor con veredicto (aunque sea "undetected") significa que el
        # analisis ya corrio. Sin resultados, no hay nada que juzgar.
        completed = bool(results) and (malicious + suspicious +
                                       int(stats.get("undetected", 0) or 0)) > 0

        familias, adware, cuenta = self._families(results)

        # Las etiquetas CRUDAS de cada motor, en minusculas. No se usan para
        # clasificar ---para eso estan las familias, que aplican vocabulario---
        # sino para poder buscar en ellas por coincidencia parcial: es la unica
        # forma de ver un "Virus.Win32.Sality" o un "Ransom.WannaCrypt.B" cuyo
        # nombre no encaje con ningun token del vocabulario.
        etiquetas = sorted({
            ((r or {}).get("result") or "").lower()
            for r in results.values() if (r or {}).get("result")
        })
        first_sub = attrs.get("first_submission_date")

        return {
            "conocido": True,
            "completed": completed,
            "malicious": malicious,
            "suspicious": suspicious,
            # Ya vienen ordenadas por consenso: no reordenar aqui.
            "familias": familias,
            # Motores que coinciden en la familia PRINCIPAL, que es justo la
            # que se acaba publicando. Es lo que mide la puerta.
            "consenso": (cuenta[familias[0]] if familias else 0),
            "adware": adware,
            "etiquetas": etiquetas,
            "first_submission": (
                datetime.fromtimestamp(int(first_sub), tz=timezone.utc)
                if first_sub else None),
            # NO VERIFICADO: vhash y ssdeep no siempre vienen en el informe.
            # Se guardan si estan; su ausencia no bloquea nada, solo deja la
            # capa 3 de unicidad sin cubrir para esa muestra.
            "vhash": attrs.get("vhash"),
            "ssdeep": attrs.get("ssdeep"),
        }

    @staticmethod
    def _families(results: dict) -> tuple[list[str], bool, dict[str, int]]:
        """Familias concretas ORDENADAS POR CUANTOS MOTORES LAS NOMBRAN.

        El orden importa: quien llama toma la primera como familia principal,
        y con ella se etiqueta la muestra en MalwareBazaar y se elige el nombre
        de Malpedia en ThreatFox. Ordenar alfabeticamente haria que un Mirai
        que dos motores llaman "gafgyt" acabara publicado como gafgyt.
        """
        cuenta: dict[str, int] = {}
        adware_hits = total_hits = 0

        for engine_result in results.values():
            nombre = (engine_result or {}).get("result") or ""
            if not nombre:
                continue
            total_hits += 1
            bajo = nombre.lower()
            if any(h in bajo for h in _ADWARE_HINTS):
                adware_hits += 1
            # set() para que un motor que repite el nombre en su cadena
            # ("Linux.Mirai.Mirai") no cuente dos veces.
            for token in set(_TOKEN_RE.findall(bajo)):
                if (token in KNOWN_FAMILIES
                        or (token not in GENERICOS
                            and len(token) >= MIN_LARGO_FAMILIA)):
                    cuenta[token] = cuenta.get(token, 0) + 1

        # "Dominante" es la mitad o mas de los motores que dicen algo. Un par
        # de motores marcando PUP no convierte un Mirai en adware.
        adware = total_hits > 0 and adware_hits >= max(3, total_hits // 2)
        # Al desempatar mandan, por este orden: cuantos motores lo nombran, si
        # es una familia que ya conocemos, y el largo del nombre. Los dos
        # ultimos son por el sufijo de variante: viaja en la misma cadena que
        # la familia, asi que empata con ella, y sin esto un "Mirai-ABCD" se
        # publicaria como "abcd". El orden alfabetico va al final, solo para
        # que el resultado sea siempre el mismo.
        familias = sorted(cuenta, key=lambda f: (-cuenta[f],
                                                 f not in KNOWN_FAMILIES,
                                                 -len(f), f))
        return familias, adware, cuenta

    # ------------------------------------------------------------------
    def motivo_rechazo(self, sha256: str, v: dict) -> str | None:
        """La puerta de EVIDENCIA: si esto es malware de verdad o no.

        Devuelve el nombre de la puerta que no pasa, o None si pasan todas.
        Cada rechazo queda registrado con su motivo.

        LA FAMILIA YA NO ESTA AQUI, y es el cambio que mas cosas destapa. Era
        una puerta unica: si fallaba, quien llama abandonaba la muestra entera
        y con ella se caian LAS CINCO plataformas ---el voto en VirusTotal, la
        subida a MalwareBazaar, la URL a URLhaus, el IOC a ThreatFox y la
        denuncia del servidor que sirvio el binario---. Pero de esas cinco,
        solo MalwareBazaar y ThreatFox necesitan un nombre de familia; a las
        otras tres no se les pide ninguno. Un nombre que no supieramos poner
        apagaba tres publicaciones perfectamente defendibles.

        Ahora la familia se exige donde hace falta, en cada uno de esos dos.
        """
        if not self.gate(sha256, "veredicto", v["conocido"],
                         "VirusTotal aun no conoce la muestra"):
            return "veredicto"
        if not self.gate(sha256, "veredicto", v["completed"],
                         "el analisis todavia no ha terminado"):
            return "veredicto"
        if not self.gate(sha256, "deteccion", v["malicious"] >= self.min_malicious,
                         f"{v['malicious']} motores maliciosos, "
                         f"hacen falta {self.min_malicious}"):
            return "deteccion"
        if not self.gate(sha256, "adware", not v["adware"],
                         "clasificado mayoritariamente como adware o PUP"):
            return "adware"
        return None

    def passes_gate(self, sha256: str, v: dict) -> bool:
        """Lo mismo, en forma de si o no."""
        return self.motivo_rechazo(sha256, v) is None

    def familia_ok(self, reporter, sha256: str, v: dict) -> bool:
        """El consenso de familia, para quien SI necesita nombrarla.

        Se cuentan MOTORES QUE COINCIDEN en la familia principal, no nombres
        distintos. Contar nombres premiaba justo lo contrario de lo que se
        busca: una muestra que todos los motores identifican igual ---un
        WannaCry, por ejemplo--- daba 1 y se rechazaba, mientras que una que
        nadie reconoce, con tres motores adivinando tres cosas distintas, daba
        3 y pasaba. El consenso es la senal; la dispersion de nombres es ruido.
        Y ademas es coherente con lo que se publica: la familia que se manda es
        la primera, asi que la puerta mide exactamente esa.

        El umbral lo guarda VirusTotal, que es quien cuenta el consenso, pero
        el rechazo se anota a `reporter`, que es quien se queda sin publicar.
        Antes todos se apuntaban a VirusTotal ---que ni siquiera pide familia---
        y el parte por plataforma senalaba al inocente.
        """
        principal = v["familias"][0] if v["familias"] else "ninguna"
        return reporter.gate(
            sha256, "familia", v["consenso"] >= self.min_families,
            f"solo {v['consenso']} motores coinciden en la familia "
            f"{principal}, hacen falta {self.min_families}")

    # ------------------------------------------------------------------
    def response_ok(self, resp: Response) -> tuple[bool, str]:
        """Un 409 "ya existe" NO es un rechazo: es que ya estaba puesto.

        VirusTotal contesta asi cuando se vuelve a votar o a comentar algo que
        esta cuenta ya voto o comento:

            HTTP 409 {"code": "AlreadyExistsError",
                      "message": "User X already voted malicious for this file"}

        Tratarlo como rechazo tenia dos consecuencias, y las dos malas:

          - Contaba en "RECHAZADAS POR LA PLATAFORMA", que es la unica linea
            del resumen diario que pide mirar el mismo dia. Una alarma que
            salta por algo que esta bien es una alarma que se deja de mirar.
          - Y como no se anotaba en `sent`, la muestra volvia a intentarlo en
            cada rechequeo: mas 409, y una llamada de API tirada cada vez.

        El resultado que se buscaba ---nuestro voto en esa muestra--- ESTA. Se
        da por bueno y se apunta, que es lo que evita repetirlo.
        """
        if resp.status == 409:
            cuerpo = resp.json_body if isinstance(resp.json_body, dict) else {}
            codigo = str((cuerpo.get("error") or {}).get("code", ""))
            if codigo == "AlreadyExistsError" or "AlreadyExists" in resp.text:
                return True, ""
        return super().response_ok(resp)

    def comment_and_vote(self, sample: Sample, v: dict) -> bool:
        """Comentario firmado y voto malicioso. Solo tras pasar la puerta."""
        if not self.is_enabled():
            return False

        texto = self._comment_text(sample, v)
        # El comentario es texto libre que puede arrastrar la URL de descarga:
        # pasa por la barrera de texto antes de salir.
        cuerpo = {"data": {"type": "comment", "attributes": {"text": texto}}}
        resp = self.send(
            f"comment:{sample.sha256}",
            lambda: self.http.request(
                self.name, "POST", f"{API}/files/{sample.sha256}/comments",
                headers=self._headers(), json_body=cuerpo, crea_recurso=True),
            texts=(texto,), detail="comentario")

        voto = {"data": {"type": "vote", "attributes": {"verdict": "malicious"}}}
        self.send(
            f"vote:{sample.sha256}",
            lambda: self.http.request(
                self.name, "POST", f"{API}/files/{sample.sha256}/votes",
                headers=self._headers(), json_body=voto, crea_recurso=True),
            detail="voto malicioso")

        return bool(resp and resp.ok)

    # ARQUITECTURAS DE EMPOTRADO. Un ELF para MIPS, ARM de 32 bits, SuperH o
    # SPARC capturado en un honeypot de SSH/telnet es malware de IoT por
    # cualquier lectura razonable: son las CPU de routers, camaras y grabadores.
    # x86_64 y aarch64 NO estan: hoy son las de cualquier servidor o VPS.
    ARQ_EMPOTRADO = {"mips", "arm", "superh", "sparc", "ppc", "m32r", "m32c"}

    # Familias de botnet de IoT confirmadas. Es la misma lista que usa el mapa
    # de Malpedia de threatfox.py, y por el mismo motivo: lo que no este aqui
    # no se afirma.
    FAMILIAS_IOT = {"mirai", "bashlite", "gafgyt", "tsunami", "mozi", "hajime",
                    "muhstik", "dofloo", "xorddos"}

    @classmethod
    def _es_iot(cls, sample: Sample, v: dict) -> bool:
        """Si podemos SOSTENER que la muestra es malware de IoT.

        Antes se ponia "#iot" en TODOS los comentarios, pasara lo que pasara.
        Un XMRig o un Kinsing para x86_64 ---mineria en servidores en la nube,
        que es lo que mas se ve--- salia publicado como malware de IoT en una
        plataforma que consulta medio mundo. Es el mismo error que la categoria
        23 de AbuseIPDB, y se corrige igual: solo se afirma con evidencia.
        """
        if (sample.elf_machine or "") in cls.ARQ_EMPOTRADO:
            return True
        return any(f.lower() in cls.FAMILIAS_IOT for f in v.get("familias") or [])

    def _comment_text(self, sample: Sample, v: dict) -> str:
        """Comentario factual: que se vio, donde y cuando. Sin adjetivos.

        EN INGLES, y no por gusto. Es un comentario publico y permanente en
        una plataforma internacional: escribirlo en castellano ata el honeypot
        a un operador hispanohablante, y la maquina se presenta como un equipo
        ucraniano. La lengua del texto es tan identificativa como una IP.

        No se incluye la IP de origen del atacante aunque la tengamos: la
        atribucion no aporta nada al analisis del binario.
        """
        familias = ", ".join(v["familias"]) or "unidentified"
        arch = sample.elf_machine or "non-ELF"
        # El protocolo concreto si el log lo dijo; si no, los dos que sirve
        # Cowrie. Decir "SSH/Telnet" cuando sabemos que fue telnet es impreciso
        # en un texto que queda publicado para siempre.
        # El servicio concreto por el que llego la muestra. La tabla vive en
        # common/model.py y la comparten los dos reporters que publican esto:
        # antes cada uno llevaba la suya y decia "SMB/RPC/MSSQL" o "SSH/Telnet"
        # en TODAS las muestras, que era falso en cuanto no fueran las tres.
        articulo, servicio = servicio_de(sample)
        protocolo = f"{articulo} {servicio}"
        partes = [
            f"Captured by {protocolo} honeypot on "
            f"{sample.seen_at.strftime('%Y-%m-%d')}.",
            f"Architecture: {arch}. Size: {sample.size} bytes.",
            f"Families per VirusTotal: {familias} "
            f"({v['malicious']} malicious engines).",
        ]
        if sample.download_url:
            partes.append(f"Served from: {sample.download_url}")
        etiquetas = "#malware #honeypot"
        if self._es_iot(sample, v):
            etiquetas += " #iot"
        if self.attribution_tag:
            etiquetas += " " + self.attribution_tag
        partes.append(etiquetas)
        return " ".join(partes)
