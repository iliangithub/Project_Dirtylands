# SPDX-License-Identifier: GPL-2.0-or-later
"""
Estado persistente: unicidad, idempotencia, cuotas y auditoria de rechazos.

Una sola base SQLite con varias tablas, y no una base por plataforma. El motivo
es la idempotencia: marcar un envio y consumir su cuota tienen que ocurrir en
la MISMA transaccion, y eso solo se puede garantizar dentro de un unico
fichero. Con bases separadas siempre existiria el hueco de "enviado pero sin
contabilizar".

Idempotencia en dos fases, que es la respuesta a "que pasa si el proceso muere
a mitad":

    begin_send()   escribe la intencion y hace COMMIT  ->  antes del POST
    commit_send()  marca el envio como confirmado      ->  despues del POST

Si el proceso muere entre ambas, al arrancar queda una fila "en vuelo" con
resultado desconocido. Esa fila NO se reintenta a ciegas: se marca para que el
reporter consulte a la plataforma si el envio llego (por ejemplo, con el
get_info de MalwareBazaar) antes de decidir. Reenviar por defecto es
exactamente como se generan los duplicados.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import log

_log = log.get("state")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sent (
    platform   TEXT NOT NULL,
    key        TEXT NOT NULL,
    status     TEXT NOT NULL,
    sent_at    TEXT NOT NULL,
    detail     TEXT,
    PRIMARY KEY (platform, key)
);
CREATE TABLE IF NOT EXISTS inflight (
    platform   TEXT NOT NULL,
    key        TEXT NOT NULL,
    started_at TEXT NOT NULL,
    PRIMARY KEY (platform, key)
);
-- Cola del rechequeo diferido: una muestra vive aqui hasta que VirusTotal
-- emite veredicto o hasta que se agota su plazo.
CREATE TABLE IF NOT EXISTS samples (
    sha256          TEXT PRIMARY KEY,
    source          TEXT,
    path            TEXT,
    state           TEXT NOT NULL,
    first_local     TEXT NOT NULL,
    vt_first_sub    TEXT,
    vt_malicious    INTEGER,
    vt_suspicious   INTEGER,
    family          TEXT,
    arch            TEXT,
    campaign_key    TEXT,
    cluster_key     TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_check      TEXT,
    updated_at      TEXT NOT NULL
);
-- Capa 3: un binario por clan de similitud (vhash / ssdeep de VirusTotal).
CREATE TABLE IF NOT EXISTS clusters (
    cluster_key TEXT NOT NULL,
    platform    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    sent_at     TEXT NOT NULL,
    PRIMARY KEY (cluster_key, platform)
);
-- Capa 4: un binario por (familia, campana, arquitectura).
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_key TEXT NOT NULL,
    platform     TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    sent_at      TEXT NOT NULL,
    PRIMARY KEY (campaign_key, platform)
);
-- PUBLICACIONES por dia. Es lo que miran los topes de MalwareBazaar (5 al
-- dia, 20 a la semana), que cuentan subidas, no llamadas.
CREATE TABLE IF NOT EXISTS quota (
    platform TEXT NOT NULL,
    day      TEXT NOT NULL,
    used     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (platform, day)
);
-- Lo MISMO, pero de la simulacion, y en una tabla aparte a proposito. Un
-- envio simulado no ha consumido nada en la plataforma, asi que no puede
-- gastar la cuota real: si lo hiciera, unos dias de pruebas dejarian a
-- MalwareBazaar creyendo que ya subio sus 20 de la semana.
CREATE TABLE IF NOT EXISTS quota_sim (
    platform TEXT NOT NULL,
    day      TEXT NOT NULL,
    used     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (platform, day)
);
-- LLAMADAS a la API por dia, publicaciones y consultas por igual. Es una
-- cuenta distinta de la anterior y hace falta: el limite de VirusTotal son
-- 500 peticiones diarias e incluye las consultas de hash, que son las mas
-- frecuentes con diferencia. Contando solo las publicaciones se puede agotar
-- la cuota real con el contador marcando tres.
CREATE TABLE IF NOT EXISTS api_calls (
    platform TEXT NOT NULL,
    day      TEXT NOT NULL,
    calls    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (platform, day)
);
-- Por que NO se reporto algo. Tan importante como el registro de lo enviado.
CREATE TABLE IF NOT EXISTS rejections (
    ts       TEXT NOT NULL,
    platform TEXT NOT NULL,
    key      TEXT NOT NULL,
    gate     TEXT NOT NULL,
    reason   TEXT NOT NULL
);
-- Sin este indice, el cortacircuitos recorre la tabla entera cada vez que
-- abuse.ch rechaza algo, y esa tabla crece unas 6000 filas al dia.
CREATE INDEX IF NOT EXISTS ix_rejections_ts ON rejections (ts);
CREATE INDEX IF NOT EXISTS ix_sent_at ON sent (platform, sent_at);
-- Cortacircuitos por CUENTA, no por plataforma. MalwareBazaar, ThreatFox y
-- URLhaus comparten la misma cuenta de abuse.ch: una sancion en cualquiera de
-- ellas se lleva por delante las tres. Cuando salta, se queda saltado hasta
-- que una persona lo rearma a mano.
CREATE TABLE IF NOT EXISTS breaker (
    account    TEXT PRIMARY KEY,
    tripped_at TEXT NOT NULL,
    reason     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rej ON rejections (ts, platform);
CREATE INDEX IF NOT EXISTS idx_samples_state ON samples (state, next_check);
"""

# Estados de una muestra en la cola
PENDING_VERDICT = "pendiente_de_veredicto"
PUBLISHED = "publicado"
DISCARDED = "descartado"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


class State:
    def __init__(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------------------------------------------------------------- envios
    def already_sent(self, platform: str, key: str,
                     contar_simulados: bool = True) -> bool:
        """Ya se envio esto?

        `contar_simulados` no es un adorno. La simulacion tambien escribe en
        `sent`, con estado "simulado", para poder ensenar el comportamiento
        real de la deduplicacion. Pero un envio simulado no existio: si contara
        como enviado al pasar a --live, todo lo recogido durante los dias de
        prueba saldria como "ya enviado anteriormente" y no se publicaria
        jamas. Cuanto mas se simulase, menos se reportaria.

        Por eso el modo real pasa False: solo los envios de verdad bloquean.
        La simulacion pasa True, para que lo que ensena siga siendo fiel.
        """
        sql = ("SELECT 1 FROM sent WHERE platform=? AND key=?"
               + ("" if contar_simulados else " AND status<>'simulado'"))
        return self.db.execute(sql, (platform, key)).fetchone() is not None

    def last_sent_at(self, platform: str, patron_clave: str,
                     contar_simulados: bool = True) -> datetime | None:
        """Fecha del ultimo envio cuya clave case con `patron_clave` (LIKE).

        Vive aqui, y no en el reporter que la necesita, para que la regla de
        "un simulado no cuenta como enviado" se escriba UNA sola vez. Estaba
        duplicada en la ventana de enfriamiento de AbuseIPDB, y alli se habia
        olvidado mirar el estado: IPs denunciadas solo en simulacion quedaban
        en cuarentena 24 h de verdad.
        """
        sql = ("SELECT sent_at FROM sent WHERE platform=? AND key LIKE ?"
               + ("" if contar_simulados else " AND status<>'simulado'")
               + " ORDER BY sent_at DESC LIMIT 1")
        row = self.db.execute(sql, (platform, patron_clave)).fetchone()
        if not row:
            return None
        try:
            return datetime.fromisoformat(row["sent_at"])
        except (TypeError, ValueError):
            return None

    def begin_send(self, platform: str, key: str) -> None:
        """Registra la intencion ANTES del POST y confirma en disco."""
        self.db.execute(
            "INSERT OR REPLACE INTO inflight (platform, key, started_at) VALUES (?,?,?)",
            (platform, key, _iso(_now())))
        self.db.commit()

    def commit_send(self, platform: str, key: str, status: str, detail: str = "") -> None:
        """Confirma el envio y consume cuota, todo en una sola transaccion."""
        day = _now().strftime("%Y-%m-%d")
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO sent (platform, key, status, sent_at, detail)"
                " VALUES (?,?,?,?,?)", (platform, key, status, _iso(_now()), detail))
            self.db.execute("DELETE FROM inflight WHERE platform=? AND key=?", (platform, key))
            tabla = "quota_sim" if status == "simulado" else "quota"
            self.db.execute(
                f"INSERT INTO {tabla} (platform, day, used) VALUES (?,?,1)"
                f" ON CONFLICT(platform, day) DO UPDATE SET used = used + 1",
                (platform, day))

    def set_detail(self, platform: str, key: str, detail: str) -> bool:
        """Reescribe el `detail` de un envio ya confirmado.

        Existe para lo que solo se sabe DESPUES de publicar: por ejemplo, si
        ThreatFox creo un indicador nuevo o lo fundio con uno que ya tenia.

        No se hace llamando otra vez a commit_send() aunque parezca lo mismo:
        commit_send consume cuota, y repetirlo apuntaria un envio de mas por
        cada verificacion. Este metodo toca `detail` y nada mas.
        """
        with self.db:
            cur = self.db.execute(
                "UPDATE sent SET detail=? WHERE platform=? AND key=?",
                (detail, platform, key))
        return cur.rowcount > 0

    def abort_send(self, platform: str, key: str) -> None:
        """El POST fallo de forma conocida: se retira la intencion."""
        with self.db:
            self.db.execute("DELETE FROM inflight WHERE platform=? AND key=?", (platform, key))

    def en_vuelo(self, platform: str, key: str) -> str | None:
        """Cuando se empezo a enviar esto y quedo sin resolver, o None.

        Sirve para NO reenviar lo que ya salio una vez sin respuesta clara. La
        alternativa ---mirar solo la tabla `sent`--- deja un agujero conocido:
        si el envio no llego a anotarse ahi, el enfriamiento no tiene de que
        agarrarse y la pasada siguiente vuelve a publicar lo mismo. Paso el
        2026-08-27 con 103.29.185.162, denunciada dos veces en catorce minutos.
        """
        fila = self.db.execute(
            "SELECT started_at FROM inflight WHERE platform=? AND key=?",
            (platform, key)).fetchone()
        return fila["started_at"] if fila else None

    def orphans(self, platform: str | None = None) -> list[sqlite3.Row]:
        """Envios en vuelo de una ejecucion anterior: resultado desconocido."""
        if platform:
            return self.db.execute(
                "SELECT * FROM inflight WHERE platform=?", (platform,)).fetchall()
        return self.db.execute("SELECT * FROM inflight").fetchall()

    # ---------------------------------------------------------------- cuotas
    def quota_used(self, platform: str, day: str | None = None,
                   contar_simulados: bool = False) -> int:
        day = day or _now().strftime("%Y-%m-%d")
        total = 0
        for tabla in ["quota"] + (["quota_sim"] if contar_simulados else []):
            row = self.db.execute(
                f"SELECT used FROM {tabla} WHERE platform=? AND day=?",
                (platform, day)).fetchone()
            total += row["used"] if row else 0
        return total

    def count_sent(self, platform: str, prefijo: str, dias: int = 0,
                   contar_simulados: bool = False) -> int:
        """Envios confirmados cuya clave empieza por `prefijo`.

        Existe porque los topes de MalwareBazaar cuentan SUBIDAS, y desde que
        cada subida lleva ademas su comentario de atribucion, contar filas de
        `sent` a secas dejaria el tope diario de 5 en dos muestras y media.
        El prefijo separa una cosa de la otra.
        """
        sql = "SELECT COUNT(*) AS n FROM sent WHERE platform=? AND key LIKE ?"
        params: list = [platform, prefijo + "%"]
        if dias > 0:
            sql += " AND sent_at >= ?"
            params.append(_iso(_now() - timedelta(days=dias)))
        else:
            sql += " AND date(sent_at) = ?"
            params.append(_now().strftime("%Y-%m-%d"))
        if not contar_simulados:
            sql += " AND status<>'simulado'"
        return self.db.execute(sql, params).fetchone()["n"]

    def note_call(self, platform: str) -> None:
        """Apunta UNA llamada a la API. La invoca el transporte, para que no
        haya forma de gastar cuota sin que quede contada."""
        day = _now().strftime("%Y-%m-%d")
        with self.db:
            self.db.execute(
                "INSERT INTO api_calls (platform, day, calls) VALUES (?,?,1)"
                " ON CONFLICT(platform, day) DO UPDATE SET calls = calls + 1",
                (platform, day))

    def calls_today(self, platform: str) -> int:
        row = self.db.execute(
            "SELECT calls FROM api_calls WHERE platform=? AND day=?",
            (platform, _now().strftime("%Y-%m-%d"))).fetchone()
        return row["calls"] if row else 0

    def quota_used_since(self, platform: str, days: int,
                         contar_simulados: bool = False) -> int:
        floor = (_now() - timedelta(days=days)).strftime("%Y-%m-%d")
        total = 0
        for tabla in ["quota"] + (["quota_sim"] if contar_simulados else []):
            row = self.db.execute(
                f"SELECT COALESCE(SUM(used),0) AS n FROM {tabla}"
                f" WHERE platform=? AND day>=?", (platform, floor)).fetchone()
            total += row["n"]
        return total

    # ------------------------------------------------------- capas 3 y 4
    def cluster_taken(self, cluster_key: str, platform: str) -> str | None:
        if not cluster_key:
            return None
        row = self.db.execute(
            "SELECT sha256 FROM clusters WHERE cluster_key=? AND platform=?",
            (cluster_key, platform)).fetchone()
        return row["sha256"] if row else None

    def campaign_taken(self, campaign_key: str, platform: str,
                       window_days: int = 30) -> str | None:
        floor = _iso(_now() - timedelta(days=window_days))
        row = self.db.execute(
            "SELECT sha256 FROM campaigns WHERE campaign_key=? AND platform=? AND sent_at>=?",
            (campaign_key, platform, floor)).fetchone()
        return row["sha256"] if row else None

    def claim_uniqueness(self, platform: str, sha256: str,
                         cluster_key: str | None, campaign_key: str | None) -> None:
        """Reserva el clan y la campana para esta muestra, tras publicarla."""
        now = _iso(_now())
        with self.db:
            if cluster_key:
                self.db.execute(
                    "INSERT OR IGNORE INTO clusters (cluster_key, platform, sha256, sent_at)"
                    " VALUES (?,?,?,?)", (cluster_key, platform, sha256, now))
            if campaign_key:
                self.db.execute(
                    "INSERT OR IGNORE INTO campaigns (campaign_key, platform, sha256, sent_at)"
                    " VALUES (?,?,?,?)", (campaign_key, platform, sha256, now))

    # ------------------------------------------------------- capa 5: rafaga
    def burst_count(self, campaign_key: str, arch: str | None,
                    minutes: int = 60) -> int:
        """Cuantas muestras de la misma campana y arquitectura hemos visto ya."""
        floor = _iso(_now() - timedelta(minutes=minutes))
        row = self.db.execute(
            "SELECT COUNT(*) AS n FROM samples"
            " WHERE campaign_key=? AND IFNULL(arch,'')=? AND first_local>=?",
            (campaign_key, arch or "", floor)).fetchone()
        return row["n"]

    # ---------------------------------------------------- cola de muestras
    def upsert_sample(self, sha256: str, **fields) -> None:
        fields.setdefault("updated_at", _iso(_now()))
        row = self.db.execute("SELECT 1 FROM samples WHERE sha256=?", (sha256,)).fetchone()
        with self.db:
            if row:
                cols = ", ".join(f"{k}=?" for k in fields)
                self.db.execute(f"UPDATE samples SET {cols} WHERE sha256=?",
                                (*fields.values(), sha256))
            else:
                fields.setdefault("state", PENDING_VERDICT)
                fields.setdefault("first_local", _iso(_now()))
                cols = ", ".join(["sha256", *fields])
                marks = ", ".join("?" * (len(fields) + 1))
                self.db.execute(f"INSERT INTO samples ({cols}) VALUES ({marks})",
                                (sha256, *fields.values()))

    def get_sample(self, sha256: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()

    def due_samples(self, limit: int = 50) -> list[sqlite3.Row]:
        """Muestras cuyo rechequeo diferido ya toca."""
        return self.db.execute(
            "SELECT * FROM samples WHERE state=? AND (next_check IS NULL OR next_check<=?)"
            " ORDER BY first_local LIMIT ?",
            (PENDING_VERDICT, _iso(_now()), limit)).fetchall()

    def censo_muestras(self) -> dict:
        """Cuantas muestras hay retenidas, y cuando toca la primera.

        Nace de una pasada real que termino asi: 70 binarios recogidos, 0
        enviados, 0 rechazos de muestra, y NI UNA LINEA que dijera por que.
        Las muestras estaban esperando su rechequeo diferido, que es lo
        correcto ---hay que darle tiempo a los motores--- pero desde fuera
        era indistinguible de un fallo nuestro. Se mira sin filtrar por
        fecha: es un censo, no un listado.
        """
        fila = self.db.execute(
            "SELECT COUNT(*) AS n, MIN(next_check) AS proxima FROM samples"
            " WHERE state=? AND next_check IS NOT NULL AND next_check>?",
            (PENDING_VERDICT, _iso(_now()))).fetchone()
        por_estado = {
            r["state"]: r["n"] for r in self.db.execute(
                "SELECT state, COUNT(*) AS n FROM samples GROUP BY state")
        }
        return {"esperando": fila["n"] or 0, "proxima": fila["proxima"],
                "por_estado": por_estado}

    def schedule_recheck(self, sha256: str, hours: int) -> None:
        with self.db:
            self.db.execute(
                "UPDATE samples SET next_check=?, attempts=attempts+1, updated_at=?"
                " WHERE sha256=?",
                (_iso(_now() + timedelta(hours=hours)), _iso(_now()), sha256))

    # ------------------------------------------------------------ rechazos
    def reject(self, platform: str, key: str, gate: str, reason: str) -> None:
        """Deja constancia de por que NO se reporto algo."""
        with self.db:
            self.db.execute(
                "INSERT INTO rejections (ts, platform, key, gate, reason) VALUES (?,?,?,?,?)",
                (_iso(_now()), platform, key, gate, reason))
        _log.info("rechazado [%s/%s] %s: %s", platform, gate, key[:16], reason)

    def count_rejections(self, platforms: tuple[str, ...], gate: str,
                         hours: int) -> int:
        """Rechazos recientes de un grupo de plataformas. Alimenta el cortacircuitos."""
        floor = _iso(_now() - timedelta(hours=hours))
        marcas = ",".join("?" * len(platforms))
        row = self.db.execute(
            f"SELECT COUNT(*) AS n FROM rejections"
            f" WHERE platform IN ({marcas}) AND gate=? AND ts>=?",
            (*platforms, gate, floor)).fetchone()
        return row["n"]

    # ------------------------------------------------------- cortacircuitos
    def trip_breaker(self, account: str, reason: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO breaker (account, tripped_at, reason)"
                " VALUES (?,?,?)", (account, _iso(_now()), reason))
        _log.critical("CORTACIRCUITOS de la cuenta %s: %s", account, reason)

    def breaker(self, account: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM breaker WHERE account=?", (account,)).fetchone()

    def clear_breaker(self, account: str) -> bool:
        with self.db:
            cur = self.db.execute("DELETE FROM breaker WHERE account=?", (account,))
        return cur.rowcount > 0

    def recent_rejections(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM rejections ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()

    def purge(self, dias: int = 30) -> dict[str, int]:
        """Tira el historial que ya no sirve para decidir nada.

        QUE NO SE BORRA, y es lo importante: las filas de `sent` cuya clave
        lleva un hash --- las subidas a VirusTotal y MalwareBazaar ---. Esa
        tabla ES la memoria que impide volver a subir una muestra que ya
        subimos; borrarla seria empezar a duplicar en las plataformas, que es
        justo lo que costo un baneo. Se guardan para siempre, y no ocupan:
        una fila por muestra publicada.

        QUE SI SE BORRA:

        - `rejections`, que es solo auditoria. La misma IP en enfriamiento
          deja una fila cada quince minutos, 96 al dia, diciendo lo mismo. El
          cortacircuitos mira 24 h y --show-rejections las ultimas; nada
          consulta mas atras.
        - Las filas de AbuseIPDB en `sent`, cuya clave es "ip@fecha". Ahi el
          historial no decide nada: la ventana de enfriamiento son 24 h.
        - Los contadores de cuota por dia, de los que solo hacen falta los
          siete ultimos (el tope semanal de MalwareBazaar).

        `samples` no se toca: esta acotada por el numero de muestras distintas
        que hemos visto, y ademas es la cola de rechequeo.
        """
        # 0 (o negativo) DESACTIVA la purga. Es la lectura que espera
        # cualquiera que escriba un 0 ahi, y sin esta guarda haria lo contrario:
        # el corte seria "ahora" y se llevaria por delante hasta las denuncias
        # de hoy, que son las que sostienen el enfriamiento de 24 h.
        if dias <= 0:
            return {}

        corte = _iso(_now() - timedelta(days=dias))
        borrado: dict[str, int] = {}
        with self.db:
            cur = self.db.execute("DELETE FROM rejections WHERE ts < ?", (corte,))
            borrado["rejections"] = cur.rowcount
            cur = self.db.execute(
                "DELETE FROM sent WHERE platform='abuseipdb' AND sent_at < ?", (corte,))
            borrado["sent (abuseipdb)"] = cur.rowcount
            # Los envios en vuelo que nadie ha sabido resolver. Cada
            # plataforma que sepa preguntar los resuelve en resolve_orphans;
            # esto se lleva los que quedan, y solo los MUY viejos.
            #
            # Borrarlos vuelve a permitir enviar esa clave, asi que el plazo
            # es el largo a proposito: pasado un mes, o aquello llego ---y
            # reenviarlo no cambia nada, porque las plataformas ya lo tienen
            # y sus propias ventanas de duplicado son mucho mas cortas--- o no
            # llego y hace tiempo que deberia haberse reintentado. Lo que no
            # puede quedarse es una fila bloqueando una clave para siempre.
            cur = self.db.execute("DELETE FROM inflight WHERE started_at < ?",
                                  (corte,))
            borrado["inflight (sin resolver)"] = cur.rowcount
            corte_dia = (_now() - timedelta(days=max(dias, 60))).strftime("%Y-%m-%d")
            n = 0
            for tabla in ("quota", "quota_sim", "api_calls"):
                n += self.db.execute(
                    f"DELETE FROM {tabla} WHERE day < ?", (corte_dia,)).rowcount
            borrado["contadores"] = n

        total = sum(borrado.values())
        if total:
            _log.info("purga: %s",
                      ", ".join(f"{k}={v}" for k, v in borrado.items() if v))
        # SQLite no devuelve el espacio al borrar. Compactar cuesta tiempo y
        # disco, asi que solo se hace cuando de verdad ha sobrado mucho: en la
        # practica, la primera limpieza despues de meses sin ninguna.
        if total > 20000:
            _log.info("purga: compactando la base (%d filas retiradas)", total)
            self.db.execute("VACUUM")
        return borrado

    def close(self) -> None:
        self.db.close()
