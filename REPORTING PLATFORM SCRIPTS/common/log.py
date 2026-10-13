# SPDX-License-Identifier: GPL-2.0-or-later
"""
Registro con redaccion obligatoria.

Se llama log.py y no logging.py a proposito: un modulo llamado igual que el de
la biblioteca estandar dentro del mismo arbol es una fuente segura de
confusion al leer los imports, aunque Python 3 lo resuelva bien.

La redaccion no es cosmetica. El log acaba en ficheros que se copian, se pegan
en informes y se comparten; una clave de API o la IP de administracion que se
cuele ahi ya no se recupera. Por eso el filtro va montado en el propio handler:
no depende de que quien escriba una traza se acuerde de sanear.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path

_SECRET_PATTERNS: list[re.Pattern] = []
_SECRET_LITERALS: set[str] = set()

# Formatos de clave conocidos. Se redactan aunque nadie las haya registrado
# como secreto, por si alguna aparece en el cuerpo de una respuesta de error.
_KEY_SHAPES = [
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{30,}"),     # token de bot Telegram
    re.compile(r"(?i)\b(auth-key|api[-_]?key|x-apikey|bot_token)\b\s*[:=]\s*\S+"),
]


def register_secret(value: str | None) -> None:
    """Marca un valor como secreto: no volvera a aparecer en el log."""
    if value and len(value.strip()) >= 8:
        _SECRET_LITERALS.add(value.strip())


def register_secret_pattern(pattern: str) -> None:
    _SECRET_PATTERNS.append(re.compile(pattern))


def redact(text: str) -> str:
    """Elimina secretos de una linea. Idempotente y sin excepciones."""
    if not text:
        return text
    for literal in _SECRET_LITERALS:
        if literal in text:
            text = text.replace(literal, "[REDACTED]")
    for pat in _KEY_SHAPES + _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


class _RedactingFilter(logging.Filter):
    """Redacta el mensaje ya formateado, con argumentos incluidos."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            record.msg = "[linea no registrable: fallo al redactar]"
            record.args = ()
        return True


def setup(log_file: Path | str | None, level: str = "INFO",
          also_stdout: bool = True) -> logging.Logger:
    """Configura el logger raiz del proyecto y devuelve el nuestro."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    redactor = _RedactingFilter()

    if log_file:
        path = Path(log_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                path, maxBytes=10_000_000, backupCount=5, encoding="utf-8")
            fh.setFormatter(fmt)
            fh.addFilter(redactor)
            root.addHandler(fh)
        except OSError as exc:      # sin log a fichero seguimos, pero se avisa
            print(f"[aviso] no se pudo abrir {path}: {exc}")

    if also_stdout or not log_file:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.addFilter(redactor)
        root.addHandler(sh)

    return logging.getLogger("dirtyland")


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"dirtyland.{name}")
