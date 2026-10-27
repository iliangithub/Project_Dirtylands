# SPDX-License-Identifier: GPL-2.0-or-later
"""Lectura de los honeypots. Traducen sus logs al modelo comun.

Un collector no sabe que existen las plataformas de reporte: su unica salida
es el modelo de common/model.py. Ahi esta la razon de que un mismo reporter
sirva para Cowrie y para Dionaea sin un solo condicional por honeypot.
"""

from __future__ import annotations

# A partir de cuantos eventos descartados sin salvar ni uno empezamos a
# sospechar. Por debajo puede ser simple falta de trafico.
_MINIMO_PARA_SOSPECHAR = 20


def avisar_si_todo_descartado(log, recogidos: int, descartados: dict[str, int]) -> None:
    """Detecta el caso en que NADA es reportable por no ser direcciones globales.

    Es un fallo que no da ningun error: si Docker enmascara la IP de origen,
    todos los atacantes llegan como la puerta de enlace del bridge (172.x.x.1),
    la barrera los descarta correctamente por no ser una direccion global, y el
    reporter informa de cero atacantes para siempre sin que nada falle. Se
    llevarian semanas sin reportar nada creyendo que no hay trafico.

    Con el honeypot todavia sellado esto es normal, porque el unico trafico es
    el de nuestras propias pruebas desde el host. Por eso es un aviso y no un
    error: lo que hace es que la pregunta se plantee, en vez de pasar en
    silencio.
    """
    total = sum(descartados.values())
    if recogidos or total < _MINIMO_PARA_SOSPECHAR:
        return

    from common.ipguard import MOTIVO_NO_GLOBAL
    no_globales = sum(n for motivo, n in descartados.items()
                      if motivo == MOTIVO_NO_GLOBAL)
    if no_globales < total / 2:
        return

    log.warning(
        "los %d eventos vistos se descartaron por no ser direcciones globales y "
        "no queda ni un atacante reportable. Si el senuelo YA esta expuesto, "
        "revisa que Docker no este enmascarando la IP de origen: con "
        "userland-proxy activado todas las conexiones llegan como la puerta de "
        "enlace del bridge y nunca se reportara nada. Compruebalo con: "
        "grep -o '\"src_ip\": *\"[^\"]*\"' en el log del honeypot; si sale una "
        "sola IP 172.x.x.1, es eso. Si el senuelo aun no esta expuesto, este "
        "aviso es normal: solo estas viendo tus propias pruebas.", total)
