# SPDX-License-Identifier: GPL-2.0-or-later
"""Un modulo por plataforma. Cada uno sirve a los dos honeypots.

Ninguno sabe de que honeypot viene lo que publica: reciben objetos del modelo
comun y ya. El campo `source` se usa para etiquetar el reporte, nunca para
bifurcar la logica.
"""
