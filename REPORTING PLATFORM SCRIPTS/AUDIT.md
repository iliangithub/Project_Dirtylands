# AUDIT.md — Auditoría del sistema de reporte a plataformas

Fecha: 2026-08-18 · Fases 1 y 2 del encargo

> [!IMPORTANT]
> **Este documento audita el código ANTERIOR**, los dos reporters monolíticos
> (`cowrie_reporter.py` y `dionaea_reporter.py`) que ya no existen en el repositorio.
> Se conserva porque en él están las citas literales de cada política, el porqué de cada
> criterio y la justificación del umbral 12 + 3, y porque documenta qué había que arreglar
> y por qué.
>
> **Todo lo que aquí aparece como `No existe`, `PARCIAL` o pendiente está ya implementado**
> en la reescritura: las cinco capas de unicidad, la idempotencia en dos fases, el retroceso
> ante 429 y 5xx, la barrera para contenido y la antigüedad tomada de `first_submission_date`.
> No leas las columnas de estado como si describieran el código de hoy.
>
> Lo que sigue vigente son los apartados **1.1 a 1.11** (políticas, decisiones y marcas
> NO VERIFICADO) y el criterio de la sección 1.7 sobre qué es y qué no es *hash busting*.

---

## 0. Alcance y método

**Qué se ha auditado.** Los dos reporters y sus auxiliares, en las copias del repositorio
(`REPORTING PLATFORM SCRIPTS/`), que son las mismas versiones desplegadas en
`/opt/dirtyland/platform-reporter/`.

> [!IMPORTANT]
> **Supuesto a verificar:** la auditoría se ha hecho sobre el repositorio, **no** sobre la VPS,
> porque el servidor se está rehaciendo y se pidió expresamente no conectarse. Antes de dar por
> buenas estas conclusiones conviene confirmar que el código desplegado coincide:
> ```
> sha256sum /opt/dirtyland/platform-reporter/cowrie/cowrie_reporter.py \
>           /opt/dirtyland/platform-reporter/dionaea/dionaea_reporter.py
> ```
> y contrastarlo con el del repositorio.

**Qué no se ha hecho.** Ningún envío real, ninguna petición de escritura a las APIs, ningún
cambio en nftables ni en la red. Las políticas se han leído de las fuentes oficiales, no de
memoria ni del propio código.

**Convención de veredictos:** `CUMPLE` · `NO CUMPLE` · `PARCIAL` · `NO VERIFICABLE`.
Cuando la documentación oficial no dice algo de forma explícita, se marca **NO VERIFICADO** en
lugar de rellenarlo por intuición.

---

## FASE 1 — Políticas vigentes, con fuente

### 1.1 MalwareBazaar

Fuentes: <https://bazaar.abuse.ch/api/> · <https://bazaar.abuse.ch/faq/>

| Regla | Cita literal | Traducción a comprobación en código |
|---|---|---|
| Solo malware confirmado | *"Please do only submit confirmed / vetted malware samples to MalwareBazaar. Do not submit any suspicious or benign files"* | Puerta de maliciosidad con veredicto de VT **antes** de subir |
| Antigüedad ≤ 10 días | *"Please refrain from uploading malware samples older than 10 days to MalwareBazaar."* | `first_submission_date` de VT dentro de 10 días, **o** desconocido para VT |
| Nada de adware/PUP | *"Please refrain from submitting Adware to MalwareBazaar."* | Descartar si las etiquetas de VT dominan en adware/PUP |
| Nada de gusanos ni file infectors | *"Please refrain from uploading file infectors and/or or worms to MalwareBazaar."* | Ver zona gris §1.6 |
| Hash busting / una por campaña | *"Some threat actors leverage hash busting to alter a file's hash sum, creating many different files."* · *"Please therefore only upload one of it per campaign."* | Ver zona gris §1.7 |
| Sanción | *"Should you repeatedly violate the submission policy documented above, your account may get banned from contributing to MalwareBazaar."* | — |

**API de envío** (confirmada): `POST https://mb-api.abuse.ch/api/v1/`, multipart con los campos
`file` y `json_data`, cabecera `Auth-Key`. Claves documentadas dentro de `json_data`:
`anonymous`, `tags`, `references`, `context`, `delivery_method`.
**Límite de tasa: NO VERIFICADO** (no aparece documentado).

### 1.2 ThreatFox

Fuente: <https://threatfox.abuse.ch/api/>

| Regla | Cita literal | Traducción |
|---|---|---|
| Solo IOC confirmados | *"Please do only submit confirmed / vetted IOCs to ThreatFox."* | Enviar solo tras veredicto de malware |
| Endpoint | `POST https://threatfox-api.abuse.ch/api/v1/`, cabecera `Auth-Key` | — |
| Esquema | `query: "submit_ioc"`, `threat_type`, `ioc_type`, `malware`, `iocs` (**array**) | El código ya usa `iocs: [ioc]` ✔ |
| Opcionales | `confidence_level` (0–100, por defecto 50), `is_compromised`, `reference`, `tags`, `comment`, `anonymous` | — |
| `malware` | Debe ser un **nombre de Malpedia** | Ya no se envía `"unknown"`: sin familia con equivalente confirmado en Malpedia **no se publica**. El mapa tiene 11 entradas y VirusTotal identifica 39 familias, así que 28 no producen IOC. Es deliberado: preferimos no publicar a inventarnos un nombre |
| Significado de los tramos de `confidence_level` | **NO VERIFICADO**: la documentación da el rango 0–100 y el valor por defecto, pero no define qué significa cada tramo | Mantener 75 y documentarlo como criterio propio |

> [!CAUTION]
> **El puerto se observa, nunca se supone.** `_ioc_de` rellenaba el puerto ausente con «443 si https, si no 80», y eso solo es cierto en http y https, donde es el puerto al que de verdad se conectó el cliente. Para cualquier otro esquema era ficción: `smb://46.46.121.73/transaction/\PIPE\` producía `46.46.121.73:80` cuando la subida entró por el **445**, y esa cadena ni siquiera es una URL de distribución — es la pseudo-URL que Dionaea sintetiza para nombrar una subida por SMB. Habríamos afirmado ante una plataforma cuya única regla es *"only confirmed / vetted IOCs"* que un puerto jamás tocado es infraestructura de entrega. **Corregido (2026-08-20):** solo se derivan IOC de `http` y `https`; el resto se descarta y el descarte queda anotado.

> [!NOTE]
> **Por qué esta plataforma nunca había recibido una petición.** Medido sobre la base de estado el 2026-08-20: `threatfox` y `urlhaus` tenían **cero filas** en `rejections`, mientras `malwarebazaar` tenía 21. No es que rechazaran mucho — es que el bloque de IOC nunca se ejecutaba. Cuelga de `if muestra.download_url:`, y ese campo venía siempre vacío por un fallo del *collector* de Dionaea: ataba cada binario a su fila de descarga buscando el **nombre del fichero** (SHA-256, 64 hex) en un índice de claves **MD5** (32 hex). No fallaba a veces; no podía acertar nunca. Corregido en la misma fecha.

### 1.3 URLhaus *(plataforma que no usamos)*

Fuente: <https://urlhaus.abuse.ch/api/>

| Regla | Cita literal | Traducción |
|---|---|---|
| Endpoint | `POST https://urlhaus.abuse.ch/api/` | **CORREGIDO tras verificar (2026-08-18):** la página del API dice que la `Auth-Key` va en el cuerpo JSON con los campos en mayúsculas (`URL`, `Threat`, `Tags`), pero el script de referencia que ella misma enlaza ([`submit_url.py`](https://github.com/abusech/URLhaus/blob/master/submit_url.py)) la manda en **cabecera HTTP** y usa los campos en minúsculas. Se sigue el script |
| Esquema | `anonymous`, `submission` (array), y por URL: `url`, `threat`, `tags`, `reference` | — |
| `threat` | Único valor válido: `malware_download` | Constante |
| URLs caídas | *"Malware URLs that are down and / or have already been cleaned should not be submitted"* | Comprobar que la URL sigue viva… **pero eso implicaría que el honeypot haga peticiones salientes al C2** (ver §2, riesgo) |
| Acortadores | *"Redirection sites or URL shorteners...should not be submitted"* | Lista de dominios acortadores |
| Adware / phishing / exploit kits | *"Please refrain from submitting URLs to URLhaus that are distributing Adware"* · *"Phishing sites... should not be submitted"* · *"Websites hosting an exploit kit should not be submitted unless the submitted URL serves the final payload"* | Solo URLs que sirvieron el binario que hemos capturado |
| IPs privadas | *"Ensure scripts don't submit RFC1597 or RFC6890 addresses"* | IPGuard ya lo cubre |

### 1.4 AbuseIPDB

Fuentes: <https://docs.abuseipdb.com/> · <https://www.abuseipdb.com/faq.html> · <https://www.abuseipdb.com/categories>

| Regla | Cita literal | Traducción |
|---|---|---|
| Endpoint | `POST https://api.abuseipdb.com/api/v2/report`, campos `ip`, `categories`, `comment`, `timestamp` | ✔ coincide con el código |
| Cuota | *"1,000"* peticiones/día al endpoint de report (cuenta estándar) | Contador diario propio (**hoy no existe**) |
| Deduplicación | *"we limit each account to reporting the same IP once per 15 minutes"* | Nuestro cooldown de 24 h es más conservador ✔ |
| Frecuencia recomendada | *"If an IP address is engaging in continuous abuse... we ask that you report the IP roughly once per day."* | 24 h encaja exactamente ✔ |
| **Prohibido** | *"prohibits reporting SYN floods and UDP connections"* (origen falsificable / no verificable) | Exigir handshake completo; nunca reportar UDP |
| PII | *"STRIP ANY PERSONALLY IDENTIFIABLE INFORMATION (PII); WE ARE NOT RESPONSIBLE FOR PII YOU REVEAL."* · *"limit your comments to only the key information"* | Redacción obligatoria en el comentario |

Categorías relevantes del catálogo completo (23): **14** Port Scan · **15** Hacking ·
**18** Brute-Force · **20** Exploited Host · **21** Web App Attack · **22** SSH ·
**23** IoT Targeted (*"include device info in comments"*).

### 1.5 VirusTotal

Fuentes: <https://docs.virustotal.com/reference/public-vs-premium-api> · <https://docs.virustotal.com/reference/files-upload-url>

| Regla | Cita literal | Traducción |
|---|---|---|
| Tasa | *"limited to **500 requests per day and a rate of 4 requests per minute**"* | Nuestro `min_seconds_between_calls = 16` da 3,75/min ✔; **el tope diario no se cuenta** |
| Uso comercial | *"The Public API **must not** be used in commercial products or services."* | Proyecto de investigación, no comercial ✔ (documentarlo) |
| Flujos que no aportan | *"The Public API **must not** be used in business workflows that do not contribute new files."* | Nuestro caso **sí** aporta ficheros nuevos ✔ |
| Multicuenta | *"You are not allowed to register multiple accounts to overcome the aforementioned limitations."* | — |
| Ficheros grandes | *"For uploading files smaller than 32MB you can simply use the POST /files endpoint, but for larger files you need to obtain a special upload URL first"* → `GET /files/upload_url` | Nuestro tope de 32 MB coincide ✔ |
| Máximo absoluto | 650 MB | — |
| Ampliación de cuota para honeypots | **NO VERIFICADO**: no he localizado un procedimiento oficial y explícito | Pendiente |

### 1.6 Zona gris: gusanos y file infectors

El texto prohíbe *"file infectors and/or worms"*. Un honeypot SSH/Telnet captura sobre todo
botnets IoT (Mirai, Gafgyt) que **sí se autopropagan**. Leído al pie de la letra, no podríamos
subir casi nada de lo que capturamos.

**Criterio operativo propuesto**, defendible ante abuse.ch:

1. **File infector: nunca.** Es la categoría inequívoca — malware que *modifica otros ficheros
   existentes* para incrustarse (virus parasitario). Riesgo real de contaminar muestras ajenas y
   entornos de análisis. Descarte automático si VT lo etiqueta como `virus`/`infector`.
2. **Autopropagante (gusano IoT): sí, pero con cuota estricta.** La razón de ser de la
   prohibición es el volumen: un gusano genera miles de muestras casi idénticas. Nuestro sistema
   ya está en el extremo opuesto porque solo sube lo que **VirusTotal no ha visto jamás**, que es
   una fracción minúscula. Se refuerza con el límite de §1.7 (una por familia, campaña y
   arquitectura) y con etiquetado honesto (`mirai`, `gafgyt`) para que los curadores puedan
   filtrar.
3. **Ante la duda, no se sube.** La muestra ya queda registrada en VirusTotal, que es donde
   aporta valor sin riesgo de política.

> Este criterio es **interpretación nuestra**, no una excepción concedida por abuse.ch. Si el
> volumen de subidas creciera, lo prudente es preguntar por su canal de contacto antes que
> asumir. **NO VERIFICADO** que acepten esta lectura.

### 1.7 Zona gris: hash busting frente a multiarquitectura

Hash busting = **el mismo payload** alterado para cambiar su hash. Un dropper que sirve
compilaciones para `mips`, `arm`, `x86` entrega **ficheros legítimamente distintos**: distinta
arquitectura de CPU, distinto código máquina.

**Criterio operativo propuesto:** deduplicar por la terna
`(familia, campaña, arquitectura ELF)`.

- **Arquitectura** = campo `e_machine` de la cabecera ELF (ya sabemos leer *magic bytes*).
- **Campaña** = la URL o el `ip:port` de descarga del payload.
- Se sube **una muestra por terna**. Dos binarios que solo difieren en relleno o cifrado, con la
  misma arquitectura y campaña, son hash busting → solo el primero.

---

### 1.8 Plataformas candidatas

| Plataforma | ¿Acepta envíos de terceros? | Qué dato | Qué aporta | Veredicto |
|---|---|---|---|---|
| **URLhaus** | Sí, `POST https://urlhaus.abuse.ch/api/` | URL que sirvió el binario | Cubre un hueco real: hoy las URLs de descarga **no se reportan a ninguna plataforma especializada** | **Incorporar.** Misma cuenta abuse.ch, coste bajo |
| **YARAify** | Sí, `POST https://yaraify-api.abuse.ch/api/v1/` | Fichero, para escaneo YARA/ClamAV | Devuelve reglas YARA que casan → **ayuda a clasificar la familia**, justo lo que nos falta para el campo `malware` de ThreatFox | **Evaluar.** Útil como *enriquecimiento*, no como reporte. Ojo: `share_file=1` por defecto |
| **DShield / SANS ISC** | Sí. *"DShield provides a platform for users of firewalls to share intrusion information."* | Logs de cortafuegos | Solapa con AbuseIPDB. *"We recently culled our list of supported firewalls as most uses use our honeypot"* | **No ahora.** Soporte específico para Cowrie: **NO VERIFICADO** |
| **Feodo Tracker** | **NO VERIFICADO**: no documenta formulario ni API de envío | — | Rastrea Dridex, Emotet, TrickBot, QakBot, BazarLoader: **troyanos bancarios de Windows**, no lo que capturamos | **Descartar** |

---

## 1.9 La carrera por la autoría (por qué el orden no es negociable)

Esto no es una preferencia de estilo: es una restricción de diseño nacida de un hecho observado.
**Hay bots que vigilan las publicaciones de MalwareBazaar y, en cuanto aparece una muestra, corren
a subirla a VirusTotal** para figurar ellos como primer remitente y quedarse con el reconocimiento.
Ya nos pasó: publicamos primero en MalwareBazaar y nos robaron la autoría en VirusTotal.

De ahí que la secuencia sea estrictamente serie, sin paralelismo posible:

1. Subir la muestra a **VirusTotal**.
2. **Esperar** a que el análisis termine de verdad.
3. Comprobar que el veredicto confirma que es malware.
4. **Comentar** la muestra (firmada con el handle).
5. **Votar** el *community score*.
6. Margen de gracia.
7. **Y solo entonces**, publicar en **MalwareBazaar**.

MalwareBazaar es el escaparate público y por tanto **lo último**: cuando la muestra aparece allí,
nuestra posición en VirusTotal ya tiene que estar consolidada y firmada. Cualquier reordenación
—o hacer los dos envíos en paralelo para "ganar tiempo"— reabre la ventana por la que nos robaron
la autoría.

> Consecuencia para el diseño: los pasos 2 y 3 pueden tardar minutos. El sistema debe poder
> **aplazar** una muestra a la siguiente pasada del cron sin perderla y sin publicarla a medias.
> Nunca acortar la espera para "no bloquear".

---

## 1.10 Decisiones tomadas: umbral y unicidad

Dos criterios cerrados, porque de ellos depende no perder las cuentas.

### A. Umbral de maliciosidad: **12 + 3**

Para comentar, votar y publicar hacen falta **todas** estas condiciones:

| # | Condición | ¿A quién bloquea? |
|---|---|---|
| 1 | El análisis de VirusTotal está en estado `completed` | a todos |
| 2 | **≥ 12 motores** en `malicious` | a todos |
| 3 | Ninguna señal dominante de adware/PUP | a todos |
| 4 | **≥ 3 motores coincidiendo en la misma familia** (`mirai`, `gafgyt`, `redtail`…), no genéricos tipo `Trojan.Generic` o `ML.Attribute` | solo MalwareBazaar y ThreatFox |

Las tres primeras responden *«¿esto es malware?»*; la cuarta, *«¿sabemos cómo se llama?»*. Son
preguntas distintas y solo la segunda se la piden las dos plataformas que publican la muestra
etiquetada con una familia. **Estuvieron mezcladas**, y mientras lo estuvieron un nombre que no
supiéramos poner apagaba también el voto de VirusTotal, la URL de URLhaus y la denuncia del
servidor distribuidor, que no piden ninguno.

Entre 1 y 11 detecciones: **no se hace nada** — ni comentario, ni voto, ni MalwareBazaar. Se marca
para revisión manual y avisa Telegram. Con 0 tras el rechequeo diferido, se descarta.

**Por qué 12 y no menos.** Un número alto rechazaría muestras recién compiladas, que apenas tienen
detecciones el primer día… pero eso se resuelve con el **rechequeo diferido** (§1.11): no decidimos
en caliente, volvemos a mirar a las 24-48 h, cuando los motores ya se han puesto al día, y seguimos
sobradamente dentro de la ventana de 10 días. Con esa red, 12 es alcanzable para malware real y
deja fuera el ruido.

**Por qué "nombre de familia" y no una lista de fabricantes.** Doce motores diciendo
`Trojan.Generic` son doce heurísticas que pueden venir del mismo tipo de clasificador. Tres
diciendo `Mirai` significan que alguien ha reconocido *qué* es. Una lista blanca de fabricantes
envejece mal y, además, los motores fuertes en Windows PE no son necesariamente los mejores en
ELF/IoT.

**Y por qué tampoco una lista blanca de familias.** Es el mismo argumento, y se tardó en aplicarlo
aquí: durante un tiempo un nombre solo contaba si estaba en una lista de 39 escritos a mano, así
que `RedTail` —capturado el 2026-08-22— daba consenso **0** con
treinta motores diciendo lo mismo. El filtro es ahora una **lista negra** de lo que no es un
nombre de familia: palabras de clase (`trojan`, `downloader`), de plataforma (`linux`, `elf`),
marcadores heurísticos (`heur`, `generic`) y los nombres de detección genérica que varias casas
comparten por licenciar el mismo motor (`zusy`, `kryptik`, `wacatac`…), que son los únicos capaces
de reunir tres motores «de acuerdo» sin identificar nada.

Ante la duda, el nombre va a la lista negra: uno bloqueado de más es una muestra que no se publica;
uno de menos es una etiqueta falsa en una plataforma pública.

> **NO VERIFICADO:** ni VirusTotal ni MalwareBazaar publican un umbral numérico oficial. Este es
> criterio propio y así debe constar.

### B. Unicidad en MalwareBazaar: cinco capas

La política prohíbe el *hash busting* y pide **una muestra por campaña**. Cinco controles, del más
barato al más caro:

| Capa | Control | Estado hoy |
|---|---|---|
| 1 | **Hash ya enviado por nosotros** → estado local SQLite | Existe |
| 2 | **Hash ya presente en MalwareBazaar** → `get_info` antes de subir, y **fail-closed**: si la consulta falla, se asume que existe y no se sube | Existe, y ya falla cerrado |
| 3 | **Clúster de similitud** → si el informe de VT trae `vhash` / `ssdeep`, guardarlo; si coincide con algo ya subido, es la misma cosa con otro hash → descartar | **No existe.** Campos **NO VERIFICADOS**: confirmar en la primera llamada real |
| 4 | **Campaña + arquitectura** → clave `(familia, host de descarga, e_machine del ELF)`. Una sola muestra por terna en 30 días | **No existe** |
| 5 | **Ráfaga** → varios binarios del mismo host, misma arquitectura y tamaño casi idéntico en poco tiempo = hash busting: se sube uno y el resto se registra como descartado | **No existe** |

Y por encima de todo, un **tope duro configurable** (por defecto 5 subidas/día y 20/semana): aunque
fallara toda la lógica anterior, es imposible inundar la plataforma. Al alcanzarlo, se aplaza y se
avisa.

La capa 4 es la que traduce el criterio de §1.7: un binario `mips` y uno `arm` de la misma campaña
son ficheros legítimamente distintos y **no** son hash busting; dos binarios de la misma
arquitectura y campaña que solo difieren en relleno, sí.

### 1.11 Rechequeo diferido: separar autoría de publicación

No hace falta decidirlo todo en la misma pasada, y separarlo resuelve la tensión entre "solo
malware confirmado" y "muestras frescas":

- **Momento 1, inmediato.** Subir a VirusTotal y esperar a `completed`. Con eso ya somos *first
  submitter*, que es lo que nos roban los bots (§1.9). Nada más: ni comentario, ni voto.
- **Momento 2, a las 24-48 h.** Volver a consultar el hash. Las detecciones maduran con el tiempo.
  Si ya cumple el umbral: comentar, votar y **entonces** publicar en MalwareBazaar.

Así no perdemos la carrera por la autoría, no votamos a ciegas y no publicamos nada sin veredicto.
Requiere que el estado sepa mantener muestras en `pendiente_de_veredicto` entre pasadas del cron.

---

## FASE 2 — Auditoría del código actual

Referencias como `cowrie:957` = `cowrie_reporter.py`, línea 957.

### Resumen

| # | Punto | Veredicto |
|---|---|---|
| 1 | Frescura por `first_submission_date` | **NO CUMPLE** (mitigado por otra vía) |
| 2 | Confirmación de maliciosidad antes de MalwareBazaar | **NO CUMPLE — crítico** |
| 3 | Orden VirusTotal antes de MalwareBazaar | CUMPLE |
| 4 | Deduplicación | CUMPLE |
| 5 | Categorías de AbuseIPDB y puerto en el comentario | CUMPLE (mejorable) |
| 6 | Filtrado de eventos no reportables | CUMPLE |
| 7 | IPGuard y `assert_safe` | PARCIAL |
| 8 | Fugas de infraestructura propia | PARCIAL |
| 9 | Manejo de errores HTTP y 429 | PARCIAL |
| 10 | Limitación de tasa frente a cuota real | PARCIAL |
| 11 | Endpoints y nombres de campo | PARCIAL |
| 12 | Comportamiento ante muerte del proceso | PARCIAL |

### 1. Frescura de las muestras — **NO CUMPLE**

`cowrie:940,957` y `dionaea:988,1004` filtran por **`st_mtime` del fichero local**:

```python
cutoff = time.time() - self.max_age_days * 86400
if st.st_mtime < cutoff:
```

**`first_submission_date` no aparece en ninguna parte del código.** Es exactamente el mecanismo
que provocó el baneo anterior.

**Atenuante importante:** hoy no es la puerta que decide. En `cowrie:987` solo se sube a
MalwareBazaar si `vt_status == "uploaded"`, es decir, **si VirusTotal no conocía el fichero**.
Una muestra que VT nunca vio es fresca por definición, así que el riesgo del baneo está
neutralizado *por otra vía*. Pero el `mtime` sigue en el código como prefiltro y la comprobación
que exige la política (`first_submission_date` ≤ 10 días) **no existe**.

### 2. Puerta de maliciosidad — **NO CUMPLE (el hallazgo más grave)**

**No hay ninguna.** El flujo real es:

```
VT responde 404 (nunca lo ha visto)  →  subimos a VT  →  subimos a MalwareBazaar
```

`cowrie:981-996`. El único requisito para enviar a MalwareBazaar es que VirusTotal **no
conociera** el fichero. Y un fichero que VT acaba de recibir **no tiene ningún veredicto todavía**:
no se consulta el análisis, no se espera a que termine, no se cuenta un solo motor.

Es decir: **subimos a MalwareBazaar precisamente los ficheros sobre los que nadie ha dictaminado
nada**, lo que choca de frente con *"Please do only submit confirmed / vetted malware samples...
Do not submit any suspicious or benign files"*.

Que hasta ahora las muestras hayan resultado ser malware es suerte estadística —lo que cae en un
honeypot suele serlo—, no un control. Un binario benigno subido por un escáner, un fichero de
prueba o un `wget` fallido pasarían la misma puerta.

**Esto es lo que resuelve la Fase 4 del encargo** (sondeo del análisis + umbral de detecciones), y
es la razón principal para reescribir.

### 3. Orden VirusTotal → MalwareBazaar — **CUMPLE el orden, NO CUMPLE la condición de espera**

El **orden sí es el correcto** y protege la autoría (§1.9). `_finalize_new_upload`
(`cowrie:824-851`) hace, en serie: sondear VT → comentar → votar → esperar `grace_seconds` → y
solo al volver se ejecuta la subida a MalwareBazaar (`cowrie:981` antes de `cowrie:1017`). Si VT
no se pudo cerrar, `cowrie:982-985` aplaza el envío. Esa parte está bien resuelta.

**El problema es qué se espera.** El bucle solo aguarda a que el `GET /files/{sha256}` devuelva
**200**, es decir, a que el fichero esté *indexado*:

```python
if g.status_code == 200:
    self.add_comment(sha256, self._new_sample_comment(path, sha256))
    self.vote_malicious(sha256)
```

Estar indexado **no es estar analizado**. Un 200 puede devolver `last_analysis_stats` a cero
porque el análisis sigue en cola. Con eso:

- Se **comenta** afirmando que es *"First-seen malware sample"* sin que ningún motor lo haya dicho.
- Se **vota `malicious`** sin veredicto: si la muestra resultara benigna, habríamos manipulado el
  *community score* de VirusTotal, que es precisamente el tipo de conducta que penaliza una cuenta.
- Y se **publica en MalwareBazaar** sin confirmación.

La corrección no es cambiar el orden, sino la condición: sondear hasta que el análisis esté
**`completed`** y aplicar el umbral de detecciones antes de comentar, votar y publicar.

### 4. Deduplicación — **CUMPLE**

SQLite con claves primarias `(ip, platform)`, `(sha256, platform)`, `(ioc, platform)`
(`cowrie:253-263`). Cooldown de IP de 24 h (`cowrie:528,562`), que encaja con la recomendación
literal de AbuseIPDB (*"roughly once per day"*) y es más conservador que su límite de 15 minutos.

### 5. AbuseIPDB: categorías y puerto — **CUMPLE, mejorable**

Categorías 14/15/18/22 (`cowrie:77-80,378-389`). El puerto va en el **comentario**
(`cowrie:410`), no en el campo `ip`. Correcto.

**Mejoras**: la categoría **23 (IoT Targeted)** encaja de lleno con lo que captura Cowrie y su
descripción pide *"include device info in comments"*; la **20 (Exploited Host)** aplica cuando la
IP atacante está a su vez comprometida, que es el caso típico de un bot IoT.

### 6. Filtrado de eventos no reportables — **CUMPLE**

Cowrie exige handshake completo (`cowrie:370`); Dionaea solo cuenta `connection_type='accept'`
(`dionaea:457,468`), descartando los `reject`. No hay ninguna ruta que reporte UDP ni SYN sueltos.
Coincide con la prohibición literal de AbuseIPDB.

### 7. IPGuard — **PARCIAL**

Las tres capas existen: lista fija (`cowrie:63`), lista del config (`cowrie:158`) y
`ip.is_global` (`cowrie:189-191`). Pero `assert_safe` **solo se invoca en dos sitios**:
`cowrie:586` (AbuseIPDB) y `cowrie:1142` (ThreatFox).

**No se invoca antes de los POST a VirusTotal ni a MalwareBazaar.** Es cierto que ahí no se envía
una IP sino un fichero, así que la comprobación tal cual no aplica; pero el requisito de "barrera
antes de cada POST" no se cumple literalmente, y esos envíos **sí** llevan metadatos
(`tags`, `references`, comentarios) que podrían filtrar infraestructura. Falta una barrera
equivalente para contenido.

### 8. Fugas de infraestructura — **PARCIAL**

`sanitize_comment` (`cowrie:220-232`) redacta toda IPv4 que el guard considere no reportable.
Bien. Pero:

- **Solo IPv4**: `IPV4_RE` (`cowrie:217`) no cubre IPv6.
- No hay redacción de **rutas internas** (`/opt/dirtyland/...`) ni de **nombres de usuario del
  sistema**, que podrían acabar en un comentario derivado de la entrada del atacante.
- Los `tags` de MalwareBazaar son constantes (`cowrie:1014`) ✔.

### 9. Errores HTTP — **PARCIAL**

El 429 se detecta (`cowrie:611,693,761,798,820`) pero la reacción es **registrar y abandonar**:
no hay reintentos, ni *backoff*, ni lectura de la cabecera `Retry-After`. Tampoco hay un
tratamiento distinto para un error de **política** (que exige parar y revisar) frente a uno de red
(que se puede reintentar).

### 10. Limitación de tasa — **PARCIAL**

`RateLimiter` por plataforma (`cowrie:326-336`): VT 16 s → 3,75 peticiones/minuto, justo por
debajo del límite documentado de 4/min ✔. **Pero el tope de 500 peticiones/día de VirusTotal no
se cuenta en ninguna parte**, ni las 1.000/día de AbuseIPDB. Con un backfill largo es posible
agotarlos sin enterarse.

### 11. Endpoints y campos — **PARCIAL**

- AbuseIPDB `/api/v2/report` ✔ · VirusTotal `GET/POST /files`, `/files/{id}/comments`,
  `/files/{id}/votes` ✔ · MalwareBazaar `mb-api.abuse.ch/api/v1/` multipart ✔ ·
  ThreatFox `query: submit_ioc` con `iocs: [ioc]` ✔ (`cowrie:1149-1156`).
- **`json_data` de MalwareBazaar incluye `"identifier"`** (`cowrie:1011`), que **no figura** entre
  las claves documentadas (`anonymous`, `tags`, `references`, `context`, `delivery_method`).
  **NO VERIFICADO** si se ignora o si invalida la petición.
- **ThreatFox envía `malware: "unknown"`** (`cowrie:1152`) cuando la documentación pide un nombre
  de **Malpedia**. **NO VERIFICADO** que `"unknown"` sea aceptado; podría ser rechazo silencioso.
- **URLhaus no está implementado**: las URLs de descarga no se reportan a ninguna plataforma
  especializada.

### 12. Muerte del proceso a mitad — **PARCIAL**

El estado se marca **después** del POST correcto. Si el proceso muere en medio, el reintento
vuelve a enviar. Está mitigado —MalwareBazaar consulta `exists()` antes, y AbuseIPDB deduplica en
su lado a 15 minutos— pero no es transaccional. Con URLhaus y ThreatFox el riesgo de duplicado es
mayor.

---

## Hallazgos por prioridad

1. **No existe puerta de maliciosidad** (§2, §3). Se comenta, se vota y se sube a MalwareBazaar
   una muestra que **no tiene veredicto**: el sistema espera a que VirusTotal la *indexe*, no a que
   la *analice*. Es un incumplimiento estructural de la política de MalwareBazaar, y además vota el
   *community score* de VirusTotal a ciegas. Es el mayor riesgo vigente para las dos cuentas.
2. **La frescura sigue calculándose con `mtime`** (§1). Hoy no decide, pero el código que causó el
   baneo anterior continúa ahí y `first_submission_date` no se consulta nunca.
3. **Sin contador de cuota diaria** (§10) para VT (500/día) ni AbuseIPDB (1.000/día).
4. **Dos campos sin verificar contra la API real** (§11): `identifier` en MalwareBazaar y
   `malware: "unknown"` en ThreatFox.
5. **URLhaus sin implementar** (§1.3): hueco de cobertura, y es la plataforma natural para las URLs
   de descarga que ya capturamos.
6. **`assert_safe` no cubre todos los POST** (§7) y la redacción no cubre IPv6 ni rutas internas (§8).
7. **Sin reintentos ni backoff** (§9); sin idempotencia real (§12).

---

## Solo verificable contra la API real

Lista para el día del primer envío de verdad:

1. Si MalwareBazaar acepta o rechaza la clave `identifier` dentro de `json_data`.
2. Si ThreatFox admite `malware: "unknown"` o exige un nombre de Malpedia válido.
3. El formato exacto de respuesta de MalwareBazaar en un alta correcta (`ok` / `inserted` / otro).
4. El comportamiento real del 429 de cada plataforma y si envían `Retry-After`.
5. Si abuse.ch considera aceptable nuestro criterio sobre gusanos IoT (§1.6).
6. Límites de tasa de MalwareBazaar y ThreatFox, no documentados.
7. Si existe un procedimiento de ampliación de cuota de VirusTotal para honeypots (§1.5).

---

## Recomendación

Reescribir según las Fases 3 y 4 del encargo. El orden de trabajo que propongo es:

1. **Puerta de maliciosidad (§1.10 A) + frescura por `first_submission_date` + rechequeo diferido
   (§1.11)** — resuelve los dos hallazgos críticos y es lo único que hoy nos expone a un baneo.
   Mantener el orden de §1.9 intacto.
2. **Las cinco capas de unicidad y el tope duro de subidas (§1.10 B)** — es el otro frente de
   baneo, hoy cubierto solo por las capas 1 y 2.
3. **Reorganización en `common/` + `collectors/` + `reporters/`** — habilita lo demás.
4. **Contadores de cuota, backoff e idempotencia**.
5. **URLhaus** como plataforma nueva.
6. **YARAify** como enriquecimiento opcional, solo si aporta el nombre de familia que le falta a
   ThreatFox.

**Pendiente de tu aprobación explícita antes de tocar una sola línea de código.**
