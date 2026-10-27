 **🇪🇸 Español** · [🇬🇧 English](README.en.md) · [🇧🇬 Български](README.bg.md) · [🇫🇷 Français](README.fr.md) · [🇩🇪 Deutsch](README.de.md)

# 1. Introducción

## 1.1 Propósito

Querido lector, quiero de manera directa, personal y breve transmitirte cuál es el propósito del proyecto.

Ya suficientemente largo es el proyecto como para que hasta algo tan simple y personal como esto me lleve mucho de explicar.

Este proyecto nace con dos propósitos:

- **Por un lado, uno técnico y profesional:** diseñar, desplegar y operar una infraestructura de honeypots capaz de atraer, capturar y estudiar la actividad de atacantes reales, aplicando criterios rigurosos de diseño, seguridad y contención. La infraestructura en sí es algo que me apasiona.

- **Por otro, un propósito personal:** servir como carta de presentación de mis competencias en el ámbito de la ciberseguridad defensiva, en un momento de búsqueda de desarrollo profesional en este campo.

A diferencia de un ejercicio de laboratorio, **este trabajo se enfrenta a amenazas reales** y soy plenamente consciente del rigor, conocimiento y filosofía que hay que volcar en esto, pues no me estoy jugando poca cosa, aquí no puede haber "errores humanos" y esa es también la idea:

- **Demostrar** mi **capacidad** de hacer algo de principio a fin, cumpliendo un **rigor, un estándar, sin errores humanos**, en defensa no se admiten errores.

Asimismo, exponer de forma controlada una máquina a internet y observar quién intenta atacarla, con qué herramientas y con qué objetivos, **ofrece una perspectiva directa del panorama real de amenazas que no se obtiene en entornos simulados, el estrés, la presión y responsabilidad que recaen.**

Ese carácter real es, para mí, lo que da valor y sentido al proyecto. Más allá del ejercicio técnico, el trabajo se enmarca en una motivación de fondo: **contribuir, aunque sea de forma modesta, a la defensa frente al cibercrimen**. La captura de malware y de indicadores de ataque, y su reporte a las plataformas y autoridades competentes (en caso necesario), no es solo un ejercicio de aprendizaje, sino **una aportación real, por pequeña que sea, al esfuerzo colectivo de defensa** que realizan analistas y equipos de seguridad en todo el mundo.

Respecto a las aspiraciones, el proyecto apuntaba muy alto. Aunque sé profundamente que la mayor parte de la actividad capturada será tráfico automatizado y oportunista, se diseñó con la ambición de poder detectar y documentar amenazas de mayor relevancia (APTs).

**Aspirar a lo máximo, asumiendo con realismo lo que es probable**, es parte del enfoque con el que se ha abordado.

En conjunto, este proyecto pretende demostrar competencias prácticas en **despliegue seguro de infraestructura, administración de sistemas y redes, y ciberseguridad defensiva e inteligencia de amenazas**, a la vez que reflejar el interés genuino y la vocación con la que se ha realizado.

<p align="center">Espero que valores, comprendas y sobre todo disfrutes cada palabra/acción realizada, tanto como yo lo he disfrutado. Gracias.</p>

## 1.2 Alcance

Este proyecto tiene por objeto el diseño, despliegue y operación de una infraestructura de honeypots orientada a la captura y el estudio de la actividad de atacantes reales en internet. En concreto, el alcance del trabajo incluye:

- El despliegue de **dos honeypots complementarios, Cowrie (para SSH y Telnet) y Dionaea (para múltiples protocolos de red)**, sobre un servidor privado virtual (VPS), utilizando contenedores Docker.
- El diseño e implementación de las **medidas de seguridad y contención** necesarias para exponer la máquina de forma responsable:
  - Configuración de cortafuegos con nftables.
  - Control estricto del tráfico de salida (egress).
  - Endurecimiento de los contenedores.
- La personalización de los honeypots para aumentar su credibilidad frente a los atacantes.
- La recogida, observación y análisis de la actividad capturada (intentos de acceso, comandos ejecutados y malware depositado).
- El reporte de los indicadores obtenidos a plataformas de inteligencia de amenazas.

Quedan **explícitamente fuera del alcance** de este trabajo:

- **Cualquier uso ofensivo de la infraestructura.** El proyecto es estrictamente defensivo y de observación.
- **La atribución de los ataques** a actores, grupos o países concretos, en coherencia con el enfoque de neutralidad expuesto en el apartado de consideraciones éticas.
- **El análisis forense exhaustivo o la ingeniería inversa en profundidad** del malware capturado, que excede los objetivos de este proyecto y podría constituir una línea de trabajo futura.
- **Un despliegue de nivel empresarial o de producción.** Se trata de un proyecto de carácter académico y de portfolio, si bien diseñado con criterios profesionales de rigor y seguridad.

## 1.3 Destinatarios

Este trabajo **no está dirigido a principiantes**.

Presupone una base técnica previa, por lo que sus destinatarios son personas con un perfil de **nivel medio o avanzado**:

- Recién graduados en ingenierías informáticas o de telecomunicaciones
- Estudiantes de máster
- Profesionales y expertos del ámbito de la ciberseguridad.

Igualmente puede resultar de interés para:

- Analistas de seguridad
- Personal de inteligencia
- Miembros de las Fuerzas y Cuerpos de Seguridad del Estado con competencias en ciberseguridad.

A lo largo del documento se asume que el lector está familiarizado con conceptos básicos de redes, sistemas operativos de tipo Linux y administración de servidores. Aunque muchos de estos conceptos se explican en detalle a lo largo del proyecto (con vocación didáctica), no se parte desde un nivel de introducción absoluta.

## 1.4 Advertencia ética y legal

Este **proyecto se enmarca de forma estricta en** el ámbito de **la investigación defensiva en ciberseguridad**. Su **finalidad** es exclusivamente **el estudio de las técnicas, herramientas y comportamientos empleados por los atacantes**, con el objetivo de comprender mejor las amenazas y aprender a defenderse de ellas. **En ningún caso se persigue atacar, perjudicar ni tomar represalias contra nadie.**

### Consideración sobre los datos y la privacidad

Durante la operación del honeypot se recogen datos generados por los propios atacantes, entre ellos direcciones IP de origen.

Conviene recordar que **una** dirección **IP puede considerarse un dato de carácter personal a efectos de**:

- El Reglamento General de Protección de Datos (**RGPD**) de la Unión Europea.
- La Ley Orgánica 3/2018 de Protección de Datos Personales y Garantía de los Derechos Digitales (**LOPDGDD**), que lo desarrolla en España.

En esta línea, el Tribunal de Justicia de la Unión Europea, en su sentencia del caso Breyer (asunto C-582/14, de 19 de octubre de 2016), determinó que **una dirección IP dinámica puede constituir un dato personal** cuando existe una posibilidad razonable de vincularla a una persona identificable. Aunque la sentencia se dictó bajo la Directiva 95/46/CE, anterior al RGPD, su criterio es coherente con el que recoge el reglamento actual en su Considerando 26.

Las normativas de protección de datos **amparan a cualquier persona física, incluidos quienes llevan a cabo actividades ilícitas**. El RGPD no protege a las personas jurídicas, como las empresas.

Tampoco sería correcto acogerse a la excepción de las actividades exclusivamente personales o domésticas (artículo 2.2.c del RGPD) por tratarse de un proyecto individual. El Tribunal de Justicia interpreta esa excepción de forma restrictiva: en el caso Ryneš (asunto C-212/13) consideró que una cámara instalada en una vivienda que grababa parte de la vía pública ya quedaba fuera de ella. **Un servidor expuesto a internet, cuyos datos además se comparten con plataformas públicas, entra con más motivo en el ámbito del reglamento.**

El tratamiento de estos datos en el marco de este proyecto se sustenta en el **interés legítimo (artículo 6.1.f del RGPD)**, orientado a garantizar la seguridad de las redes y de la información, un fin que el propio reglamento reconoce expresamente como interés legítimo en su Considerando 49.

No obstante, dicho tratamiento se realiza aplicando los principios de **minimización y proporcionalidad**: se recoge únicamente lo necesario para el análisis de las amenazas.

**Por prudencia**, en este documento **se han anonimizado u ocultado los siguientes datos:**

- Direcciones IP.
- Ciertos payloads.
- URL y direcciones de servidores de mando y control (C2).
- Los datos propios de la infraestructura del proyecto (la IP pública del servidor, credenciales y cualquier dato que pudiera comprometer su seguridad).
- Otros datos sobre el atacante.

Aunque estos datos no pertenecen a las categorías especiales que el RGPD considera sensibles (artículo 9: salud, ideología, origen étnico, etc.), se ha optado igualmente por anonimizarlos.

El informe de análisis original, con los datos completos, **se conserva cifrado de forma local en mi propio ordenador durante un máximo de un año** desde el cierre del proyecto, tras el cual se eliminará. **No se sube a GitHub ni a ningún otro sitio de internet** porque no puede garantizarse que lo publicado se borre de forma definitiva:

- Si alguien lo descarga antes.
- El historial de commits.
- WayBackMachine

La decisión de anonimizar, y no seudonimizar, se debe a que **el RGPD solo deja de aplicarse a los datos verdaderamente anonimizados**, que por definición no permiten identificar a nadie, mientras que **los seudonimizados siguen siendo datos personales** porque, con la información adicional adecuada, se puede volver a llegar a la persona.

Y por último, respecto al "borrado de como máximo 1 año": mientras conserve el informe original, puedo deshacer las etiquetas. Según una lectura estricta del Considerando 26, que tiene en cuenta los medios del propio responsable, la versión publicada sería anónima para cualquier lector, pero seudonimizada para mí hasta que borre el original. Hay debate jurídico sobre si se debe mirar desde la perspectiva de quien recibe los datos o de cualquiera. Pero **eliminar el original al cumplirse el plazo cierra esa duda en cualquiera de las dos interpretaciones.**

### Neutralidad y contexto geopolítico

A lo largo del proyecto, el país asociado a cada dirección IP se muestra **únicamente como dato técnico, nunca como atribución**. Las direcciones IP, como se ha explicado, se han anonimizado por protección de datos.

El país, en cambio, se conserva porque por sí solo no identifica a nadie, pero conviene interpretarlo con cautela: **no es posible atribuir con total certeza una IP, una muestra de malware ni ningún otro dato a un país concreto.** La dirección que llega al honeypot es solo el último salto de la conexión, y detrás de ella puede haber un proxy, una VPN, la red Tor, un VPS alquilado en un tercer país, un servidor de mando y control (C2) o, con mucha frecuencia, un dispositivo IoT comprometido que forma parte de una botnet y cuyo propietario ni siquiera sabe que está atacando.

A todo esto se suman las **falsas banderas**, es decir, rastros dejados de forma deliberada (idioma de las cadenas, zonas horarias, infraestructura reutilizada) para que el ataque parezca proceder de otro lugar.

Incluso **la geolocalización de una IP refleja dónde está registrado el rango de direcciones, no dónde se encuentra la máquina** ni, mucho menos, la persona que la controla. Además, como veremos más adelante, los rangos IPv4 se compran, se venden y se alquilan entre organizaciones de distintos países, de modo que un bloque registrado en un país puede estar operando en otro, lo que mezcla y complica todavía más cualquier intento de atribución geográfica.

**Por tanto, que una conexión figure con un país determinado no significa que ese país, ni nadie que resida en él, sea el autor del ataque.**

Existe, además, una razón de contexto: dado el panorama geopolítico europeo actual, se ha considerado importante que este trabajo se mantenga en un plano técnico y objetivo, sin hacer atribuciones ni alimentar ningún tipo de dramatización o aprovechamiento de la situación. **El interés del proyecto está en el "cómo" técnico de los ataques, no en el "quién"** ni en su origen geográfico.

### Sobre la seguridad del propio sistema

Conviene ser honesto respecto a un principio fundamental de la disciplina: **no existe un sistema 100% seguro**, y un honeypot, por su propia naturaleza de máquina deliberadamente expuesta, lo asume de partida.

Lo que sí es posible, y es el enfoque adoptado en este trabajo, es aplicar un **diseño extremadamente riguroso, profesional y con múltiples capas de contención**, de modo que el riesgo se reduzca a un mínimo conocido y controlado.

### Autorización del proveedor y cumplimiento de sus condiciones

Antes de iniciar el proyecto, el primer paso fue **solicitar autorización expresa a la empresa proveedora** del servidor privado virtual (VPS).

Para ello se remitió un correo electrónico en el que se explicaba, con plena transparencia, la naturaleza del proyecto y las actividades que se iban a llevar a cabo: el despliegue de honeypots para la captura y el estudio de la actividad de atacantes reales. **El proveedor respondió confirmando su conformidad con la actividad.** Dicho correo no se reproduce en este documento por privacidad, pero se conserva como constancia de que la actividad fue comunicada y autorizada de antemano.

Asimismo, se revisaron de forma individual las políticas y condiciones de uso del proveedor, con el fin de asegurar que la operación del honeypot se mantuviera dentro de los términos que este establece.

**Se recomienda encarecidamente** a cualquiera que desee replicar un proyecto de esta naturaleza que **solicite autorización previa a su proveedor y revise sus condiciones de uso antes de desplegar nada**. Es un paso sencillo que evita problemas legales y de servicio, y es la forma responsable de proceder.

## 1.5 Riesgos

Todo honeypot conlleva un riesgo inherente: se expone deliberadamente una máquina a atacantes reales. El peligro principal no es tanto que el atacante "gane" dentro de la emulación, sino **que la máquina comprometida o abusada se convierta en una herramienta para atacar a terceros**, con todo el tráfico saliendo desde la IP pública del proyecto (con las consiguientes consecuencias legales, de reputación y de posible inclusión en listas negras). A continuación se detallan los riesgos identificados y las medidas adoptadas para cada uno.

### Riesgo 1: abuso de la emulación de wget y curl para amplificación de DDoS (SSRF)

El riesgo más documentado en Cowrie es el recogido en la vulnerabilidad **CVE-2025-34469**. Se trata de un fallo de tipo SSRF (Server-Side Request Forgery) en la emulación de los comandos wget y curl: en el modo de shell emulado (el que se usa por defecto), estas emulaciones realizan peticiones HTTP reales hacia el destino que indique el atacante. Al no existir un límite de ritmo en esas peticiones, un atacante no autenticado podía invocar repetidamente esos comandos para generar tráfico HTTP ilimitado contra una víctima, **usando el honeypot como nodo de amplificación de denegación de servicio** y enmascarando su propia IP tras la del honeypot.

**Cómo se mitiga en este proyecto:**

- La versión de Cowrie desplegada (3.0.10) es posterior a la 2.9.0, que es la que corrige oficialmente esta vulnerabilidad. Por tanto, **el despliegue no es vulnerable a este CVE concreto**.

- Además, y de forma independiente al parche, el cortafuegos de salida (egress) impone un límite de ritmo estricto a las conexiones salientes de los contenedores (ver apartado del egress). Esto significa que, aunque existiera un fallo similar, la máquina no podría generar el volumen de tráfico necesario para amplificar un ataque. **Es una defensa en profundidad: no se depende solo de que el software esté parcheado.**

### Riesgo 2: fuga de la emulación hacia el sistema real

Aunque Cowrie simula un sistema de ficheros y un shell falsos, no puede descartarse por completo que exista alguna vulnerabilidad que permita a un atacante escapar de la emulación y ejecutar código en el sistema real. **Es un riesgo bajo, pero no nulo.**

**Cómo se mitiga en este proyecto:**

- Cowrie se ejecuta dentro de un **contenedor Docker dedicado**, no directamente sobre el sistema anfitrión.
- El **contenedor está endurecido** (no-new-privileges, límites de memoria, CPU y número de procesos), de modo que un eventual escape se encontraría con un entorno restringido.
- El cortafuegos de salida **bloquea el acceso a redes internas y a la propia infraestructura**, impidiendo el movimiento lateral (pivoteo) incluso en caso de escape.

### Riesgo 3: uso indebido del modo proxy (alta interacción)

Cowrie dispone de un modo de alta interacción (proxy) que redirige el tráfico SSH hacia un sistema real. Si estuviera activado sin control, podría usarse para alcanzar otros sistemas.

**Cómo se mitiga en este proyecto:**

- **El despliegue usa el modo de shell emulado (backend = shell), no el modo proxy.** Se verificó en los registros de arranque de Cowrie. No hay ningún sistema real detrás al que redirigir.

### Riesgo 4: identificación de estar en un honeypot por el atacante

Un atacante que detecte que está ante un honeypot puede abandonar, falsear su comportamiento o, en el peor caso, tomar represalias. No es un riesgo de daño a terceros, pero **sí compromete el objetivo del proyecto (recoger inteligencia)**.

**Cómo se mitiga en este proyecto:**

- **Personalización de Cowrie** para aumentar su credibilidad (hostname, datos del sistema coherentes con un Debian real, usuarios y sistema de ficheros verosímiles), detallada en el apartado correspondiente.

Y una última cosa muy importante **a mencionar del riesgo 4:**

**La máquina Cowrie y Dionaea, de manera objetiva, es casi imposible que no se parezca a un honeypot.**

¿Por qué?

1. Son honeypots de media y baja interacción respectivamente, no tienen discos duros ni ningún almacenamiento fijo, si entras y creas un archivo, al salir se borra.

   Y eso delata.

2. Hay scripts genuinamente imposibles de recrear, estructuras de control o el uso de "python3".

   Y eso delata.

3. Comandos que pueden romper la simulación. Descargas de programas como "nmap", "masscan", o algo menos frecuente, actualizaciones o actualizar la máquina. ¿Acaso es realista programar que se pueda permitir la descarga de cualquier programa?

   Y eso delata.

**Ya con estos 3 motivos, espero que comprendas que es casi imposible recrear algo 100% realista.** La solución ante esto que no la vamos a utilizar, es un honeypot de alta interacción, una máquina real.

# 2. Arquitectura, infraestructura y conceptos.

Las explicaciones detalladas se encuentran en el documento principal. Este repositorio
cubre el apartado 3, Procedimientos.

## 2.1 Arquitectura

![Arquitectura](IMG/arquitectura.png)

## 2.2 Infraestructura

|  | VPS |
| ---: | :---   |
| CPU | 1 core |
| RAM | 2GB  |
| MEMORIA | 40GB (NVME) |
| IP('s) | 2 |
| ANCHO DE BANDA | 4TB/mes |
| S.O. | Debian 13, Trixie |
| HoneyPot | Cowrie + Dionaea |

# 3 Procedimientos

Empezaremos siguiendo no solo un orden lógico, sino de prioridad respecto a la importancia. El procedimiento sería el mismo para casi cualquier máquina de casi cualquier proveedor.

## 3.1 Lo único que NO es copiar y pegar.

Esta guía está pensada para copiar y pegar comandos sin pensar mucho. <br>Lleva explicaciones donde hacen falta, y hay momentos en los que tendrás que poner cosas: tus IPs, tus puertos, tus claves.

Estos son los nueve ficheros que vas a tener que tocar más adelante:

| Fichero | Apartado | Por qué no se puede copiar |
|---|---|---|
| `/etc/hosts` | 3.2.1 | Lleva el nombre de la máquina |
| `/etc/netplan/50-cloud-init.yaml` | 3.2.7 | Lleva la segunda IP pública |
| `/etc/ssh/sshd_config.d/99-hardening.conf` | 3.2.5, 3.2.6 | Puerto de administración y usuario permitido |
| `/etc/nftables.conf` (partes 1 y 2) | 3.3 | Se aplican **antes** de subir el repositorio: en ese momento no hay nada que copiar |
| `/etc/nftables.conf` (partes 3 y 4) | 3.3.2, 3.8.2 | Podrían copiarse; se pegan a propósito, porque el cortafuegos se revisa línea a línea y pegarlo obliga a mirarlo |
| `/opt/dirtyland/docker-compose.yml` | 3.4 | Lleva tus dos IPs públicas en el `ports:` |
| `/opt/dirtyland/cowrie/etc/cowrie.cfg` y `userdb.txt` | 3.4 | La leyenda y las contraseñas del señuelo |
| `/opt/dirtyland/Telegram Reports/telegram.cfg` | 3.4.2.7 | Tus dos tokens de bot y tu chat |
| `/opt/dirtyland/platform-reporter/config.ini` | 3.5.5.1, 3.8.1 | Las API keys de las cinco plataformas |

Durante toda la guía verás `[IP VPS]`, que es la de Cowrie, e `[IP VPS 2]`, que es la de Dionaea. Todo lo demás se pega tal cual.

## 3.2 Tras alquilar la VPS (tras realizar el pago)

### 3.2.1 Hacer de inmediato.

Para acceder a la máquina VPS se hará vía SSH.<br>
Cuando hagamos la compra, nos pedirá colocar la clave pública que generemos en nuestra máquina local. Es importante que la clave privada tenga contraseña, "passphrase".

En mi caso al usar Linux Mint:

```bash
ssh-keygen -t ed25519 -C "admin-honeypot"
```

Mostraremos la clave pública y la pegaremos en la página del proveedor VPS y confirmamos. 

```bash
cat ~/.ssh/honeypot_vps.pub
```

Gracias a esto ahora podremos acceder a la máquina.

> [!IMPORTANT]
> Si borramos la clave privada que tenemos localmente, nos quedamos sin acceso, entonces si quisiéramos cambiarla, tocará hacer otra privada, luego quitar la primera.

```bash
ssh -i ~/.ssh/honeypot_vps root@[IP]
```

Cambiar la contraseña del usuario que nos han proporcionado. Sea "root", "admin" o el que sea. De hecho nos deberían de haber mandado un correo avisando que la contraseña debe de ser cambiada lo antes posible.

Cuando estemos ya dentro vía ssh:

```bash
passwd
```

Este paso es el más urgente, a diferencia de los posteriores. Podemos también aprovechar ahora y cambiar el hostname en caso de que hiciera falta:

```bash
sudo hostnamectl set-hostname hostname
```

```bash
sudo nano /etc/hosts
```
Y dentro, en la misma línea de 127.0.0.1, al lado pones el "hostname".

**En mi caso me avisa de que no va a funcionar SOLO eso. Si tu caso NO ES como el mío sáltate el paso y continúa al 3.2.2. Si no, edita el fichero, pero vamos a editar y del cloud-init (la plantilla), el aviso es este:**

<pre>
    GNU nano 8.4                       /etc/hosts
# Your system has configured 'manage_etc_hosts' as True.
# As a result, if you wish for changes to this file to persist
# then you will need to either
# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl
# b.) change or remove the value of 'manage_etc_hosts' in
#     /etc/cloud/cloud.cfg or cloud-config from user-data
#
</pre>

```bash
sudo cp -a /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.bak-$(date +%F)
```

```bash
sudo tee /etc/cloud/cloud.cfg.d/99-dirtyland-hostname.cfg > /dev/null <<'EOF'
preserve_hostname: true
manage_etc_hosts: false
EOF
```

```bash
sudo sed -i 's/^\( *\)- update_etc_hosts$/\1# - update_etc_hosts/' /etc/cloud/cloud.cfg
```

```bash
grep -n "update_etc_hosts" /etc/cloud/cloud.cfg
```

Reiniciamos o `exec bash` abrimos una nueva terminal:

```bash
hostnamectl && cat /etc/hosts
```

### 3.2.2 Comprobaciones sobre nuestro producto.

La arquitectura de la VPS contempla <b>dos IPs públicas en la misma máquina</b>: 
- Una para el señuelo Linux (Cowrie, SSH/Telnet)
- y otra, separada, para el señuelo Windows (Dionaea, SMB/RPC/MSSQL).

El motivo de utilizar dos direcciones IP es que carece de sentido que Windows y Linux compartan la misma IP. Si Dionaea simulara un entorno Windows y otro basado en Debian 13 utilizando una única dirección IP, ello evidenciaría que la VPS es un honeypot.

Por eso, al contratar la VPS, solicitamos (o añadimos) una segunda IP pública.

Para cada una de las dos IPs comprobamos:

- Que el servidor está geográficamente posicionado en el sitio que hemos pedido.
- Que la IP tenga buena reputación. Y si no, pedimos una devolución.
  - Para ello buscaremos en estas páginas:
    - https://www.virustotal.com/gui/home/url
    - https://www.abuseipdb.com/
    - https://viz.greynoise.io/
    - https://www.shodan.io/
    - https://www.ipvoid.com/

- Que no tenga ningún nombre de dominio asociado a esa IP (Registro PTR), del dueño anterior. Por higiene y ética hacia esa persona que anteriormente usó esa IP.

![](IMG/Pasted%20image%2020261009175859.png)
![](IMG/Pasted%20image%2020261009175950.png)
- Comprobar los puertos y cosas expuestas de la máquina VPS.

<pre>
root@hostname:~# ss -tulnp
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port   Process                                                                         
udp     UNCONN   0        0             127.0.0.54:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=22))                                     
udp     UNCONN   0        0          127.0.0.53%lo:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=20))                                     
udp     UNCONN   0        0                0.0.0.0:5355          0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=11))                                     
udp     UNCONN   0        0                   [::]:5355             [::]:*       users:(("systemd-resolve",pid=4099,fd=13))                                     
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*       users:(("sshd",pid=6944,fd=6))                                                 
tcp     LISTEN   0        4096          127.0.0.54:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=23))                                     
tcp     LISTEN   0        4096       127.0.0.53%lo:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=21))                                     
tcp     LISTEN   0        4096             0.0.0.0:5355          0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=12))                                     
tcp     LISTEN   0        128                 [::]:22               [::]:*       users:(("sshd",pid=6944,fd=7))                                                 
tcp     LISTEN   0        4096                [::]:5355             [::]:*       users:(("systemd-resolve",pid=4099,fd=14))                                     
</pre>

**Mira la columna Local Address.** Si empieza por `127.` o `[::1]`, el puerto solo escucha dentro de la máquina y da igual lo que sea. Preocupa lo que escuche en `0.0.0.0`, en `[::]` o en una IP pública.

| Puerto | Qué es | ¿Expuesto? |
|---|---|---|
| 53 en `127.0.0.53` y `.54` | El resolvedor DNS de systemd | No, loopback |
| 25 | `exim4`, el correo local que trae Debian | No, loopback |
| 22 en `0.0.0.0` | Tu SSH. Lo único abierto ahora mismo, y el que vas a endurecer | Sí |
| 5355 en `0.0.0.0` | LLMNR, también de systemd-resolved | Sí, pero el nftables con `policy drop` lo tapa |

### 3.2.3 Requisitos previos al endurecimiento y configuración del host.

- Contratar Mullvad (en mi caso) y comprobar que funciona. Lo que el cortafuegos dejará entrar por SSH no es "la VPN" sino las **IP de salida de sus proxies SOCKS5**.
  Si la VPN funcionara pero no pasa por el proxy, la máquina te rechazará (3.2.6.3).

> [!IMPORTANT]
> Nunca una sola de esas IP, los relays se caen o los renumeran, y entonces tu propio cortafuegos te deja fuera. Aquí van tres, en países distintos.

- Y con el afán de no perder el acceso a la máquina, necesitamos que en nuestra página web del proveedor VPS tenga un panel de acceso vía web para configurar desde allí la máquina en caso de que falle el acceso SSH o cualquier cosa.

> [!TIP]
> Míralo **antes** de necesitarlo. Muchos lo sirven con un `noVNC` antiguo **sin portapapeles**, y ahí se teclea todo a mano. Que la contraseña de `root` sea larga, pero escribible.

### 3.2.4 Principio de menor privilegio.

Crearemos un usuario nuevo para no usar el root todo el rato ni accedamos con "root" vía SSH. 
<p>Actualizamos la máquina:</p>

```bash
apt update && apt upgrade -y
```

Y creamos un nuevo usuario. El nombre da totalmente igual, pues no se expondrá nada de la VPS.

```bash
adduser --gecos "" user
```

Le damos permisos de "sudo":

```bash
usermod -aG sudo user
```
Si sudo no existe se instala: `apt install sudo`.

```bash
groups user
```
Y nos tiene que aparecer algo como:

`[NOMBRE USUARIO]: [NOMBRE USUARIO] sudo users`

### 3.2.5 Acceso del nuevo usuario vía SSH.

> [!IMPORTANT]
> **Todavía como root:**

```bash
mkdir -p /home/user/.ssh
```
Para copiar las claves que generé en mi propio ordenador para acceder a root, serán copiadas para acceder al usuario nuevo:

```bash
cp /root/.ssh/authorized_keys /home/user/.ssh/authorized_keys
```

Como el creador ha sido "root" pues estamos con root, vamos a cambiar el propietario al usuario nuevo y dejar los permisos como los exige SSH. Van los tres encadenados con `&&`, en un solo pegado:

```bash
chown -R user:user /home/user/.ssh/ && chmod 700 /home/user/.ssh && chmod 600 /home/user/.ssh/authorized_keys
```

> [!NOTE]
> <b>`&&` y no `;`.</b> Con `&&` cada orden se ejecuta <b>solo si la anterior terminó bien</b> Si algo falla, la cadena se para en seco y el error se ve.

Si quieres comprobar de que todo OK:

```bash
ls -lah /home/user/.ssh/
```
Tendrá que mostrar:
- `drwx------` .
- `drwx------` ..
- `-rw-------` authorized_keys

Y si quieres comprobar de verdad que funciona prueba conectarte vía ssh con el usuario nuevo. Por si a caso, abrimos otra terminal sin cerrar esta y ejecutamos:

```bash
ssh -i ~/.ssh/claveprivada user@[IP]
```

```bash
whoami && echo " " && groups && echo " " && id && echo " " && sudo whoami
```

Mostrará: <br>
`user` <br>
`user sudo user` <br>
`uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),100(users)` <br>
`root`

### 3.2.6 Securizar SSH.

En este nuevo apartado:
- Abre una nueva terminal, CTRL + SHIFT + T, sin importar el sistema operativo.
- Se decidirá que puerto diferente al 22, usaremos para conectarnos vía SSH.
	- Buscamos que no sea 22, para que los bots no lo ataquen, porque apuntan por defecto a ese.
	- Y que tampoco sea de los evidentes: un `2222`, un `4444` o un `4445` están tan escaneados como el propio 22 y no te ahorran nada.
- Saber los nombres de los servidores proxy que usaremos para acceder exclusivamente desde esas IP's vía SSH y de ninguna otra forma.

Sobre el enfoque de seguridad operativa, conviene aclararlo para no confundir el objetivo: 
- Aquí no se busca un OPSEC sofisticado, del estilo de pagar la VPN en efectivo por correo para no dejar rastro financiero. No hace falta, porque ese rastro solo lo verían bancos o gobiernos, y el modelo de amenaza de este proyecto es otro bastante más acotado. 
- De Mullvad se quiere una cosa concreta: que oculte la IP real haciendo él las peticiones. Lo que sí conviene custodiar bien es el número de cuenta de Mullvad, porque funciona a la vez como usuario y como contraseña.

#### 3.2.6.1 En caso de que vayas a acceder desde Linux.

> [!IMPORTANT]
> **En nuestra máquina anfitriona, NO LA VPS.**

Tal y como hemos dicho, vamos a acceder vía Proxy SOCKS, entonces lo primero que necesitamos saber son las IP y los servidores en sí.

Mullvad publica la lista entera en su API. Esto saca los relays que tienen SOCKS5 **y están activos**, con su país y su ciudad:

```bash
curl -s https://api.mullvad.net/www/relays/all/ | jq -r '.[] | select(.socks_name and .active) | [(.socks_name | sub("\\.relays\\.mullvad\\.net$";"")), .country_name, .city_name] | @tsv' | sort | awk -F'\t' '{printf "%-26s %-20s %s\n", $1, $2, $3}'
```

Son más de quinientos, así que lo normal es filtrar. El país va en inglés, así que España es `spain`:

```bash
curl -s https://api.mullvad.net/www/relays/all/ | jq -r '.[] | select(.socks_name and .active) | [(.socks_name | sub("\\.relays\\.mullvad\\.net$";"")), .country_name, .city_name] | @tsv' | grep -i spain | awk -F'\t' '{printf "%-26s %-20s %s\n", $1, $2, $3}'
```

Si no tienes `jq`, `sudo apt install -y jq`.

**Elige tres, en países distintos:** uno principal y dos de respaldo. El nombre que necesitas es el de la izquierda, sin el sufijo `.relays.mullvad.net`.

Ahora el fichero. La configuración no va escrita aquí dentro: está en el repositorio, en **[Local SSH/For Linux/config](Local%20SSH/For%20Linux/config)**. Ábrelo, cópialo entero y pégalo al final de tu `~/.ssh/config`.

Guardando antes una copia del que hubiera, y abriéndolo para pegar:

```bash
cp ~/.ssh/config ~/.ssh/config.bak 2>/dev/null; nano ~/.ssh/config
```

Ya pegado, se sustituyen los huecos que van entre `< >`:

| Hueco | Por |
|---|---|
| `<IP a la que te vas a conectar>` | la IP pública de tu VPS |
| `<Futuro puerto SSH>` | el puerto que pondrás en el 3.2.6.3 |
| `<proxy principal>` | el relay que hayas elegido arriba, sin el `.relays.mullvad.net` |
| `<proxy-respaldo-1>` y `<proxy-respaldo-2>` | los otros dos |
| `<pais-1>` y `<pais-2>` | el nombre que quieras darles a los dos alias de respaldo (`se`, `fr`, `jp`...) |

Y se le dejan los permisos que SSH exige:

```bash
chmod 600 ~/.ssh/config
```

**Comprobamos (opcional)**. Esto lee del propio fichero los alias que hayas puesto, así que vale se llamen como se llamen:

```bash
for h in $(awk '/^Host dirtyland/{print $2}' ~/.ssh/config); do
  echo "=== $h ==="
  ssh -G $h | grep -Ei '^(hostname|port|user|identityfile|proxycommand)'
done
```

#### 3.2.6.2 Si tu equipo es Windows.

> [!IMPORTANT]
> **En nuestra máquina anfitriona, NO LA VPS. Si has hecho el 3.2.6.1 no hagas este.**

Escrito sobre Windows 11 Pro.<br>
El cliente de OpenSSH viene de serie desde Windows 10, lee el mismo `~/.ssh/config` y trae `ssh`, `scp` y `ssh-add`; no hay que instalar nada.

**1. Elegir los tres proxys.**

La misma lista de Mullvad que en Linux, aquí con PowerShell. Salen los relays con SOCKS5 activos, ordenados por país:

```powershell
(Invoke-RestMethod https://api.mullvad.net/www/relays/all/) | Where-Object { $_.socks_name -and $_.active } | Sort-Object country_name, city_name | Format-Table @{n='Proxy';e={$_.socks_name -replace '\.relays\.mullvad\.net$',''};width=26}, @{n='Pais';e={$_.country_name};width=20}, @{n='Ciudad';e={$_.city_name};width=22}
```

Son más de quinientos. Para filtrar por país, se añade el filtro:

```powershell
(Invoke-RestMethod https://api.mullvad.net/www/relays/all/) | Where-Object { $_.socks_name -and $_.active -and $_.country_name -eq 'Spain' } | Format-Table @{n='Proxy';e={$_.socks_name -replace '\.relays\.mullvad\.net$',''};width=26}, @{n='Ciudad';e={$_.city_name};width=22}
```
Como podemos ver nos muestra los servidores de España, Spain. Si quisiéramos de otro país pues quitamos Spain y ponemos el país en cuestión en inglés.

**Elige tres, en países distintos:** uno principal y dos de respaldo. El nombre que necesitas es el de la columna `Proxy`, sin el sufijo `.relays.mullvad.net`.

**2. Comprobar que tienes `connect.exe`.**

El `ProxyCommand` de Linux usa `nc -X 5` para hablar SOCKS5 con el relay, y Windows no trae netcat. Lo sustituye `connect.exe`, que viene con **Git para Windows** (si has clonado este repositorio, lo tienes):

```powershell
Test-Path "C:\Program Files\Git\mingw64\bin\connect.exe"
```

Tiene que responder `True`. <br>
Si responde `False`, instala Git para Windows y repite la comprobación:

```powershell
winget install --id Git.Git -e
```

**3. Crear la carpeta `.ssh` y dejar dentro la clave privada.**

```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ssh" | Out-Null
```

Copia ahí `honeypot_vps` (el fichero es el mismo que en Linux, se copia tal cual) y comprueba que está donde toca:

```powershell
Test-Path "$env:USERPROFILE\.ssh\honeypot_vps"
```

**4. Escribir el fichero `%USERPROFILE%\.ssh\config`.**

Ese es el fichero que hay que editar. La configuración no va escrita aquí dentro: está en el repositorio, en **[Local SSH/For Windows/config](Local%20SSH/For%20Windows/config)**. Es la misma que la de Linux salvo la línea del `ProxyCommand`, que llama a `connect.exe` en vez de a netcat. Ábrelo, cópialo entero y pégalo al final de tu `config`.

Guardando antes una copia del que hubiera, y abriéndolo para pegar (si no existe, el Bloc de notas te ofrece crearlo):

```powershell
if (Test-Path "$env:USERPROFILE\.ssh\config") { Copy-Item "$env:USERPROFILE\.ssh\config" "$env:USERPROFILE\.ssh\config.bak" -Force }
notepad "$env:USERPROFILE\.ssh\config"
```

Ya pegado, se sustituyen los huecos que van entre `< >`:

| Hueco | Por |
|---|---|
| `<IP a la que te vas a conectar>` | la IP pública de tu VPS |
| `<Futuro puerto SSH>` | el puerto que pondrás en el 3.2.6.3 |
| `<proxy principal>` | el relay que hayas elegido arriba, sin el `.relays.mullvad.net` |
| `<proxy-respaldo-1>` y `<proxy-respaldo-2>` | los otros dos |
| `<pais-1>` y `<pais-2>` | el nombre que quieras darles a los dos alias de respaldo (`se`, `fr`, `jp`...) |

> [!IMPORTANT]
> **Al guardar, el fichero se llama `config`, sin extensión.** El Bloc de notas le añade `.txt` por su cuenta si no eliges "Todos los archivos" en el desplegable de tipo. Un `config.txt` no lo lee nadie, y el síntoma es que `ssh dirtyland` responde que no conoce ese host.
>
> Y en "Codificación", **UTF-8**, no "UTF-8 con BOM": esos tres bytes invisibles al principio bastan para que OpenSSH no entienda la primera línea. La plantilla es ASCII puro a propósito por eso sus comentarios van sin tildes, así que cualquiera de las dos opciones sin BOM vale.

**5. Permisos de la clave privada.**

En Windows los permisos son ACL, no bits de Unix, así que aquí no hay `chmod 600`. OpenSSH se niega a usar una clave privada que puedan leer otros, y sin esto falla con `UNPROTECTED PRIVATE KEY FILE`:

```powershell
icacls "$env:USERPROFILE\.ssh\honeypot_vps" /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

`/inheritance:r` corta los permisos heredados de la carpeta que es de donde viene el problema y `/grant:r` deja solo a tu usuario, con lectura. Sin el primero, el segundo no arregla nada: los heredados siguen ahí.

**6. Encender el agente SSH.**

La clave tiene contraseña. En Linux el agente ya está en marcha; en Windows el servicio existe pero **viene deshabilitado**, así que `ssh dirtyland` te la pediría cada vez. En una PowerShell **como administrador**:

```powershell
Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent
```

Si responde `Acceso denegado` es que esa PowerShell no era de administrador. Compruébalo antes de pelearte con ello, porque puede que ya estuviera hecho:

```powershell
Get-Service ssh-agent | Select-Object Name, Status, StartType
```

Si sale `Running` y `Automatic`, el error daba igual: ya estaba como tiene que estar.

Y después, en una PowerShell normal, se añade la clave, la contraseña se teclea aquí, una sola vez:

```powershell
ssh-add "$env:USERPROFILE\.ssh\honeypot_vps"
```

**7. Comprobar.**

Esto lee del propio fichero los alias que hayas puesto, así que vale se llamen como se llamen. No conecta con nada: solo enseña lo que `ssh` ha entendido.

```powershell
$alias = Select-String -Path "$env:USERPROFILE\.ssh\config" -Pattern '^Host (dirtyland\S*)' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique
foreach ($h in $alias) { "=== $h ==="; ssh -G $h | Select-String -Pattern '^(hostname|port|user|identityfile|proxycommand)' }
```

#### 3.2.6.3 Volviendo al securizar SSH.

> [!IMPORTANT]
> **DENTRO DE LA VPS, con el usuario nuevo, NO como root.**

El endurecimiento va en un fichero propio dentro de `sshd_config.d/`, y no editando el `sshd_config` principal, por organización: queda identificado y localizable en vez de mezclado con lo que trajera la imagen del proveedor.

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Estará vacío, le añadimos:

```conf
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers user
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
```
La configuración primera de SSH básicamente:
- Buscamos denegar la posibilidad de acceder con root vía SSH.
- Sólo el "user" nuevo creado podrá.
- Prohibido usar contraseña para autenticarnos, solo clave privada.
- Aquí el puerto sigue siendo 22 para acceder, luego lo cambiaremos.

Comprobamos la sintaxis:

```bash
sudo sshd -t
```

```bash
sudo systemctl reload ssh
```

Una vez se haya aplicado tras el reinicio, vamos a obligar a que se acceda exclusivamente a través de los proxies SOCKS5 de Mullvad. Por lo tanto:
- Necesitamos saber las IP's que usaremos, 2 como mínimo y 3 como máximo.
- Que puerto SSH será desde el que a futuro accederemos, en mi caso he establecido el `56769`.

**Y esas IP no son las que da la API de Mullvad.** `ipv4_addr_in` es la de **entrada** al relay; la que tu VPS verá llegar, y por tanto la que hay que permitir, es la de **salida**. Se pregunta a través del propio proxy, **desde tu equipo y con el túnel levantado**. 

<b>En Linux:</b>

```bash
curl -sS -x socks5h://<proxy>.relays.mullvad.net:1080 https://am.i.mullvad.net/ip
```

<b>En Windows lo mismo, con `curl.exe`:</b>

```bash
curl.exe -sS -x socks5h://<proxy>.relays.mullvad.net:1080 https://am.i.mullvad.net/ip
```

Una vez por cada uno de los tres proxys, cambiando el nombre. Esas tres direcciones son las que van en las reglas de abajo. Y vuelve a mirarlas si algún día pierdes el acceso, porque **Mullvad las renumera**.

Si en vez de una IP te sale `curl: (28) Connection timed out`, ese relay está de baja. No es cosa tuya y no se arregla esperando: elige otro y vuelve a listar, que el listado de arriba ya solo enseña los que están activos. El `-sS` está justo para eso silencia el contador de progreso pero **no** los errores, porque con `-s` a secas un relay caído no imprime nada y parece que no ha pasado nada.

```bash
sudo apt install nftables -y
```

Para comprobar de que realmente se ha instalado:

```bash
sudo nft --version
```

Y nos devolverá algo como: `nftables v1.1.3 (Commodore Bullmoose #4)`.

Borramos el contenido que llevara dentro sin eliminar el fichero en sí. Muy importante no eliminarlo entero con tal de que esté vacío porqué de pereza borrar manualmente con el nano lo que lleve dentro:

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

> [!IMPORTANT]
> Y aquí usaremos el contenido del archivo **[CORTAFUEGOS/nftables-PART-1.txt](CORTAFUEGOS/nftables-PART-1.txt)** del repositorio. Ojo al nombre: lleva guion también antes del número.
> Aquí se establecerá tanto el puerto nuevo que hemos elegido, como el 22 ssh, para no cerrar la sesión ssh que teníamos actualmente.

Para comprobar la sintaxis del fichero:

```bash
sudo nft -c -f /etc/nftables.conf
```

Aplicamos:

```bash
sudo nft -f /etc/nftables.conf
```

Ahora modificamos el fichero ssh para añadir el puerto nuevo (Ya que hemos hecho la regla de cortafuegos que acepte solo desde X IP a puerto Y que es el nuevo puerto para SSH):

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```
Así quedará:

```conf
Port 22
Port 56769
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers user
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
```

El `Port 22` tiene que ir escrito, no vale con omitirlo: en cuanto declaras explícitamente cualquier `Port`, SSH deja de escuchar en el 22 por defecto y atiende solo en los que le indiques. Si pusieras únicamente `Port 56769`, perderías el 22 en cuanto recargaras.

Comprobamos sintaxis:

```bash
sudo sshd -t
```

```bash
sudo systemctl reload ssh
```

La `-t` minúscula solo dice si el fichero está bien escrito. Para ver **qué configuración queda de verdad**, una vez combinados el `sshd_config` principal, lo que trajera el proveedor y nuestro fichero, está la `-T` mayúscula, que vuelca la configuración efectiva final:

```bash
sudo sshd -T | grep -Ei '^(port|permitrootlogin|pubkeyauthentication|passwordauthentication|allowusers|maxauthtries)'
```

Si alguna directiva no sale con el valor que acabas de escribir, es que otro fichero la está pisando.

Abrimos otra terminal, **sin cerrar la anterior (CTRL + SHIFT + T)**, que es el salvavidas: una sesión ya iniciada no se cae aunque cambies la configuración, porque los cambios solo afectan a las conexiones nuevas, así que es con la que revertirías si algo saliera mal. Con ella abierta probamos acceder con la VPN activada y da igual el servidor (por lo tanto con ese puerto nuevo que pusimos):

> [!IMPORTANT]
> Imprescindible no olvidar que las reglas de cortafuegos hemos dicho que SOLO SE ACCEDE DESDE LAS IP Proxy de Mullvad, es decir, que da igual que tengas la VPN activada, si intentas acceder vía ssh a la VPS no te dejará, porque NO estarás usando la IP del proxy, para usar la IP del proxy hay que ejcutar comandos, etc... 
> 
> Y por eso hicimos lo del principio de crear un alias o shortcut. Y da igual a que servidor VPN te conectes, siempre usará los mismos proxys que le has puesto al ejecutar ese alias.

```bash
ssh dirtyland
```

Funcionará.

> [!TIP]
> Se recomienda por lo tanto probar con los tres alias, uno por proxy, y después intentar entrar sin pasar por ninguno. Eso último NO debería dejarnos.

```bash
ssh dirtyland-<pais-1>
```

```bash
ssh dirtyland-<pais-2>
```

Sustituyendo `<pais-1>` y `<pais-2>` por los nombres que les hayas puesto a tus dos alias de respaldo. Si no te acuerdas, los lista el fichero: `grep '^Host dirtyland' ~/.ssh/config`.

> [!TIP]
> **Si en vez de entrar te sale un error, los tres sospechosos, por orden:**
>
> - `Could not resolve hostname dirtyland` -> `ssh` no encuentra el alias. En Windows lo habitual es que el fichero se guardara como `config.txt`; en los dos sistemas, que no esté en la carpeta `.ssh` de tu usuario.
> - `UNPROTECTED PRIVATE KEY FILE` -> los permisos de la clave privada. En Linux es el `chmod 600`; en Windows, el `icacls` del apartado 3.2.6.2, que corta la herencia de la carpeta.
> - `Permission denied (publickey)`, y `ssh -vv dirtyland` enseña `Server accepts key: ...honeypot_vps` justo antes -> **no es la clave ni el servidor**: el servidor dice que la acepta. Es que `ssh` no ha podido firmar porque no tiene la contraseña de la clave. Falta cargarla en el agente con `ssh-add` (o se está ejecutando sin terminal interactiva, o con `BatchMode=yes`).

Tras esto volvemos a editar el fichero de ssh y quitamos oficialmente el puerto 22 y lo dejamos solo en el puerto que queríamos (56769):

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```
Solo quitamos el puerto 22.
```conf
Port 56769
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers user
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
```

Y ya está. <br>
Probablemente nos preguntemos: <br><i>¿Y que pasa con la regla de cortafuegos del puerto 22<br>
¿Hay que quitarla?</i><br>
No, la dejamos, la usará Cowrie, y luego redirigirá de 22 --> 2222.

Muy importante hacemos un reload, porque aunque hayamos establecido lo del puerto y en efecto no nos deje entrar, internamente ese puerto sigue ocupado. Y más adelante no nos permitirá montar el Cowrie sobre el 22. 

Este comando NO NOS CORTA LA CONEXIÓN. Como lo haría un `restart`.

```bash
sudo systemctl reload ssh
```

Realizamos un:

```bash
sudo ss -tlnp | grep -E ':(22|56769) '
```

Para asegurarnos de que se ha liberado de verdad. Nos tiene que aparecer así:

<pre>
LISTEN 0      128          0.0.0.0:56769      0.0.0.0:*    users:(("sshd",pid=639,fd=6))            
LISTEN 0      128             [::]:56769         [::]:*    users:(("sshd",pid=639,fd=7))
</pre>

```bash
sudo systemctl enable nftables
```

```bash
sudo systemctl start nftables
```

Además muy importante vamos a intentar hacer conexión vía el puerto 22 para ver si realmente ya NO podemos entrar a ssh por ese puerto en cuestión. Desde fuera, nuestra propia máquina probaremos:

```bash
ssh -i ~/.ssh/honeypot_vps -p 22 user@[IP VPS]
```

`ssh: connect to host [IP VPS] port 22: Connection refused`
- `refused` significa alcanzable pero sin servicio. `timed out` significa filtrado.
- **Puerto 22, refused:** El cortafuegos tiene tcp dport 22 accept, así que el paquete SYN atraviesa nftables y llega al kernel. Pero en ss -tulnp no hay nada escuchando en el 22: solo el 56769. Al no encontrar proceso asociado, el kernel responde con un RST, y tu nc lo traduce como conexión rechazada. Es decir, llegaste hasta el final del recorrido y te contestaron que ahí no hay nadie.
- **Puertos 23 o uno inventado, timed out:** No existe regla que los acepte, así que caen en policy drop. El paquete se descarta sin generar respuesta alguna, y tu cliente se queda esperando hasta agotar los tres segundos del -w 3.

### 3.2.7 Configuración de la segunda IP.

Como establecimos en el diseño (apartado 3.2.2), la máquina dispone de dos IPs públicas: la principal (`[IP VPS]`) para Cowrie y una segunda (`[IP VPS 2]`) para Dionaea. El proveedor asigna esta segunda IP en una interfaz propia (`ethX`), gestionada por cloud-init. Tras un reinicio de la máquina, la interfaz aparece configurada automáticamente.

<b>(Opcional)</b>

```bash
sudo reboot
```

Al volver, comprobamos que la IP está presente:

```bash
echo " " && hostname -I && echo " " && ip -br a
```

El único ajuste necesario es eliminar el conflicto de doble ruta por defecto que introduce la nueva interfaz. Editamos el netplan y quitamos el bloque `routes` de `ethX` (dejando solo su IP, sin ruta por defecto propia). La interfaz a veces puede ser la `eth2`, la `eth1` o la que sea. En mi caso son tres interfaces.

Copia de seguridad por lo que sea.

```bash
sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init__$(date +%Y-%m-%d_%H:%M:%S).yaml.bak
```

No vamos a borrar su contenido ni nada, porque tiene asociadas ya las IP's y MAC's, todo está correcto y solo buscamos eliminar una cosa:

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

A diferencia de otras veces, aquí no podemos copiar y pegar sin más, por cada vez que se formatea o hay una máquina nueva, las MAC's cambian. Entonces, importar lo que una instancia o máquina anterior usaba (Como sus MAC's) no tiene sentido.

**Quitas el bloque routes de eth1.**

<pre>
      routes:
      - to: "default"
        via: "&lt;IP Gateway&gt;"
</pre>

Es importante mencionar, que en MI caso el `eth2` corresponde a IPv6, y nada más, simplemente mi VPS no pone IPv4 e IPv6 en una misma interfaz, sino que separa y aisla todo.

Verificamos la sintaxis:

```bash
sudo netplan generate
```

Aplicamos con red de seguridad (se revierte solo a los 20 segundos, en caso de que perdamos acceso):

```bash
sudo netplan try --timeout 20
```

Si el acceso se mantiene, confirmamos con ENTER y lo hacemos persistente:

```bash
sudo netplan apply
```

Verificamos que queda **una sola** ruta por defecto:

```bash
ip route show default
```

Tiene que salir **exactamente una línea**. Si salen dos, el bloque `routes` sigue puesto en algún sitio y hay que volver al `nano`.

Y que las dos IP públicas siguen ahí:

```bash
ip -4 -br addr show scope global
```

<pre>
eth0             UP             [IP VPS]/24
eth1             UP             [IP VPS 2]/24
</pre>

El comando no lleva escrito el nombre de la interfaz a propósito: aquí la segunda IP está en `eth1`, pero en otra máquina puede estar en `eth2`, y con el nombre fijo no devolvería nada y parecería que la IP se ha perdido cuando solo se llama de otra forma. Así las lista **todas** con su interfaz, y comprueba las dos IP y no solo la segunda: si la que faltara fuera la primera, Cowrie se quedaría sin dónde escuchar.

## 3.3 Docker + cortafuegos.

Se siguió la guía oficial de Docker para Debian (https://docs.docker.com/engine/install/debian/), sin desviaciones sustanciales respecto al procedimiento recomendado.
Requisitos previos y eliminación de paquetes en conflicto:

```bash
sudo apt update
```
```bash
sudo apt install -y ca-certificates curl
```
```bash
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt remove -y $pkg; done
```
En el servidor no había ningún paquete en conflicto instalado previamente, por lo que este paso no eliminó nada.

Incorporación de la clave GPG oficial de Docker al llavero de APT, necesaria para que APT pueda verificar la autenticidad de los paquetes:
```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

```bash
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
```

```bash
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

Declaración del repositorio oficial de Docker: primer intento fallido y corrección aplicada.
La guía oficial resuelve el codename de la distribución y la arquitectura mediante sustitución de comandos dentro de un heredoc:
```bash
printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: trixie\nComponents: stable\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/docker.asc\n' | sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null
```
  
Instalación del motor y sus componentes:

```bash
sudo apt update
```

```bash
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Verificación de la instalación:

```bash
sudo docker version
```

```bash
sudo systemctl status docker --no-pager
```

La versión instalada fue Docker Engine 29.6.1, con backend de iptables sobre la capa de compatibilidad iptables-nft (Experimental: false), que es el backend estable recomendado por Docker en la fecha de este despliegue; el backend nativo de nftables sigue siendo experimental en esta versión. El servicio quedó activo (systemctl status docker mostró "active (running)").

No se añadió el usuario administrador al grupo docker. Pertenecer a ese grupo equivale en la práctica a tener acceso root sin contraseña, ya que Docker no dispone de un mecanismo de verificación equivalente al de sudo. En un host destinado a exponerse a atacantes reales, esa vía de escalada trivial no es asumible. Todos los comandos de Docker se ejecutan con sudo.

### <u>3.3.1 Teoría DNAT y comprender las reglas de cortafuegos (Opcional).</u>

Este apartado es teoría y no hay nada que ejecutar.<br>
Explica por qué todas las reglas que controlan los señuelos van en la cadena `forward` y no en la `input`. <br>
Si ya lo tienes claro, sáltatelo.

**El problema.** Cowrie y Dionaea son contenedores, y un contenedor no tiene dirección pública. Docker les reparte direcciones privadas de su red interna, en nuestro caso `172.20.0.10` para Cowrie y `172.20.0.20` para Dionaea, con el anfitrión en `172.20.0.1` a través del puente `dirtyland0` (usamos un puente propio en vez del `docker0` de serie, y nada más). Esas direcciones solo existen dentro del servidor. La única interfaz expuesta a internet es la `eth0` y la `eth1` (_o incluso `eth2`, ya depende de tu caso_) del anfitrión. Así que la pregunta es cómo llega un atacante hasta los contenedores, y la respuesta es el DNAT.

**¿Pero antes de eso, qué es NAT?** <br>
NAT (*Network Address Translation*) no es un protocolo, es una técnica. Un protocolo define cómo dialogan dos partes: el formato de los mensajes, el orden, el significado de cada campo, como hacen IP, TCP o HTTP. <br>
NAT no define ningún mensaje nuevo. Lo que hace es reescribir las direcciones de la cabecera de los paquetes de otros protocolos al pasar por un dispositivo intermedio. Opera sobre las direcciones IP, que son de capa 3, pero cuando además reescribe puertos (la variante PAT o NAPT, que es justo lo que ocurre al mapear un puerto del anfitrión a un contenedor) toca también la capa 4. Lo riguroso es decir que actúa sobre la capa 3 y, a menudo, sobre los puertos de la 4.

Dentro de NAT hay dos variantes, según qué dirección se reescriba:

| | Qué reescribe | Caso habitual |
|---|---|---|
| **SNAT** (*Source NAT*) | La dirección de **origen** | Salir a internet: tu IP privada se traduce a una pública para que el destino sepa a dónde responder. Es lo que hace el router de casa. |
| **DNAT** (*Destination NAT*) | La dirección de **destino** | Un paquete que llega a una IP pública se redirige a una máquina interna. Es "abrir un puerto", y es exactamente lo que hace Docker al publicar el de un contenedor. |

Lo que define a cada una es qué extremo reescribe, con independencia de los tipos de dirección implicados.

**¿Quién decide la cadena (input o forward)?** <br>
Que exista un DNAT no determina por sí solo si el tráfico irá a `input` o a `forward`. Lo determina **la naturaleza del destino ya reescrito**: si corresponde a la propia máquina, va a `input`; si corresponde a otra máquina o a un contenedor al que el anfitrión debe reenviar, va a `forward`. Como el destino reescrito es el contenedor, que a efectos de red es otra máquina, el tráfico de los señuelos va **siempre** a `forward`.

Que el paquete pase físicamente por el anfitrión da igual, porque para el cortafuegos cuenta a quién va dirigido, no por dónde entra. Y eso lo decide el núcleo en una secuencia fija. El orden es la clave:

1. El paquete entra por `eth0` con destino `[IP VPS 2]:445`, nuestra IP pública.
2. **Fase de PREROUTING.** Aquí se aplica el DNAT que Docker creó al publicar el puerto. El destino se reescribe y ahora el paquete va a `172.20.0.20:445`, el contenedor de Dionaea. La traducción ocurre **antes** de que el núcleo decida el camino.
3. **Decisión de enrutado.** El núcleo mira el destino, que ya está reescrito, y comprueba si esa IP es suya o de otra máquina. Como `172.20.0.20` no es del anfitrión, concluye que el paquete es de reenvío.
4. Al ser de reenvío, entra en la cadena `forward`. **Nunca toca la `input`.**

Tal y como vemos, la cadena `input` protege el tráfico dirigido a la propia máquina, como el SSH de administración del 56769, pero **no ve el tráfico de los contenedores**. Ese viaja por `forward`. Por eso todas las reglas que controlan los señuelos, tanto la entrada hacia ellos como la salida hacia internet, se escriben en `forward`, el único punto donde el anfitrión, actuando de router, decide qué reenvía y qué no.

**Dónde mirar, entonces.**

| Para saber... | Mira | Es tuya |
|---|---|---|
| Si el anfitrión está protegido | `table inet filter`, cadena `input` | Sí. Ahí está tu SSH del 56769 restringido a los proxies. |
| Si los señuelos están protegidos o expuestos | `table inet filter`, cadena `forward` | Sí. Es tu punto de control real sobre Docker. |
| Qué está haciendo Docker por debajo | `table ip nat` y `table ip filter` | No. El propio núcleo avisa con el `do not touch`. Se leen, no se editan. |

Y la distinción entre las dos tablas de Docker: **`ip nat` traduce direcciones, `ip filter` decide si el paquete pasa**.

En `table ip nat` vive el DNAT del que hemos hablado. Su cadena `PREROUTING` es exactamente la fase donde se reescribe el destino de lo que entra. Con la pila levantada y el 445 publicado, ahí aparece la regla que traduce tu IP pública al contenedor; con la pila parada, la cadena `DOCKER` está vacía porque no hay nada publicado. Esta tabla no bloquea ni permite nada, solo traduce. Su `POSTROUTING` hace el trabajo inverso, el SNAT: la regla de *masquerade* es la que permite que, cuando un contenedor habla hacia fuera, su `172.x` se reescriba a la pública para que la respuesta sepa volver.

En `table ip filter` es donde Docker decide si el tráfico ya traducido pasa, con su propia cadena `FORWARD` (distinta de la tuya) y sus subcadenas `DOCKER-USER`, `DOCKER-FORWARD` y demás. Esa sí permite o bloquea, pero recuerda lo que se verifica en el 3.3.2: tu `forward` de `inet filter` y la `FORWARD` de Docker cuelgan del mismo punto del núcleo, y como un `drop` es final, **tu `drop` manda por encima de lo que Docker permita**. Por eso la tuya es el guardián y la de Docker es secundaria para ti.

### 3.3.2 Cortafuegos POST Docker.

Primero, copia de seguridad del fichero anterior:

```bash
sudo cp /etc/nftables.conf /etc/nftables__$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```
De nuevo lo vacíamos:
```bash
sudo truncate -s 0 /etc/nftables.conf
```

Y **ponemos la parte 2 del cortafuegos**, que es el contenido de **[CORTAFUEGOS/nftables-PART-2.txt](CORTAFUEGOS/nftables-PART-2.txt)** del repositorio.

```bash
sudo nano /etc/nftables.conf 
```

Tal y como hicimos anteriormente ponemos la parte 2 sin más.

**Es lo mismo que la parte 1, pero con un único cambio.** <br>
En la parte 1 el fichero empezaba con `flush ruleset`. No hacía daño, porque Docker aún no estaba instalado y no había nada más que borrar. Pero ahora sí. 

Docker ha creado sus propias tablas (`ip nat`, `ip filter`, `ip6 nat` e `ip6 filter`), que conviven con la nuestra (`inet filter`) sin pisarse porque son de familias y nombres distintos. Pero `flush ruleset` **no vacía solo lo nuestro: lo borra todo**, también las de Docker, y deja los contenedores sin traducción de direcciones ni filtrado hasta que Docker las vuelve a crear.

Por eso en la parte 2 ese `flush ruleset` se sustituye por dos líneas que reinician únicamente nuestra tabla: `add table inet filter` y `delete table inet filter`.

El `add` crea la tabla si no existe, de modo que el `delete` posterior nunca falle por intentar borrar algo inexistente y el `delete` la elimina para volver a definirla limpia justo después. El efecto es un reinicio de nuestra tabla y solo de la nuestra.

Antes de aplicarlo, que la sintaxis esté bien:

```bash
sudo nft -c -f /etc/nftables.conf
```

Después de escribir el fichero, los comandos que confirmaron que la corrección funciona son:

```bash
sudo nft -f /etc/nftables.conf
```
```bash
sudo nft list tables
```
Y la salida que tiene que devolver:
- table ip nat
- table ip filter
- table ip6 nat
- table ip6 filter
- table inet filter

## 3.4 Cowrie + Dionaea.

> [!IMPORTANT]
> ### Botón del pánico.
>
> Para parar el docker compose:
>
> ```bash
> sudo docker compose -f /opt/dirtyland/docker-compose.yml down
> ```
>
> Y para vaciar la cadena `forward`, que queda en denegación porque `flush` borra las reglas pero no toca la política:
>
> ```bash
> sudo nft flush chain inet filter forward
> ```
>
> Van de mayor a menor contundencia. Después de cualquiera de los dos, <b>compruébalo, no lo supongas</b>:
>
> ```bash
> sudo docker ps
> sudo ss -tulnp
> ```
>
> El primero tiene que salir vacío. En el segundo no puede quedar nada de Cowrie ni de Dionaea: solo puertos internos de loopback y servicios ajenos al proyecto.

<b>1. Preparación de carpetas</b>

Todo el proyecto vive bajo `/opt/dirtyland`. En vez de ir creando carpetas a trozos a lo largo del documento, montamos **el árbol completo de una sola vez**: así el punto de partida es siempre idéntico, el montaje es reproducible y ningún apartado posterior falla porque falte un directorio.

```bash
sudo mkdir -p \
  /opt/dirtyland/cowrie/{etc,fs,honeyfs,cmdpatch,keys,parches} \
  /opt/dirtyland/cowrie/txtcmds/usr/bin \
  /opt/dirtyland/dionaea/services-enabled \
  "/opt/dirtyland/Telegram Reports/state" \
  /opt/dirtyland/geoip \
  /opt/dirtyland/monitor \
  /opt/dirtyland/platform-reporter \
  /var/lib/dirtyland-reporter \
  /var/log/dirtyland-reporter
```

El árbol queda así:

<pre>
/opt/dirtyland/
├── docker-compose.yml       # la pila: Cowrie + Dionaea
├── build-dirtyland-fs.sh    # generador del sistema de ficheros falso (3.4.2.3)
├── cowrie/
│   ├── etc/                 # cowrie.cfg, userdb.txt, ps_command_output.json, ayudas-comandos.json
│   ├── fs/                  # fs.pickle: los METADATOS del sistema falso
│   ├── honeyfs/             # el CONTENIDO de los ficheros (aquí se extrae el /home)
│   ├── cmdpatch/            # los .py de los comandos emulados, ya parcheados
│   ├── parches/             # ficheros de la IMAGEN que corregimos (3.4.2.8): protocol.py
│   ├── keys/                # las claves de host SSH, generadas con ssh-keygen (3.4.2.10)
│   └── txtcmds/             # salidas enlatadas que sustituyen a las de Cowrie (3.4.2.8)
├── dionaea/
│   └── services-enabled/    # solo los servicios coherentes con un Windows
├── Telegram Reports/        # alertas de Cowrie: plugin de salida + baneos
│   └── state/               # el ÚNICO directorio con escritura para el contenedor
├── monitor/                 # vigilancia del anfitrión: send-alert.sh, digest, watchers
└── platform-reporter/       # reporte a AbuseIPDB / VirusTotal / MalwareBazaar / ThreatFox / URLhaus
    ├── orchestrator.py      # punto de entrada unico para los dos honeypots
    ├── collectors/          # leen Cowrie y Dionaea -> modelo comun
    ├── reporters/           # uno por plataforma
    ├── common/              # modelo, estado, cuotas, HTTP y la barrera de IPs
    ├── tests/               # comprueban que las puertas saltan (3.5.5.2)
    └── cron.d/
</pre>

Fuera de `/opt` se crean dos rutas de servicio para los reporters, que no son configuración sino datos: `/var/lib/dirtyland-reporter` (el estado de qué se ha reportado ya, para no duplicar) y `/var/log/dirtyland-reporter` (sus registros).

> [!IMPORTANT]
> Tres de estos nombres <b>no se pueden cambiar</b>, porque están escritos dentro de los scripts del repositorio:
> - `/opt/dirtyland/Telegram Reports/` la usan el plugin `telegram_alert_cowrie.py` y el servicio de baneos, y se monta en el contenedor <b>en la misma ruta exacta</b> que en el host, para que la constante del plugin valga dentro y fuera.
> - `/opt/dirtyland/monitor/` es donde `daily-digest.sh`, `ssh-watch.sh` y `dionaea-watch.sh` buscan `send-alert.sh` y `telegram.env`, por ruta absoluta.
> - `/opt/dirtyland/platform-reporter/config.ini` es el valor por defecto del reporter, y `malware-watch.sh` y el fichero de cron dan por hecha esa ruta.

De aquí en adelante hacen falta ficheros del repositorio en varios apartados: el `.tar` del honeyfs, los 70 módulos de comandos y sus salidas enlatadas, la salida de `ps`, el `smb.yaml` de Dionaea, el generador de volúmenes y el reporter. Se suben <b>todos de una vez</b>, ahora, y el resto de la guía los coge de ahí.

En nuestro equipo, clonando el repositorio:

```bash
git clone https://github.com/iliangithub/Project_Dirtylands.git
```

Una vez bajado el repo, <b>la carpeta no se sube tal cual a la VPS</b>, se empaqueta antes con `git archive`, que saca exactamente lo que hay confirmado en el commit y nada más. Este comando empaqueta, transfiere, descomprime en la VPS y borra el `.tar.gz` de los dos lados.

**En Linux:**

```bash
cd Project_Dirtylands && git archive --format=tar --prefix=dirtyland-repo/ HEAD | gzip > /tmp/dirtyland-repo.tar.gz && scp /tmp/dirtyland-repo.tar.gz dirtyland:/tmp/ && rm /tmp/dirtyland-repo.tar.gz && ssh dirtyland 'rm -rf /tmp/dirtyland-repo && tar -xzf /tmp/dirtyland-repo.tar.gz -C /tmp/ && rm /tmp/dirtyland-repo.tar.gz && echo subido'
```

**En Windows** ese comando no vale: PowerShell no entiende `&&`, no hay `/tmp` y no trae `gzip`. Es el mismo de arriba con lo que sí entiende (`;` para encadenar e `if` para no seguir si algo falla), y también va de un solo pegado:

```powershell
$repo = if (Test-Path .\Project_Dirtylands\.git) { ".\Project_Dirtylands" } else { "." }; git -C $repo archive --format=tar.gz --prefix=dirtyland-repo/ -o "$env:TEMP\dirtyland-repo.tar.gz" HEAD; if ($LASTEXITCODE -eq 0) { scp "$env:TEMP\dirtyland-repo.tar.gz" dirtyland:/tmp/ }; if ($LASTEXITCODE -eq 0) { ssh dirtyland "rm -rf /tmp/dirtyland-repo && tar -xzf /tmp/dirtyland-repo.tar.gz -C /tmp/ && rm /tmp/dirtyland-repo.tar.gz && echo subido"; Remove-Item "$env:TEMP\dirtyland-repo.tar.gz" }
```

Da igual desde dónde lo pegues al lado de la carpeta o ya dentro de ella.

Tres diferencias con el de Linux: 
- `git archive` comprime él solo con `--format=tar.gz` y escribe con `-o`, así que no hace falta `gzip`
- el fichero intermedio va a `%TEMP%` en vez de a `/tmp`, que en Windows no existe
- y los `&&` que quedan son los de dentro de las comillas, que ejecuta el `bash` de la VPS y no PowerShell.

> [!CAUTION]
> <b>Por qué no un `scp -r` de la carpeta.</b> Copia el directorio de trabajo entero y no lee el `.gitignore`, así que se lleva el `.git/` y todos los `__pycache__`. Y lo grave: nuestro `.gitignore` excluye a propósito `config.ini`, `telegram.env` y `*.sqlite3`, que son <b>las claves de las cinco plataformas</b> y el estado del reporter. Si alguna vez has ejecutado el reporter en tu equipo, esos ficheros existen en la carpeta local y un `scp -r` te los sube. Medido aquí: 1,6 MB con `git archive` contra 11,4 MB con `scp -r`.

Las transferencias van por el <b>alias</b> de `~/.ssh/config`, que ya lleva el puerto, el usuario, la clave y el `ProxyCommand`. Sin él el cortafuegos rechaza la conexión, porque solo acepta las IP del proxy de Mullvad.

Se comprueba que ha llegado completo:

```bash
cd /tmp/dirtyland-repo && for x in "3.6 Para facilitarnos la vida" "ANALISIS" "CORTAFUEGOS" "COWRIE FAKE ENVIRONMENT" "COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" "DIONAEA" "DOCKER-COMPOSE" "Local SSH" "README.md" "REPORTING PLATFORM SCRIPTS" "TELEGRAM SCRIPTS"; do [ -e "$x" ] && echo "  OK     $x" || echo "  FALTA  $x"; done; echo "  ----------"; echo "  $(ls -1 | wc -l) de 11 elementos en la raiz"
```

<pre>
  OK     3.6 Para facilitarnos la vida
  OK     ANALISIS
  OK     CORTAFUEGOS
  OK     COWRIE FAKE ENVIRONMENT
  OK     COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE
  OK     DIONAEA
  OK     DOCKER-COMPOSE
  OK     Local SSH
  OK     README.md
  OK     REPORTING PLATFORM SCRIPTS
  OK     TELEGRAM SCRIPTS
  ----------
  11 de 11 elementos en la raiz
</pre>

Si sale algún `FALTA`, la transferencia se quedó a medias, se repite lo de antes **y no se sigue.**

Los scripts del repositorio se entregan siempre con finales de línea de Unix, aunque se descarguen desde Windows, y lo garantiza un `.gitattributes`. Si alguna vez copias un script y falla con `203/EXEC` en systemd o con `bad interpreter`, es que ese fichero llegó con finales de Windows: `sed -i 's/\r$//' fichero` lo arregla.

```bash
cd /opt/dirtyland
```

```bash
sudo docker pull cowrie/cowrie:3.0.10
```

> [!CAUTION]
> <b>La versión de Cowrie va fijada, no en `latest`.</b> Este montaje sustituye ficheros internos de Cowrie, los 70 módulos del 3.4.2.8, y dependen de su API interna, que cambia entre versiones sin previo aviso. Nos pasó con la `3.0.11`, que movió `cwd` del protocolo a la shell y convirtió `user` de objeto a diccionario: la autenticación funcionaba, salía el MOTD y no aparecía ningún prompt. La `3.0.10` es la última compatible. Antes de subir de versión hay que comprobar si la API sigue encajando:
>
> ```bash
> sudo docker run --rm --entrypoint /cowrie/cowrie-env/bin/python3 cowrie/cowrie:<version> -c "
> h=open('/cowrie/cowrie-git/src/cowrie/shell/honeypot.py').read()
> print('COMPATIBLE' if ('self.protocol.cwd' in h and 'self.user[' not in h) else 'API NUEVA: hay que adaptar los modulos')"
> ```

```bash
sudo docker pull cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47
```

<b>Dionaea también va fijada</b>, y por digest en vez de por etiqueta, porque el proyecto solo publica `latest`. El motivo es el mismo que con Cowrie: le sustituimos el módulo TDS del paso 5, y con `latest` una imagen nueva podría traerlo cambiado y quedarse con nuestra copia vieja montada encima, sin dar ningún error. Para actualizarla a propósito se rehace el parche y se cambia el digest, que se consulta así:

```bash
sudo docker image inspect cowrie/dionaea -f '{{index .RepoDigests 0}}'
```

<b>2. Configuración del daemon de Docker</b>

```bash
printf '{\n  "userland-proxy": false,\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "10m", "max-file": "3" }\n}\n' | sudo tee /etc/docker/daemon.json > /dev/null
```
```bash
sudo systemctl restart docker
```

<b>3. Ficheros de configuración de Cowrie</b>
```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```
Lo que pusimos dentro fue:
```ini
[honeypot]
hostname = pc-dev-003-ignis

[shell]
kernel_version = 6.12.74+deb13+1-amd64
kernel_build_string = #1 SMP PREEMPT_DYNAMIC Debian 6.12.74-2 (2026-03-08)
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026
```

Para este otro archivo, el de credenciales:

```bash
sudo nano /opt/dirtyland/cowrie/etc/userdb.txt
```
```
root:x:root
admin:x:admin
alyosha:x:alyosha123
user-ssh:x:987654321
```

El formato es `usuario:x:contraseña`, una línea por cuenta y sin repetir ninguna. Tampoco se usa el comodín `*` ni la negación `!`: un `userdb` con `*:*:*` acepta cualquier intento y es de las señales más inmediatas de que hay un honeypot detrás.

Las claves son fáciles a propósito, y `root:root` la que más, porque casi todos los intentos van contra `root`: si esa cuenta no acepta ninguna, el barrido rebota sin capturar nada. El precio es un retrato de máquina mal administrada, que sigue siendo creíble. En el anfitrión no añade riesgo, porque allí `root` por SSH está desactivado y solo se entra con clave desde las IP de los proxies: este fichero describe al señuelo emulado. `mihail` y `mykhailo` tienen directorio en `/home` y no aparecen aquí, así que existen sin que nadie pueda autenticarse con ellas.

> Por experiencia, es casi obligatorio poner "admin" "admin", porque los bots ni siquiera se esfuerzan en hacer un ataque de diccionario en el que tenga que durar la fuerza bruta más de 3 o 4 segundos. Van a la contraseña que sea genuinamente más fácil. Da igual que cojamos la contraseña número 1184 del diccionario de contraseñas "rockyou.txt", simplemente los bots ni se van a esforzar en hacer fuerza bruta.

El fichero se monta en solo lectura (`:ro`) en el contenedor, así que cualquier modificación exige un `sudo docker restart dirtyland_cowrie` para que Cowrie vuelva a leerlo.

<b>4. docker-compose.yml final</b>

```bash
sudo nano /opt/dirtyland/docker-compose.yml
```

El contenido de este docker-compose está en **[DOCKER-COMPOSE/PART 1/docker-compose.yml](DOCKER-COMPOSE/PART%201/docker-compose.yml)**.

Recuerda sustituir, que van en los `ports` de cada señuelo:

- `[IP VPS]` -> la primera IP del servidor, la de Cowrie (puertos 22 y 23).
- `[IP VPS 2]` -> la segunda, la de Dionaea (445, 135 y 1433).

Y **nada más pegarlo**, se comprueba que el YAML está bien:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml config >/dev/null && echo "compose OK"
```

Tiene que responder `compose OK`. Si no lo hace, no sigas: los pasos siguientes montan volúmenes y levantan contenedores sobre este fichero.

Pegar YAML en `nano` es delicado, y por eso la comprobación va aquí y no tres pasos después: si se pierde o se fusiona una sola línea, `docker compose` falla con un error que no dice qué línea está mal, del tipo `did not find expected key`.

> [!NOTE]
> <b>Solo si el `config` de arriba ha fallado.</b> No busques la línea a ojo. Vuelve a pegar el fichero entero. Y si el `nano` te descuadra la sangría al pegar, ábrelo con el autosangrado desactivado:
>
> ```bash
> sudo nano -I /opt/dirtyland/docker-compose.yml
> ```
>

Cada señuelo se publica atado a <b>su</b> IP, no en todas las interfaces (`0.0.0.0`), así que Cowrie solo responde por la suya y Dionaea por la suya desde el primer arranque. Dionaea se expone con tres puertos coherentes con una máquina Windows (SMB 445, RPC 135, MSSQL 1433) y su personalización completa va en el apartado 3.4.3.

<b>5. El parche de MSSQL de Dionaea</b>

Va **antes** de levantar la pila, y el orden no es negociable: el `docker-compose` monta este fichero, y Docker, cuando el origen de un montaje de fichero no existe, **crea un directorio con ese nombre**. Dionaea arrancaría entonces sin poder importar su propio módulo.

El motivo es este. Un `nmap -sV` contra el 1433 de un Dionaea de serie devuelve, sin scripts ni nada:

<pre>
1433/tcp open  ms-sql-s  Dionaea honeypot MS-SQL server
</pre>

nmap trae esa firma <b>en su base de datos de fábrica</b>: reconoce el paquete de pre-login TDS de Dionaea, que lleva la versión escrita a fuego y anuncia un SQL Server 2000 (`8.0.528`). Son dos problemas en la misma línea: el señuelo dice su nombre, y además dice ser una versión que no cuadra con la leyenda.

No hay clave de configuración para eso, así que se saca el fichero de la imagen (la misma técnica que con `createfs.py` en el 3.4.2.3) y se le cambia el número:

```bash
cid=$(sudo docker create cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47) && sudo docker cp "$cid:/opt/dionaea/lib/dionaea/python/dionaea/mssql/include/tds.py" /opt/dirtyland/dionaea/tds.py && sudo docker rm -f "$cid"
```

```bash
sudo sed -i 's/LEIntField("Version",268566536)/LEIntField("Version",1276654090)/' /opt/dirtyland/dionaea/tds.py
```

Y **se comprueba que el `sed` ha mordido**, porque si la imagen cambiara ese renglón el `sed` no haría nada y no diría nada:

```bash
grep -c 'LEIntField("Version",1276654090)' /opt/dirtyland/dionaea/tds.py
```

<pre>
1
</pre>

Si sale `0`, el fichero de la imagen ha cambiado: hay que mirar cómo se llama ahora ese campo antes de seguir, no ignorarlo.

```bash
sudo chown root:root /opt/dirtyland/dionaea/tds.py && sudo chmod 644 /opt/dirtyland/dionaea/tds.py
```

`1276654090` no es un número mágico: son los cuatro bytes `0a 32 18 4c` leídos en little-endian, o sea versión **10.50 build 6220**, que es SQL Server 2008 R2 SP3, que sí es coherente con un Windows 7. Para otra versión, los bytes son `mayor, menor, build-en-2-bytes`.

<b>Y del mismo módulo hay que sacar un segundo fichero, sin él, cualquiera puede dejar colgado a Dionaea mandando un solo paquete.</b>

Esto me pasó dos veces en una semana y tuve que hacer este parche de urgencias. <br> 
Dionaea dejó de anotar conexiones y estuvo cinco días así, y al reiniciarlo se volvió a colgar noventa segundos después, porque volvieron a mandar el paquete. <br>
Las dos veces las últimas líneas de su log eran de MSSQL. No se cae, se queda <b>dando vueltas</b>, y por eso no lo nota nadie: `docker ps` sigue diciendo `Up`, el proceso existe y el `nftables` sigue contando los paquetes que entran. Lo único que se ve es un núcleo al 100% y una base de datos que deja de crecer.

El fallo está en `handle_io_in()`, y son tres líneas seguidas:

<pre>
chunk = data[offset:offset+p.Length]
p = TDS_Header(chunk)      <b>&lt;-- se reescribe p con un trozo truncado</b>
offset += p.Length         <b>&lt;-- y se avanza con el Length del p NUEVO</b>
</pre>

La cabecera TDS ocupa 8 bytes y su `Length` es el tamaño del paquete entero, así que no puede valer menos de 8, pero solo se rechaza el `0`. Si alguien declara <b>1, 2 o 3</b>, el trozo que se corta se queda sin los bytes donde vive el `Length`, el reparseo los rellena con ceros, el `Length` sale `0`, `offset += 0` y el bucle vuelve al principio con los mismos bytes. Para siempre, y sin escribir una línea, porque por ese camino no se registra nada.

El arreglo son dos líneas y viene en el repositorio, con su explicación entera dentro:

```bash
cid=$(sudo docker create cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47) && sudo docker cp "$cid:/opt/dionaea/lib/dionaea/python/dionaea/mssql/mssql.py" /opt/dirtyland/dionaea/mssql.py && sudo docker rm -f "$cid"
```

```bash
sudo install -m 755 "/tmp/dirtyland-repo/DIONAEA/parche-mssql.py" /opt/dirtyland/dionaea/parche-mssql.py && sudo /opt/dirtyland/dionaea/parche-mssql.py /opt/dirtyland/dionaea/mssql.py
```

<pre>
parcheado: /opt/dirtyland/dionaea/mssql.py
</pre>

```bash
sudo chown root:root /opt/dirtyland/dionaea/mssql.py && sudo chmod 644 /opt/dirtyland/dionaea/mssql.py
```

> [!TIP]
> <b>Si estás ACTUALIZANDO una instalación que ya funciona</b>, no toques el `docker-compose.yml` a mano: hay que meter una línea en un fichero que ya lleva tus IPs sustituidas. Desde cero no hace falta, porque el compose se pega entero desde `DOCKER-COMPOSE/PART 1`. Esto dice qué falta sin tocar nada:
>
> ```bash
> sudo /opt/dirtyland/montajes-dionaea.sh
> ```
>
> Y esto lo pone, con la sangría correcta, dejando copia de seguridad y validando el YAML:
>
> ```bash
> sudo /opt/dirtyland/montajes-dionaea.sh --apply
> ```
>
> Se puede lanzar dos veces, y la lista sale del compose del repositorio, así que un montaje nuevo se pide solo. Si aún no lo tienes instalado (se copia en el 3.4.2.9) sirve igual desde `/tmp/dirtyland-repo/DOCKER-COMPOSE/montajes-dionaea.sh`. Existe por un fallo real: esa línea se pegó a mano y salió con el guion duplicado, y sin ese montaje Dionaea vuelve a colgarse con el primer paquete MSSQL malformado mientras el compose sigue siendo YAML válido.
>

> [!IMPORTANT]
> <b>El parche no adivina.</b> Si el fichero de la imagen no es exactamente el que espera, por ejemplo tras cambiar el digest del `docker-compose`, no toca nada, dice `ESTE mssql.py NO ES EL ESPERADO` y sale con error. Un parche aplicado a medias se monta encima sin dar ningún fallo, y eso es peor. Ejecutarlo dos veces no rompe nada: dice `ya estaba parcheado` y se va.
>
> `test_parche_mssql.py` (apartado 3.7.10) no comprueba que el texto cambie: <b>ejecuta el bucle</b> con un paquete de `Length = 1`, antes y después, y verifica que el primero no termina nunca y el segundo sí.

El fallo no lo introdujimos nosotros: el `diff` de nuestro `tds.py` contra el de la imagen es una única línea, la del número de versión. Lo que cambió fue lo que le mandaron, porque hace falta que alguien declare un `Length` de 1, 2 o 3, y que el segundo cuelgue llegara noventa segundos después de reiniciar dice que ese tráfico ya es continuo. Con el parche, `nmap -sV` pasa de `Dionaea honeypot MS-SQL server` a `ms-sql-s?`: no convierte el puerto en un SQL Server creíble ante un análisis a fondo, pero deja de anunciar que hay un honeypot detrás.

<b>6. Levantar la pila</b>

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```
### 3.4.1 Reglas cortafuegos mejoradas para el docker-compose.

```bash
sudo cp /etc/nftables.conf /etc/nftables_3.4.1.post.docker_creacion_compose___$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```

La siguiente regla de cortafuegos corresponde a la regla de cortafuegos de la parte 3, de nuevo, está en la carpeta del repositorio:

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

Y ponemos dentro el contenido de **[CORTAFUEGOS/nftables-PART-3.txt](CORTAFUEGOS/nftables-PART-3.txt)**. Aquí es importante que lo revisemos bien.

```bash
cat /etc/nftables.conf
```

Respecto a las reglas:
- En la cadena input (no la forward) tiene la regla tcp dport 22 accept, que abre el 22 a cualquier IP. Esa regla estaba pensada para el señuelo de Cowrie. Pero recuerda que el tráfico hacia el contenedor de Cowrie pasa por forward (por el DNAT), no por input, así que esa regla de input no hace que el contenedor sea alcanzable. El resultado neto sigue siendo timeout en el 22, porque el forward lo bloquea. Al ver esa línea tcp dport 22 accept en el input, podrías pensar que el 22 debería conectar y no, no conecta, porque quien manda para el contenedor es el forward, que lo descarta.

Para comprobar la sintaxis del fichero:

```bash
sudo nft -c -f /etc/nftables.conf
```

Aplicamos:

```bash
sudo nft -f /etc/nftables.conf
```

Además vamos a ver que los contenedores siguen activos:

```bash
sudo docker ps
```

Algo así debería de aparecer y mostrar:

<pre>
CONTAINER ID   IMAGE                   COMMAND                  CREATED        STATUS        PORTS                                                                                                                                NAMES
7d5ee4b4cb4c   cowrie/cowrie:3.0.10    "/cowrie/cowrie-env/…"   20 hours ago   Up 20 hours   [IP VPS]:22->2222/tcp, [IP VPS]:23->2223/tcp                   dirtyland_cowrie
e7f37419a6af   cowrie/dionaea@sha256:7c3c1b…   "/opt/dionaea/entryp…"   26 hours ago   Up 26 hours   [IP VPS 2]:135->135/tcp, [IP VPS 2]:445->445/tcp, [IP VPS 2]:1433->1433/tcp           dirtyland_dionaea
</pre>

Y si, está todo sellado sigue sin estar expuesto a Internet. Para verificar que es verdad:

```bash
IP1=[IP VPS]; IP2=[IP VPS 2]; for par in "$IP1 22" "$IP1 23" "$IP2 135" "$IP2 445" "$IP2 1433"; do nc -vz -w 3 $par; done
```

Windows no trae `nc`, así que desde PowerShell es esto otro (el `3000` son los mismos tres segundos de espera del `-w 3`):

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```
<b>¡Nos tiene que dar error!</b><br> 
`nc: connect to [IP VPS] port 22 (tcp) timed out: Operation now in progress`<br>
En PowerShell, lo mismo dicho de otra forma: `cerrado o filtrado` en los cinco.

> [!IMPORTANT]
> <b>Todavía no hay nada expuesto</b>

#### 3.4.1.1 Por qué estas reglas: la contención de salida explicada.

Lo que sigue explica las reglas que acabas de aplicar, regla por regla.

Un honeypot es, por definición, una máquina que se deja deliberadamente al alcance de atacantes. Por bien que Cowrie y Dionaea emulen sus servicios, hay que asumir lo peor: "que alguien escape de la emulación y consiga ejecución de código real dentro de un contenedor". En seguridad se diseña para cuando las cosas salen mal, no confiando en que no salgan.

El peligro de ese escenario no es perder la máquina, es que **la máquina se convierta en plataforma de ataque contra terceros**: escaneos masivos, denegación de servicio, spam o propagación, todo saliendo desde la IP pública del proyecto y, por tanto, con las consecuencias legales y reputacionales para quien le pertenece la VPS.

Por eso el control de la salida (*egress*) es la pieza central de la contención, y con un principio detrás: la barrera <b>no se implementa dentro del honeypot</b>, que es software emulado y que si se compromete deja de estar bajo control, sino por debajo, en la cadena `forward` del cortafuegos del anfitrión, que sigue mandando aunque el contenedor caiga. La que de verdad contiene es la dura.

<b>La filosofía es permisiva pero controlada.</b> Bloquear toda la salida garantiza cero daño a terceros, pero impide que Cowrie complete la descarga de los payloads que ordena el atacante, y con ella se pierden las muestras. Se eligió permitir la descarga acotándola al mínimo con reglas quirúrgicas, porque cosechar malware es uno de los objetivos del proyecto: permitir solo lo que una descarga necesita y dejar la máquina inútil para cualquier abuso masivo.

<b>El anclaje común.</b> Todas las reglas del egress comparten la misma condición de origen: se aplican solo al tráfico que entra al enrutado desde el puente de los contenedores (`iifname "dirtyland0"`) y cuyo origen es su subred (`ip saddr 172.20.0.0/24`). No filtramos toda la salida de la máquina, solo la de los contenedores, el tráfico del propio anfitrión sale por su cadena `output` en aceptación por defecto.

**Regla 1. Tráfico de retorno.** Se aceptan las conexiones ya establecidas o relacionadas (`established, related`) y se descartan las inválidas. Es la base para que las respuestas al tráfico legítimo circulen. Cuando una descarga permitida abre una conexión, el flujo de vuelta pertenece a esa conexión y debe poder pasar. El descarte de inválidos elimina tráfico con estado anómalo o corrupto.

**Regla 2. Anti pivoteo.** Seis reglas que impiden que un contenedor comprometido alcance destinos que no debe tocar:

| Rango | Qué es | Por qué se bloquea |
|---|---|---|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Direcciones privadas del RFC 1918, no enrutables por internet | Evita que un atacante salte hacia redes internas: la del proveedor, la de otros clientes o la de la propia máquina |
| `169.254.0.0/16` | *Link-local* o APIPA, la que un equipo se autoasigna cuando no encuentra DHCP | Un contenedor no tiene ningún motivo legítimo para dirigirse ahí |
| `100.64.0.0/10` | CGNAT, el bloque reservado al uso interno de los operadores | Cierra otra vía hacia la infraestructura del proveedor de hosting |
| La IP pública del propio servidor | La nuestra | Impide que el contenedor se vuelva contra el anfitrión atacando sus servicios, por ejemplo el SSH de administración |

El propósito conjunto es cerrar el movimiento lateral. Cada bloqueo se registra con el prefijo `DL-EGRESS-PRIV` o `DL-EGRESS-HOST`.

**Regla 3. Anti spam.** Se bloquea la salida hacia los puertos del correo: el `25` (SMTP), el `465` (SMTP sobre TLS) y el `587` (envío autenticado). La máquina no puede usarse para mandar spam, uno de los abusos más habituales de un servidor comprometido.

**Regla 4. Anti amplificación.** Se bloquea **todo** el UDP saliente de los contenedores. Un ataque de amplificación consiste en mandar peticiones UDP pequeñas con el origen falsificado a servidores reflectores (DNS, NTP, memcached, SSDP), que responden con un volumen mucho mayor dirigido a la víctima suplantada. Sin capacidad de emitir UDP hacia fuera, la máquina no puede ser el origen de eso.

Que un bloqueo total de UDP no rompa el señuelo se verificó expresamente. **Las consultas DNS de los contenedores no salen por esta vía**. El resolvedor interno de Docker (`127.0.0.11`) reenvía al resolvedor del anfitrión (`systemd-resolved`, en `127.0.0.53`), y es el anfitrión quien sale a internet a resolver, por su cadena `output`, no el contenedor por la `forward`.

Una consecuencia asumida: un payload servido por <b>TFTP</b>, que va sobre UDP, no se podría descargar. Se aceptó porque la inmensa mayoría se distribuyen por HTTP o HTTPS sobre TCP, y a cambio el vector de amplificación se cierra sin excepciones.

**Regla 5. Salida TCP con límite de ritmo.** Se apoya en un paquete concreto: el que lleva la bandera SYN, que es el que inicia toda conexión TCP nueva. Filtrar los SYN equivale a filtrar los intentos de abrir conexiones.

La primera línea permite abrir conexiones nuevas limitando el ritmo a **10 por minuto, con un margen de arranque de 20**. Se toleran hasta veinte aperturas casi seguidas y, a partir de ahí, una nueva cada seis segundos aproximadamente. La segunda descarta y registra (`DL-EGRESS-RATE`) todo lo que pase de ese ritmo.

La lógica de fondo es una **asimetría entre el uso legítimo y el abuso**. Una descarga de un payload son una o dos conexiones y cabe de sobra. Un escaneo de puertos o un DDoS necesita abrir miles por segundo y choca con el límite de inmediato. La misma regla permite lo uno e imposibilita lo otro.

La tercera línea, aceptar el resto del TCP, es la que hace que la descarga funcione, porque el límite solo se aplica a las <b>aperturas</b>: una vez admitida la conexión, sus paquetes siguientes ya no son SYN y el fichero baja a velocidad normal. Se limita cuántas conexiones nuevas por minuto puede abrir la máquina, no el caudal de una descarga ya autorizada. Y se permite cualquier puerto de destino, no solo el 80 o el 443, porque los atacantes alojan sus payloads en puertos no estándar y el límite de ritmo ya neutraliza el abuso.

**Regla 6. Cajón de seguridad.** Lo que no haya encajado en ninguna regla anterior se registra (`DL-EGRESS-OTHER`) y se descarta. Junto con la política por defecto de la cadena (`policy drop`), garantiza que nada imprevisto salga. Lo que no está explícitamente permitido, queda bloqueado.

<b>El registro como alarma.</b> Todas las reglas de bloqueo dejan constancia con un prefijo identificativo (`DL-EGRESS-PRIV`, `DL-EGRESS-HOST`, `DL-EGRESS-SMTP`, `DL-EGRESS-UDP`, `DL-EGRESS-RATE`, `DL-EGRESS-OTHER`). En condiciones normales los contenedores apenas generan salida bloqueada, así que si empiezan a aparecer intentos hacia redes privadas, puertos de correo o a ritmo alto, la señal es que algo dentro de un contenedor está intentando escapar de la contención. La contención, además de proteger, genera inteligencia.

**Qué amenaza neutraliza cada pieza.**

| Abuso | Por qué no puede |
|---|---|
| Servir de C2 alcanzable | La entrada solo se reenvía a los puertos de los señuelos, no se expone ningún servicio nuevo |
| Amplificar | Bloqueo del UDP saliente |
| Escanear o sumarse a un DDoS volumétrico | Límite de ritmo de conexiones nuevas |
| Mandar spam | Bloqueo de SMTP |
| Pivotar | Bloqueo hacia redes privadas e infraestructura del proveedor |

El resultado es una máquina capaz de cosechar malware e inútil como plataforma de ataque.

**Verificación.** El diseño no se dio por bueno sobre el papel. Se comprobó desde dentro de un contenedor (Dionaea):

1. Que una descarga TCP permitida funciona. Una petición a un servidor web externo por el 80 devolvió un `200`. En la misma prueba se confirmó que la resolución de nombres funcionaba sin ninguna regla de DNS en la `forward`, tal como se había previsto.
2. Que el acceso a una red privada se bloquea. Un intento hacia `10.0.0.1` quedó bloqueado y registrado con `DL-EGRESS-PRIV`, mostrando origen y destino.
3. Que el UDP saliente se bloquea. El envío de un paquete UDP hacia un servidor externo quedó bloqueado y registrado con `DL-EGRESS-UDP`.

<b>Alcance honesto.</b> Ninguna contención es absoluta: esto no elimina el riesgo, lo reduce al mínimo que consideramos aceptable. Aunque alguien escapara de la emulación no podría mandar spam, amplificar ni pivotar, porque esos vectores están cerrados del todo; solo podría escanear o intentar un DDoS a un ritmo inútil. La idea de partida es dar por hecho que te pueden comprometer y limitar de antemano lo que la máquina puede hacer hacia fuera.

### 3.4.2 Customizar y mejorar Cowrie.

En este apartado ampliamos el `docker-compose` para montar el árbol de directorios falso, la configuración personalizada y las alertas. El compose crece por fases porque cada capa se verifica antes de pasar a la siguiente.

#### 3.4.2.1 Construcción del árbol de directorios falso (honeyfs).

El árbol de directorios que verá el atacante dentro de Cowrie (la cuenta de "Alyosha" y compañía, con sus dotfiles, claves SSH, historiales y el proyecto Node) se ha diseñado, construido aparte y no se entrará en detalles como se ha hecho. <br>

Para dotar al señuelo de una historia creíble y coherente. La construcción del contenido y su diseño narrativo se ha hecho de forma externa. Aquí documentamos cómo se integra en Cowrie.

<p>
Pero, para ser breves, simplemente se ha creado con Claude Code los archivos en una máquina debian 13, se convierte el `home` entero en un archivo empaquetado (que no comprimido) y se pasa a la máquina anfitriona. El comprimido sería por ejemplo un `.rar`, en nuestro caso, un archivo empaquetador `.tar` (que preserva las fechas de modificación, cosa importante para el realismo).
</p>

Recomendamos que esté en formato `.tar` y no `.rar`. No vamos tampoco a explicar la aventura que sería, en caso de que fuera un `.rar` ni como solucionar nada de si fuera `.rar`.

Se usa `.tar` porque preserva los `mtime`. Un `.rar` creado desde Windows no transporta permisos POSIX ni propietarios, así que esos metadatos habría que reconstruirlos aparte.

El `.tar` está en la carpeta **COWRIE FAKE ENVIRONMENT**, así que ya vino con el repositorio en el apartado 3.4 y solo hay que ponerlo en su sitio. <b>Ojo al nombre de destino</b>: tiene que quedar como `/tmp/home.tar`, no con el nombre que trae del repositorio.

```bash
cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/honeyfs-home-DEFINITIVO.tar.gz" /tmp/home.tar
```

Y verificamos que conserva los "mtime" originales. Deben aparecer las fechas diseñadas (de 2026), no la fecha de hoy:

```bash
tar -tvf /tmp/home.tar | head -5
```

> [!IMPORTANT]
> El nombre `/tmp/home.tar` no es una preferencia: es la ruta que el generador del sistema de ficheros (`build-dirtyland-fs.sh`, apartado 3.4.2.3) lleva escrita dentro, en su variable `HOME_TAR`, y también la que se extrae en el honeyfs en el apartado 3.4.2.5. Si se sube con otro nombre, el build no encuentra el árbol y el señuelo se genera sin `/home`. La extensión da igual: `tar` detecta solo que el fichero viene comprimido.

#### 3.4.2.2 El problema del pickle y por qué se regenera entero.

Cowrie no representa su sistema de ficheros virtual con los ficheros reales, sino con un índice en formato "pickle" (`fs.pickle`) que guarda los metadatos (nombre, tipo, uid, gid, tamaño, permisos y fecha) de cada ruta. El contenido real de cada fichero se sirve aparte, desde un directorio "honeyfs".

Esto tiene dos consecuencias clave:

- Un fichero necesita <b>las dos piezas</b> para que el atacante lo vea con contenido: una entrada en el pickle (los metadatos) y un fichero real en el honeyfs (el contenido).
    - Si falta la entrada del pickle, el fichero es invisible aunque esté en el honeyfs.
- El pickle que trae Cowrie de fábrica es una foto de un Debian antiguo (12.5) y no contiene nuestros usuarios.
    - No se puede "fusionar" con el nuestro; hay que <b>regenerarlo entero</b> desde un sistema Debian real que incluya tanto la base del sistema como nuestro árbol.

Evidentemente, esos metadatos de cada archivo que tenemos, no los hacemos manualmente. La herramienta que genera el pickle es `createfs.py`, que recorre un sistema de ficheros real y anota sus metadatos. Vive dentro del contenedor de Cowrie, así que primero confirmamos el nombre real del contenedor (Docker Compose lo prefija con el nombre del proyecto):

```bash
sudo docker ps --format '{{.Names}}\t{{.Image}}'
```

Y la extraemos para usarla en la generación:

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/scripts/createfs.py /tmp/createfs.py
```

La imagen de Cowrie es mínima y no trae `ls`, `find` ni `grep`. Para mirar dentro hay que usar `docker cp` o el Python de su propio entorno virtual (`/cowrie/cowrie-env/bin/python3`).

Dos detalles del código de `createfs.py`. El campo de fecha que guarda en el pickle es el `mtime` y no el `ctime`, que es lo que queremos: las fechas diseñadas en el árbol sobreviven íntegras. Y los <b>enlaces simbólicos solo se conservan si su destino cae dentro del árbol procesado</b>; el nuestro no tenía ninguno, pero conviene saberlo por si se añade uno.

#### 3.4.2.3 Generación del pickle desde un Debian 13 real.

<b>¿Por qué desde un Debian entero y no a mano?</b> Porque `createfs.py` no inventa nada: necesita <b>recorrer un sistema real</b> para fotografiarlo. Fabricamos lo que debe ser falso, la historia de nuestro `/home`, y copiamos lo que debe ser real, el sistema con sus ~69.000 rutas y sus permisos exactos. Un tamaño que no cuadrara con el binario real de Debian sería un indicio.

La estrategia es levantar un contenedor Debian 13 efímero (coherente con la versión que anuncia Cowrie), instalarle el software que la leyenda requiere, inyectar nuestro árbol `/home` encima, crear los usuarios con sus uid fijos, normalizar permisos y propietarios, y solo entonces ejecutar `createfs.py`.

Primero descargamos la imagen base:

```bash
sudo docker pull debian:13
```

El proceso se encapsula gracias a un script, que vino con el repositorio en la carpeta **COWRIE FAKE ENVIRONMENT**. Se copia y se le da permiso de ejecución:

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/build-dirtyland-fs.sh" /opt/dirtyland/
```

Lo ejecutamos:

```bash
sudo bash /opt/dirtyland/build-dirtyland-fs.sh
```

<b>En la VPS va sin límites de recursos, y es a propósito.</b> El script acepta `LIMITES_CPU`, `LIMITES_CPUSET` y `LIMITES_MEM`, pero vacíos por defecto: la VPS tiene un solo procesador, y anclar el contenedor a otros núcleos no la hace ir lenta, la deja sin arrancar (`Requested CPUs are not available`). Además aquí se <b>instalan los paquetes de la leyenda</b>, así que un techo de memoria pequeño tampoco sale gratis. Donde sí sirven es al ensayar en un equipo de escritorio:

```bash
LIMITES_CPU=0.5 LIMITES_CPUSET=12-19 LIMITES_MEM=2g bash build-dirtyland-fs.sh
```

> [!TIP]
> <b>Ensayar la regeneración fuera de la VPS.</b> Las cinco rutas del script (`IMAGE`, `HOME_TAR`, `CREATEFS`, `OUT_DIR`, `HONEYFS_DIR`) traen por defecto las de producción, pero se pueden sobreescribir por entorno y ejecutar la cadena entera en otra máquina Debian con Docker antes de tocar el señuelo:
>
> ```bash
> SUDO="" OUT_DIR=/tmp/ensayo/fs HONEYFS_DIR=/tmp/ensayo/honeyfs \
>   HOME_TAR=/tmp/home.tar CREATEFS=/tmp/createfs.py \
>   bash build-dirtyland-fs.sh
> ```
>
> `SUDO=""` quita el `sudo` cuando el usuario ya está en el grupo `docker`. Entre ensayo y ensayo hay que borrar el `fs.pickle.new` anterior, porque `createfs.py` se niega a sobreescribir su propia salida; el script lo comprueba al principio, que si no el error salta al final, después de instalar todos los paquetes.
>
> Hacen falta dos piezas que no están en el repositorio. El `home.tar` sí viene con él; el `createfs.py` se saca de la imagen exacta que fija el `docker-compose`, no de GitHub, para que sea la misma que corre en la VPS:
>
> ```bash
> cid=$(docker create cowrie/cowrie:3.0.10)
> docker cp "$cid:/cowrie/cowrie-git/src/cowrie/scripts/createfs.py" /tmp/createfs.py
> docker rm -f "$cid"
> ```
>

El contenedor de construcción se lanza con `--network host` porque su descarga de paquetes, saliendo por la red por defecto de Docker, caería en la `policy drop` del cortafuegos. Es una excepción puntual y solo durante la construcción.

> [!WARNING]
> El pickle recién generado **todavía no es de fiar**. Para una veintena de ficheros de sistema (su lista interna `EMBED_PATHS`: `/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`, `/proc/version`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/modules`) `createfs.py` no anota metadatos, incrusta el contenido. Y como ese contenedor corre con `--network host` sobre una VPS virtualizada, llegan con **datos reales del anfitrión**: el hostname del servidor, referencias a `cloud-init`, un `resolv.conf` que dice "Generated by Docker Engine", los módulos de kernel de Docker, el flag `hypervisor` en la CPU y los 2 GB de RAM reales. Hay que **sanearlo** antes de instalarlo, y es lo que hace el apartado siguiente.

#### 3.4.2.4 Verificación y saneamiento del pickle antes de instalarlo.

El árbol salió perfecto, así que el saneamiento no lo toca: reescribe solo esa veintena de ficheros especiales. Los de `/proc` porque son virtuales y el kernel los genera al vuelo, de modo que dentro del contenedor describen el hardware real de la VPS, y los de red porque con `--network host` heredaron la identidad del anfitrión.

Cowrie trae una herramienta (`dumpfs.py`) para volcar el pickle en texto y auditarlo. La extraemos y comprobamos que los usuarios, uid, permisos y contenido son los correctos:

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/scripts/dumpfs.py /tmp/dumpfs.py
```

**Comprobamos que los cinco usuarios salen con sus uid correctos y con el home en `40750`:**

El `40750` (`drwxr-x---`) es lo que hace que un usuario no pueda husmear en el home de otro. Con `40755` el señuelo dejaría que cualquier cuenta listara los proyectos y las claves de las demás, y el control de permisos de los módulos no tendría nada que denegar. Lo fija `build-dirtyland-fs.sh`, porque `useradd -m` los crea en `0755`.

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -E '^/home/(mihail|admin|user-ssh|mykhailo|alyosha)\s'
```
El output que tiene que dar:

/home/admin	    DIR	40750	1001:1001	4096<br>
/home/alyosha	DIR	40750	1004:1004	4096<br>
/home/mihail	DIR	40750	1000:1000	4096<br>
/home/mykhailo	DIR	40750	1003:1003	4096<br>
/home/user-ssh	DIR	40750	1002:1002	4096<br>

**Comprobamos permisos críticos (claves SSH en 600, .env en 600) y que la base es Debian 13:**

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -E '/home/alyosha/\.ssh/|/home/admin/ignis api/\.env'
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -E '^/etc/(debian_version|passwd)\s'
```

/home/admin/ignis api/.env	REG	100600	1001:1001	332<br>
/home/alyosha/.ssh/id_ed25519	REG	100600	1004:1004	419<br>
/home/alyosha/.ssh/id_ed25519.pub	REG	100644	1004:1004	108<br>
/home/alyosha/.ssh/known_hosts	REG	100644	1004:1004	237<br>
/etc/debian_version	REG	100644	0:0	5<br>
/etc/passwd	REG	100644	0:0	1190<br>

**Comprobamos que el "tell" de Docker (`/.dockerenv`) fue eliminado (debe salir vacío):**

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -iE 'dockerenv'
```

No devuelve nada.

Falta lo más importante, que no se ve mirando el árbol: **qué contenido incrustó `createfs.py` dentro de los ficheros de sistema**. Salió del anfitrión de verdad, y por eso lleva sus datos. En nuestro caso delataba doce cosas, todas por haber generado el pickle sobre una VPS virtualizada y con `--network host`:

| Fichero | Qué delataba |
|---|---|
| `/etc/hostname`, `/etc/hosts` | El hostname **real** del servidor, y rastros de `cloud-init` |
| `/etc/resolv.conf` | Literalmente `# Generated by Docker Engine`, y el dominio del proveedor |
| `/proc/modules` | Los módulos de Docker (`veth`, `bridge`, `br_netfilter`, `xt_MASQUERADE`): la huella de un host de contenedores |
| `/proc/cpuinfo` | El flag `hypervisor`, el chivato clásico de virtualización, y un Xeon Gold de servidor con un solo núcleo |
| `/proc/meminfo` | Los 2 GB reales de la VPS |
| `/proc/version` | Un kernel con sufijo `-cloud` y otra fecha de compilación. Contradice al `uname -a` |
| `/etc/os-release` | Vacío, por ser un enlace a `/usr/lib/os-release`, que no está en `EMBED_PATHS`. Y es de lo primero que mira cualquiera |
| `/etc/localtime` | `Etc/UTC` en vez de la zona de la leyenda. En Debian 13 ese enlace **es** la zona horaria, porque `/etc/timezone` ya no existe |
| `/etc/group` | El grupo `sudo` vacío, con un `.bash_history` lleno de `sudo apt` |
| `/etc/shadow` | Todas las cuentas bloqueadas y fechadas el día del build, no en marzo como dice la leyenda |
| `/proc/mounts`, `/etc/mtab` | Enlaces al PID del contenedor de construcción, o sea **rotos**: `cat /etc/mtab` no devolvía nada |
| `/proc/9355`, `/proc/self` | Un directorio con el PID del build. Un `ls /proc` enseña dos números y el segundo no sale en `ps aux` |

Tres más se arreglan **fuera del pickle**, en el 3.4.2.8: `ps` mostraba procesos de otra máquina, `netstat` delataba un Ubuntu y `free` daba la RAM del anfitrión.

Los ficheros de `/proc` no se pueden escribir a mano en el contenedor, así que la única vía es reescribir los bytes ya incrustados en el pickle. De eso se encarga `sanitize-pickle.py`, que los deja coherentes con la leyenda: un PC de desarrollo con un i5-12400, 16 GB de RAM, kernel sin `-cloud`, DNS de la LAN corporativa y `alyosha` en el grupo sudo. Los escribe también en el `honeyfs`, porque algún comando emulado, como `free`, los lee del disco y no del pickle.

El script está en **COWRIE FAKE ENVIRONMENT**, así que también viene con el repositorio:

```bash
cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/sanitize-pickle.py" /tmp/sanitize-pickle.py
```

Para luego ejecutarlo. Recibe el pickle recién generado, escribe el pickle final saneado, y de paso puebla el `honeyfs` con los ficheros que el código emulado lee de disco:

```bash
sudo python3 /tmp/sanitize-pickle.py /opt/dirtyland/cowrie/fs/fs.pickle.new /opt/dirtyland/cowrie/fs/fs.pickle /opt/dirtyland/cowrie/honeyfs
```

Fíjate en el orden: entra `fs.pickle.new`, el sucio, y sale `fs.pickle`, el definitivo. Así el `.new` queda como respaldo del estado sin sanear.

Lo primero que hace es dejar **legibles** `/proc/mounts` y `/etc/mtab`, y escribir la historia del disco:

<pre>
Corrigiendo /etc/mtab y /proc/mounts:
  OK: /etc/mtab -> /proc/mounts
  OK: /proc/mounts pasa de enlace roto a fichero con la tabla
</pre>

<b>Por qué una sola tabla.</b> `/proc/mounts`, `/etc/mtab` y el comando `mount` dicen lo mismo en un Linux de verdad, así que los tres salen de la constante `PROC_MOUNTS` del script. Mantenerlas por separado es garantizar que algún día dejen de coincidir. Los tamaños tampoco son libres: `/dev` es la mitad de la memoria que anuncia el `dmesg` enlatado, `/run` el 10% de `MemTotal` y `/dev/shm` el 50%, que son las cuentas que hacen el kernel y systemd, así que `df -h`, `mount` y `/proc/meminfo` cuadran solos. Y el disco es un NVMe porque `/proc/modules` carga `nvme` y no `ahci`.

`/proc/mounts` queda como fichero en vez de como enlace a `/proc/self/mounts`, y es un intercambio consciente: un `ls -l` enseña un fichero donde un Debian enseña un enlace, pero a cambio `cat /proc/mounts` funciona.

Y quita el rastro del contenedor que lo generó:

<pre>
Quitando el PID del contenedor de construccion:
  OK: /proc/9355 renombrado a /proc/48230 (el bash de ps)
  OK: /proc/self -> /proc/48230
</pre>

El número no se elige al azar: **48230 es el `-bash` que declara `ps_command_output.json`**, así que el PID que sale en `ls /proc` es uno de los que `ps aux` reconoce. No se clonan los 85 procesos del JSON porque cada uno arrastraría su medio centenar de ficheros de `/proc/<pid>/`.

Antes de eso arregla **los destinos de todos los enlaces simbólicos**, que son varios miles:

<pre>
Corrigiendo los enlaces simbolicos:
  OK: 7453 destinos de enlace con su barra inicial
</pre>

<b>Por qué hay que tocarlos.</b> `createfs.py` guarda el destino con `os.path.realpath(path)[len(localroot):]`, y con `localroot="/"` eso le quita la barra inicial. El resultado se ve en cualquier `ls -l` del señuelo:

<pre>
localtime -> usr/share/zoneinfo/Europe/Kyiv
S01cron   -> etc/init.d/cron
</pre>

Un Linux real imprime `/usr/share/zoneinfo/Europe/Kyiv`, y no es un enlace suelto: afecta a todos los del sistema de ficheros. Descuadraba además el tamaño, porque el `st_size` de un enlace es la longitud del destino original (`../init.d/cron`, 14) y lo guardado es el resuelto (`etc/init.d/cron`, 15), así que se recalcula. Lo que no se recupera es la forma relativa, que `realpath` ya perdió: queda un enlace absoluto, válido y coherente aunque un Debian de serie tenga ahí uno relativo.

Y avisa si falta la lista de paquetes que alimenta al `dpkg -l`:

<pre>
Lista de paquetes para dpkg -l:
  OK: 558 paquetes, del mismo contenedor que el pickle
</pre>

No hay que copiarlo a ninguna parte: el `docker-compose` lo monta desde `fs/`, que es donde el generador lo deja, al lado del pickle. **Es a propósito.** Copiarlo a mano sería un paso más, y el día que se regenerara el sistema de ficheros sin repetirlo, el señuelo quedaría con el pickle nuevo y la lista de paquetes vieja: dos versiones distintas de sí mismo, sin ningún error que lo dijera. Los artefactos que **se generan** viven todos en `fs/` y se montan de ahí; en `etc/` solo está lo que viene escrito del repositorio.

<b>Por qué el `dpkg -l` no lleva su lista dentro.</b> La llevaba, una tabla de 26 paquetes escrita a mano, y había envejecido sin que nada avisara: 20 de esas 26 versiones ya no coincidían con Debian 13 y una contradecía al banner que el propio señuelo anuncia. Además 26 son pocos, que una `debian:13` recién bajada ya trae 78. Ahora la lista sale del mismo contenedor que genera el pickle, así que el `dpkg -l` y el disco falso no pueden discrepar, y el módulo solo la formatea reproduciendo las columnas, que se ajustan al contenido.

Entre medias corrige la zona horaria, que en Debian 13 vive en un enlace y no en un fichero:

<pre>
Corrigiendo la zona horaria:
  OK: /etc/localtime -> usr/share/zoneinfo/Europe/Kyiv
</pre>

Si sale un `AVISO: ... no esta en el pickle`, el saneador **deja el enlace como estaba** en vez de dejarlo roto apuntando a una zona que no existe en el árbol: un enlace roto delata más que un UTC. Querría decir que `tzdata` no entró en el contenedor de construcción.

La zona acaba dicha en <b>tres</b> sitios y los tres tienen que coincidir, porque cubren a lectores distintos: la variable `TZ` del servicio y el montaje de `/etc/localtime` gobiernan a los procesos del contenedor, de donde salen las fechas que imprime el señuelo, y este enlace dentro del pickle es el que ve el atacante con un `ls -l /etc/localtime`. Si el señuelo responde con hora de Kyiv y su `/etc/localtime` dice `Etc/UTC`, son dos mitades de la misma mentira que no se sostienen.

El saneador termina con dos cosas mas, anadidas al habilitar telnet:

**Comprobación de coherencia.** Avisa si el señuelo ofrecería el 23 sin nada en su disco que lo explique. Son **dos** líneas, y hacen falta las dos:

<pre>
Coherencia de telnet:
  OK: el pickle trae inetd, su configuracion y el servidor
  OK: /etc/inetd.conf declara telnet sin comentar
</pre>

Si en su lugar sale un `AVISO: faltan en el pickle: ...`, faltan los paquetes: hay que añadirlos a `PACKAGES` y regenerar. No aborta, porque un pickle sin telnet sigue valiendo para SSH, pero se niega a pasar desapercibido, que es justo lo que hace falta: la degradación sería invisible en el arranque.

<b>Por qué se mira en dos sitios.</b> El listado lo da el pickle, pero el contenido de `/etc/inetd.conf` no figura en la `EMBED_PATHS`, así que llega vacío y lo que responde un `cat` sale del honeyfs. Comprobar solo la primera mitad daba un <b>OK engañoso</b>: `inetutils-telnetd` en trixie instala solo el binario y no registra nada, así que el fichero llegaba entero comentado mientras el señuelo contestaba en el 23, y un `cat` mostraba una máquina que no explica su propio puerto abierto.

El aviso, si salta, es `AVISO: /etc/inetd.conf NO declara telnet`. La línea la activa el propio Debian dentro del contenedor de construcción con `update-inetd --enable telnet`: ya viene en el fichero, desactivada con el marcador `#<off>#`.

**Instalación de los `/etc` de serie.** El saneador copia al honeyfs lo que `build-dirtyland-fs.sh` exporto en `fs/honeyfs-etc/`, y lo hace en el mismo comando para que no haya un paso manual que se pueda olvidar:

<pre>
  OK: /opt/dirtyland/cowrie/honeyfs/etc/inetd.conf      (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/issue           (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/issue.net       (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/ssh/sshd_config (de Debian, no inventado)
</pre>

<b>Dos orígenes, y la diferencia importa.</b> Los ficheros de la leyenda (`hostname`, `hosts`, `resolv.conf` y el destino de `localtime`) se <b>inventan</b>, porque tienen que mentir. Los de serie (`issue`, `issue.net`, `inetd.conf` y `ssh/sshd_config`) se <b>copian</b> de un Debian real, porque no dependen de nuestra historia y escribirlos a mano es inventarse un formato; del `sshd_config` se cambia `PermitRootLogin yes` antes de copiarlo, porque el señuelo acepta `root` con contraseña. Y `etc/issue.net` no es decorativo: es de donde Cowrie saca el banner de telnet, y si falta escribe `ERROR: Failed to load /etc/issue.net` en cada arranque y sirve un banner vacío.

Se comprueba que el banner ha quedado bien:

```bash
sudo cat /opt/dirtyland/cowrie/honeyfs/etc/issue.net
```

Y que el pickle trae ya el servidor de telnet y su configuración:

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle | grep -E '^/(etc/inetd\.conf|usr/sbin/(inetd|tcpd|in\.telnetd|telnetd))\s'
```

Que existan no basta: hay que ver lo que el atacante vería al abrir el fichero. Tiene que salir la línea de telnet **sin comentar**, y los dos binarios que cita en la orden anterior:

```bash
sudo grep -vE '^\s*#|^\s*$' /opt/dirtyland/cowrie/honeyfs/etc/inetd.conf
```

<pre>
telnet	stream	tcp	nowait	root	/usr/sbin/tcpd	/usr/sbin/telnetd
</pre>

Si esa línea sale precedida de `#<off>#`, el fichero está como lo deja Debian de fábrica y el `update-inetd --enable telnet` del 3.4.2.3 no se ejecuto.

Esto sanea el <b>pickle</b>, pero hay una <b>segunda parte</b>: tres comandos que Cowrie emula (`ps`, `netstat`, `free`) también delatan el entorno real y necesitan montarse como binds en el compose, así que se sanean en el apartado 3.4.2.8, una vez definido.

#### 3.4.2.5 Preparar el honeyfs (contenidos).

El honeyfs es el directorio con el contenido real de los ficheros. Se extrae del mismo tar, respetando la ruta.

<b>¿Por qué el mismo árbol dos veces?</b> Porque el pickle guarda los <b>metadatos</b> (lo que ve un `ls -la`) y el honeyfs el <b>contenido</b> (lo que ve un `cat`). Los dos salen del mismo tar para que tamaños y contenido cuadren.

```bash
sudo tar -xpf /tmp/home.tar -C /opt/dirtyland/cowrie/honeyfs
```

Comprobamos que ha caído donde toca (los cinco usuarios bajo `honeyfs/home/`) y que las fechas siguen siendo las diseñadas y no las de hoy:

```bash
ls -la /opt/dirtyland/cowrie/honeyfs/home/
sudo find /opt/dirtyland/cowrie/honeyfs/home -newermt '30 days ago' | head
```

El primer comando debe listar `admin`, `alyosha`, `mihail`, `mykhailo` y `user-ssh`; el segundo no debe devolver nada (si devuelve ficheros, el `.tar` se ha creado o extraído perdiendo los `mtime`, y todo el árbol aparecería recién creado).

El `-p` de `tar` preserva permisos, y al extraer como root también los propietarios. Importa porque el `.env` y las claves SSH del señuelo deben seguir en `600`: un fichero de credenciales legible por todos es tan sospechoso como no tenerlo.

#### 3.4.2.7 Alerting en tiempo real vía Telegram (Cowrie).

Esto no requiere tocar el cortafuegos: el DNS del contenedor lo resuelve Docker internamente, sin salir por `dirtyland0`, así que el bloqueo de UDP saliente no lo afecta, y el TCP/443 saliente ya estaba permitido.

El propio cowrie trae un plugin para notificar vía telegram. Sin embargo, lo vamos a modificar. Por defecto muestra:

- `cowrie.login.success` -> alguien acertó unas credenciales y entró.
- `cowrie.command.input` -> un comando que Cowrie sí sabe emular.
- `cowrie.command.failed` -> un comando que Cowrie **no** reconoce. Ojo, no significa "comando erróneo": son los binarios exóticos que el atacante esperaba encontrar, y suelen delatar mejor su intención que los comandos normales.
- `cowrie.session.file_download` -> se descargó

Y estas son nuestras cinco modificaciones sobre el original:

1. **Fecha en cada alerta.** El plugin original no la incluía; con varias alertas llegando en ráfaga, saber la hora sin ir al log importa.
2. **Descargas enriquecidas.** Además de la URL, ahora incluye el **SHA256**, el fichero destino y un enlace ya montado a VirusTotal con ese hash. Es lo que alimenta directamente la fase de reporte del informe.
3. **Enlace a AbuseIPDB** bajo cada IP, para ver país, ASN y reputación con un toque. Se hace así, y no consultando una API de geolocalización desde el propio honeypot, para no generar tráfico saliente extra que compita con el rate-limit de egress ni añadir dependencias de terceros: la consulta la hace el operador desde su móvil, no la máquina.
4. **Reporta también `cowrie.session.file_upload`** (subidas por SCP), que el original ignoraba. Una subida es tan interesante como una descarga.
5. **Escapa el HTML del input del atacante.** Sin esto, un comando que contenga `<` o `>` rompería el `parse_mode=HTML` y esa alerta no llegaría nunca.
6. **La bandera y el país de cada IP**, pegados a la línea del `Source`, que es lo que se lee de reojo en el móvil. Sale de una tabla en disco, así que **no cuesta ni una consulta ni un milisegundo de espera** (apartado 3.4.4).

   <pre>
   [Cowrie vía Telnet]

   Event: cowrie.command.input
   Source: 153.117.13.106  🇵🇰 Pakistan
   Ver IP en AbuseIPDB
   </pre>

   Es el país donde está **registrado el rango**, no donde está la máquina: un atacante detrás de un VPS holandés sale de Países Bajos. Por eso va pegado a la IP y no como un "desde tal país". Y si la tabla faltara, la alerta sale igual, sin bandera: el adorno no puede tumbar un aviso.

7. **Calla lo repetido, pero no lo nuevo.** Sin esto el canal es inservible: una sola IP llegó a dar **10.038 eventos idénticos en dos horas**. De cada IP se avisan sus **dos primeras** veces con un mismo guion (el contador va por (IP, guion), así que un guion distinto vuelve a sonar desde cero) y a partir de ahí se calla, salvo que teclee algo que nunca le habíamos visto. Lo callado no se pierde: se cuenta y sale en el resumen.

<b>Los comandos no llegan de uno en uno.</b> El plugin separa los eventos en dos grupos, y conviene saberlo antes de probarlo o parecerá que no funciona:

- <b>Inmediatos</b> (`PRIORITY_EVENTS`): el acceso con credenciales acertadas y las subidas y descargas de ficheros.
- <b>Agrupados</b> (`BATCH_EVENTS`): `cowrie.command.input` y `cowrie.command.failed`, que se acumulan y se envían en un único resumen al cerrarse la sesión.

Cuarenta comandos en diez segundos serían cuarenta mensajes y un móvil inservible; agrupados son uno solo, que además deja ver la secuencia completa de un vistazo. La consecuencia al probarlo es que mientras sigas conectado por SSH <b>no llegará nada</b> de los comandos: hay que cerrar la sesión con `exit`.

<b>De cada IP se recuerdan sus comandos, y el tope importa.</b> Para saber si una IP ha tecleado algo nuevo se guarda un hash corto de cada comando suyo, hasta `MAX_CMDS_PER_IP`. Estuvo en 80 y era poco: un bot con un guion largo no cabía entero en su propia memoria, así que cada pasada "descubría" comandos ya vistos y la alerta no callaba nunca. Ahora son 400. Y para que no dependa de ese número, si de una IP se ha tenido que olvidar algo se marca y se deja de afirmar que nada es nuevo, porque sobre una memoria incompleta no se puede distinguir "nunca lo hizo" de "se me olvidó":

<pre>
Vez 341 con este guion, callada desde la 3, suena por lo de abajo
Guion 79b8b0d62de1631d
Comandos que no le habiamos visto nunca:
</pre>

Los cuatro ficheros vinieron con el repositorio en el apartado 3.4, así que se copian en su sitio. No hay que pegar nada:

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram_alert_cowrie.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-ban-watcher" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-ban-watcher.service" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-notification-ban" "/opt/dirtyland/Telegram Reports/"
```

Y se comprueba que están los cuatro:

```bash
ls -la "/opt/dirtyland/Telegram Reports/"
```

Las notificaciones de telegram y el manejo de la API requiere de un chat ID y API Token.<br>
Cuando creamos un bot con `@BotFather` en Telegram, devolverá un token. En caso de no devolver ningún token, vamos a generarlo en el @BotFather ejecutamos `/mybots` seleccionamos el que nos interesa y seguimos lo que nos dice.

Luego lo más importante, cuando lo obtengamos, tenemos que iniciar el chat, y escribir cosas en él, muy importante. Si no hacemos eso, el script no nos funcionará y basta con seguir escribiéndole al chat cosas hasta que al ejecutar el script ya nos devuelva el ID.

Para obtener el "chat_id" he creado un script que automatiza esto, está en base64 que se decodifica y ejecuta. El motivo por el que está en base64, es porque visualmente es de una sola línea, te pide el token y el ya te encuentra el chat_id:

```bash
bash <(echo "cmVhZCAtcCAiRW50ZXIgeW91ciBib3QgdG9rZW46ICIgVE9LRU4KaWYgWyAteiAiJFRPS0VOIiBdOyB0aGVuIGVjaG8gIlRva2VuIGlzIGVtcHR5LiI7IGV4aXQgMTsgZmkKZWNobyAiT2J0YWluaW5nIENoYXQgSUQuLi4iClJFU1BPTlNFPSQoY3VybCAtcyAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRUT0tFTi9nZXRVcGRhdGVzIikKQ0hBVF9JRD0kKGVjaG8gIiRSRVNQT05TRSIgfCBncmVwIC1vRSAnImNoYXQiOlx7ImlkIjotP1swLTldKycgfCB0YWlsIC0xIHwgc2VkICdzLy4qImlkIjovLycpCmlmIFsgLXogIiRDSEFUX0lEIiBdOyB0aGVuCiAgZWNobyAiRXJyb3I6IE5vIGNoYXQgZm91bmQuIFNlbmQgYSBtZXNzYWdlIHRvIHlvdXIgYm90IGZpcnN0LiIKICBleGl0IDEKZmkKZWNobyAiQ2hhdCBJRDogJENIQVRfSUQiCg==" | base64 -d)
```

El "chat_id" es el valor `result[0].message.chat.id`.

Una vez tengamos tanto el chat_id como el token lo ponemos dentro.

```bash
sudo nano /opt/dirtyland/Telegram\ Reports/telegram.cfg
```

**La estructura del `telegram.cfg` está en el repositorio**, en **[TELEGRAM SCRIPTS/COWRIE/telegram.cfg.example](TELEGRAM%20SCRIPTS/COWRIE/telegram.cfg.example)**. Y evidentemente las API Keys o Tokens o ID's no se comparten con nadie jamás.

Como Python es sensible a la indentación y pegar en un editor por terminal puede alterarla, validamos la sintaxis del fichero antes de montarlo (se hace con el Python del host, no con el del contenedor, porque el fichero todavía no está montado dentro):

```bash
sudo python3 -c "import ast; from pathlib import Path; ast.parse(Path('/opt/dirtyland/Telegram Reports/telegram_alert_cowrie.py').read_text()); print('sintaxis OK')"
```

Comprobaremos antes de nada que el cfg tiene los tokens y que los scripts no traen saltos de línea de Windows:

```bash
grep -E '^(bot_token|chat_id)' "/opt/dirtyland/Telegram Reports/telegram.cfg"; file "/opt/dirtyland/Telegram Reports/telegram-ban-watcher" "/opt/dirtyland/Telegram Reports/telegram-notification-ban"
```

Instalamos los dos scripts en el host:

```bash
sudo install -o root -g root -m 0755 "/opt/dirtyland/Telegram Reports/telegram-notification-ban" "/opt/dirtyland/Telegram Reports/telegram-ban-watcher" /usr/local/sbin/
```

Instalamos y arrancar el servicio:

```bash
sudo install -o root -g root -m 0644 "/opt/dirtyland/Telegram Reports/telegram-ban-watcher.service" /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now telegram-ban-watcher && sudo systemctl status telegram-ban-watcher --no-pager
```

Creamos el directorio de escritura con el uid del contenedor:

```bash
CU=$(sudo ps -o uid= -p $(sudo docker inspect -f '{{.State.Pid}}' dirtyland_cowrie) | tr -d ' ') && echo "uid de Cowrie visto por el host: $CU" && sudo mkdir -p "/opt/dirtyland/Telegram Reports/state" && sudo chown "$CU" "/opt/dirtyland/Telegram Reports/state" && sudo chmod 770 "/opt/dirtyland/Telegram Reports/state" && sudo chown "$CU" "/opt/dirtyland/Telegram Reports/telegram.cfg" && sudo chmod 600 "/opt/dirtyland/Telegram Reports/telegram.cfg" && ls -la "/opt/dirtyland/Telegram Reports/"
```

<b>Activar el plugin en `cowrie.cfg`.</b> Tener el fichero dentro del contenedor no basta: Cowrie solo carga un motor de salida si existe su sección en la configuración.

```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```

Y le añadimos al final:

```ini
[output_telegram]
enabled = true
```

Comprobamos que ha quedado escrita:

```bash
grep -A1 "^\[output_telegram\]" /opt/dirtyland/cowrie/etc/cowrie.cfg
```

> [!WARNING]
> <b>El nombre de la sección no se elige, y no funciona como uno esperaría.</b> El cargador de Cowrie (`src/twisted/plugins/cowrie_plugin.py`) hace esto:
>
> ```python
> engine: str = x.split("_")[1]
> output = import_module(f"cowrie.output.{engine}").Output()
> ```
>
> Es decir, parte el nombre de la sección por el guion bajo y se queda con <b>el primer trozo</b>. Una sección `[output_telegram_alert_cowrie]` daría `engine = "telegram"` y Cowrie importaría `cowrie.output.telegram`, que es <b>el plugin de fábrica</b>, no el nuestro. Y lo peor: no da ningún error. En el log aparece un tranquilizador `Loaded output engine: telegram` mientras nuestro plugin no se ha cargado y las alertas no llegan nunca.
>
> Por eso la sección es `[output_telegram]` a secas y el plugin se monta <b>encima</b> del `telegram.py` original (apartado 3.4.2.9): en el host el fichero conserva su nombre descriptivo, y lo que apunta al nombre que Cowrie espera es la <b>ruta de destino</b> del montaje. Como consecuencia, un módulo cuyo nombre lleve guiones bajos es inalcanzable para este cargador.
>

La parte de Telegram queda repartida en tres apartados: aquí van los cuatro ficheros del plugin, el `telegram.cfg` con los tokens, el servicio de baneos y el buzón `state/`; en el 3.4.2.9 los tres montajes que los meten en el contenedor, y <b>hasta ese apartado las alertas todavía no llegan</b>; en el 3.4.2.10 el `cowrie.cfg` definitivo. El segundo bot, el que vigila el anfitrión, es independiente de todo esto y se monta en el 3.4.4.

<b>Cómo sabe el plugin qué IPs somos nosotros.</b> Los rangos privados los lleva escritos, pero los nodos de salida del VPN son direcciones públicas normales. Sin ellos, una comprobación propia llega como si fuera un ataque y el botón rojo ofrece <b>banear tu propio nodo</b>, que te deja fuera de la máquina.

La lista buena es la `[blocklist]` del `config.ini`, pero ese fichero no se monta en el contenedor ni debe montarse, porque lleva las claves de API. Lo que se hace es que el reporter publique solo la lista, sin secretos, en `/opt/dirtyland/Telegram Reports/ips-propias.txt`, y el plugin la lea de ahí. Se reescribe en cada pasada, así que añadir un nodo al `[blocklist]` llega solo. El fichero no existe hasta la primera pasada del reporter (apartado 3.5), y no pasa nada.

#### 3.4.2.8 Comandos emulados: instalar el juego completo ya parcheado.

Esta es la <b>segunda parte del saneamiento</b> que empezamos en el apartado 3.4.2.4. Allí saneamos el pickle (lo que Cowrie lee de disco); aquí sustituimos los <b>comandos</b>, que Cowrie genera por su cuenta y que, tal como vienen de fábrica, delatan el señuelo o filtran datos reales del anfitrión.

La shell emulada implementa cada comando como un módulo de Python. Corregirlos uno a uno en el servidor (sacándolos con `docker cp` y parcheándolos con `sed`) es lento y, sobre todo, **no es reproducible**: cada reinstalación obligaría a repetir decenas de parches a mano y a acertar con todos. Por eso el repositorio ya trae **el juego completo de módulos corregidos**; aquí solo hay que colocarlos y montarlos.

Los <b>70 ficheros</b> están en **[`COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE`](COWRIE%20FAKE%20ENVIRONMENT/COMANDOS%20COWRIE)** del repositorio (dentro del entorno falso, porque son parte de él: lo que el atacante ve al teclear un comando y lo que ve al mirar un fichero tienen que contar la misma historia). Lo que corrigen, agrupado:

| Grupo | Módulos | Qué arregla |
|---|---|---|
| Identidad del sistema | `lsb_release`, `dpkg`, `systemctl`, `journalctl`, `uptime`, `systemd_detect_virt` | Coherencia con Debian 13 + systemd; `systemd-detect-virt` no confiesa el contenedor. `dpkg` **no lleva la lista de paquetes escrita dentro**: la lee del fichero que exporta el generador del sistema de ficheros (3.4.2.3), del mismo contenedor del que sale el pickle |
| Hardware | `nproc`, `lscpu`, `lsblk`, `dmidecode`, `free`, `getconf` | Cuentan el mismo hardware que el pickle (i5-12400, 16 GB). `free` lee el `meminfo` del honeyfs y lo formatea como el `procps-ng` de Debian 13 (`16Gi`, no `16G`). `lsblk` describe un **NVMe**, lo único coherente con `/proc/modules`. Y `getconf LONG_BIT` devuelve **64**, que es lo que miran los droppers de Mirai para elegir binario |
| Discos y memoria | `df`, `mount`, `top` | Los tres estaban rotos o mintiendo: `df` y `mount` daban `Exec format error` y `top` devolvía un error de Vim. Ahora `df` y `mount` cuadran con `lsblk`, con `/etc/fstab` y con `/proc/mounts`, y `top` se dibuja con los procesos del mismo `ps_command_output.json` que `ps aux`, se refresca cada 3 s y sale con `q`. En la cabecera de memoria había un espacio de más en cada uno de los ocho campos, porque el `%9.1f` ya trae su relleno, y la línea de `Swap` lleva un punto antes de `avail Mem` y no una coma: no es una errata, es así |
| Editor | `nano` (y `pico`) | Emulación real, no un mensaje enlatado: antes contestaba `E558`, que es un error de Vim. Dibuja la pantalla de GNU nano 8.4, acepta `^O`, `^X`, `^G` y `^C`, respeta los permisos y **guarda en el sistema de ficheros falso lo que el atacante escribe**, así que un `cat` posterior lo devuelve |
| Entorno de la sesión | `honeypot.py`, `printenv`, `env`, `set` | Las variables que un login deja puestas, medidas en un Debian 13 real entrando por SSH y por telnet. Cowrie ponía `TMOUT=1800`, que ningún Debian pone, exportaba variables de shell que no salen en `printenv`, y le faltaban `PWD`, `SHLVL`, `MAIL`, las `SSH_*`, las `XDG_*` y el `LS_COLORS`. `printenv` ni existía |
| **`apt`** | `apt`, `apt-get`, `ps`, `systemctl` | **No instala nada**: consulta lo que ya está instalado leyendo el mismo fichero que `dpkg`, así que no pueden contradecirse. Antes contestaba `E: Unable to locate package nmap`, y nmap **está** en Debian, o sea que la regla de "lo que no está, no se encuentra" era mentira comprobable justo con los paquetes que se piden. Ahora contesta lo que contesta `apt` con el candado de dpkg ocupado, que ni llega a mirar si el paquete existe; `apt update` sigue funcionando porque usa otro candado, y lo sostiene `unattended-upgrades`, añadido al `ps` y al `systemctl` para que el PID del mensaje exista. Nos apartamos del real a propósito en una cosa: el de trixie espera para siempre, y un señuelo colgado se lleva por delante el resto del guion del atacante. Y no lo suelta todo de golpe, que así parecía que no hacía nada: va revelando cada línea según contacta el repositorio, con indicador de progreso solo si hay terminal |
| **`awk`** *(rehecho)* | `awk` | **El `-F` no existía**, declarado como bandera sin argumento, así que `awk -F: '{print $2}'` no funcionaba de ninguna de las dos formas en que se teclea. Ahora entiende `-F` (un carácter va literal como manda POSIX, de dos en adelante es una expresión regular), `-v`, `-f`, `--`, las `-W` de mawk, y `NF` y `NR`. Y dejó de decir que es GNU Awk: en Debian 13 el `awk` por defecto es **mawk**, así que `awk --version` y `dpkg -l` se contradecían |
| **`journalctl`** *(rehecho)* + **el paginador** | `journalctl`, `paginador`, `systemctl` | Devolvía once líneas fijas escritas a mano, siempre con fecha de julio y firmando `sshd` cuando el `auth.log` de al lado firma `sshd-session`. Ahora se genera de **la misma fuente que el `auth.log`**, así que los dos registros no pueden contar historias distintas, y entiende `-n`, `-u`, `-r`, `-p`, `-k`, `-b`, `--since`, `--until`, `--list-boots` y `--no-pager`. Como ahora saca cientos de líneas hizo falta el paginador, y son tres programas distintos: el de systemd va con `LESS=FRSXMK`, `less` a secas usa la pantalla alternativa, y `more` es de util-linux y avisa con un porcentaje por bytes. Sin terminal no pagina ninguno |
| **`/var/log/auth.log`** *(nuevo)* | `authlog` | La máquina declaraba `rsyslog.service` activo y `dpkg` lo daba por instalado, pero el fichero no existía, porque rsyslog solo los crea al correr. Y ese fichero lo mira todo el mundo: quien entra comprueba si su acceso quedó anotado, y muchos droppers hacen `> /var/log/auth.log`. Se genera al abrir la sesión, con una semana de historia y al final la entrada del propio atacante, que es la que convence. Va al sistema de ficheros y no al pickle, que ahí nacería correcto y a los cinco minutos mentiría. Tres detalles medidos: marca ISO con microsegundos, las conexiones las firma `sshd-session` desde OpenSSH 9.8, y el fichero es `root:root` y no el `root:adm` de toda la vida |
| Lo que escucha la máquina | `ss`, `netstat`, `ip`, `ifconfig`, `lsof` | Una sola tabla la leen los dos, así que `ss` y `netstat` no pueden discrepar en qué escucha la máquina aunque lo pinten distinto, y los PID que declaran se cruzan. **No había ni un socket UDP**, con `systemd-resolved` declarado activo y su proceso en el `ps`; tres cosas que se midieron en un trixie porque no se adivinan: el stub va con `%lo`, hay un segundo escuchador en `127.0.0.54` y el LLMNR del 5355 sale por v4 y por v6. A `netstat` le faltaba obedecer `-n` y `-p`, así que un `-tulpn` mostraba `*:ssh` en vez de `0.0.0.0:22` y se dejaba la columna `PID/Program name`, y su cabecera decía siempre "w/o servers" aunque listara servidores. A `ss` le faltaba la columna `Netid`, que el de verdad saca en cuanto se piden dos protocolos, o sea en el `ss -tuln` de cualquier reconocimiento, y los anchos iban escritos a fuego con el formato de una versión anterior: el de iproute2 6.x los calcula del contenido y parte cada dirección por el último `:`. Y `netstat` ya no delata el `upstart` de Ubuntu |
| **`sed`** *(nuevo)* | `sed` | El segundo más tecleado de los que no sabíamos ejecutar, 132 usos en 90 días, y fallaba con `Exec format error` a mitad del guion del atacante. Entiende `s///` con cualquier delimitador, direcciones por número, `$`, patrón, rangos y negación, `-n`, `-e`, `-i`, `-E`/`-r`, y las órdenes `d p q =`; lo que no sabe hacer lo dice en vez de fingir que lo aplicó. El detalle que no se adivina: `sed` usa BRE de POSIX, donde `(` y `+` son literales y `\(` y `\+` los metacaracteres, al revés que en Python |
| **`openssl`** *(nuevo)* | `openssl` | Aquí no faltaba, sobraba una contradicción: `openssl` lo arrastra `ca-certificates`, así que existe en el pickle y `dpkg -l` lo declara, pero el intérprete contestaba `command not found`. Ahora responde `version`, la ayuda entera, los resúmenes de `dgst` (que openssl no llama como se piden: `-sha256` se anuncia `SHA2-256`), `enc -base64`, `rand`, `prime`, `ciphers`, `list`, `s_client` y `passwd`. Los hashes de `passwd` y la clave de `genrsa` **se calculan de verdad**, porque una fija sería un delator: dos ejecuciones darían la misma. Lo único que no contesta es `speed`, que describiría el rendimiento del anfitrión |
| **`tr`** *(nuevo)* | `tr` | El comando más tecleado de los que no sabíamos ejecutar, 276 veces en 90 días, por delante de `sed`. Y no fallaba callando: el pickle lo declara, así que un `cat x \| tr -d '\r'` contestaba `Exec format error` a mitad de tubería. Entiende traducción, `-d`, `-s`, `-c`, `-t`, las clases `[:digit:]`, los rangos, los escapes y los octales. Trabaja en bytes y no en texto, que lo que pasa por ahí suele ser un binario |
| **`systemctl`** | `systemctl` | El pie era de un systemd anterior: el 245 escribía `LOAD   = ...` y el 257, que es el que declara nuestro `dpkg`, pone `Legend: LOAD   -> ...` y añade dos líneas. Y no tenía `--version`: contestaba con la lista de unidades, que es lo que hacía con cualquier opción desconocida |
| **`grep`** | `fs.py` | Imprimía el uso de **BSD** en una máquina que dice ser Debian con GNU grep 3.11; el de verdad son dos líneas, por stderr y con código 2. Y un directorio no se decía: `grep x /tmp` contestaba `No such file or directory` sobre algo que el propio `ls` acababa de listar. Ahora dice `Is a directory`, y con `-s` se calla |
| **`find`** | `find` | **No entendía `-perm`**, y `find / -perm -4000` es *la* orden para buscar por dónde escalar: tanto el `-perm` como el `-4000` se colaban por la rama de argumento desconocido, así que listaba la máquina entera. Ahora entiende las tres formas de GNU find (`-4000`, `/2000`, `2755`), las simbólicas y `-type l`, y una ruta que no existe ya no se recorre en silencio. Además colgaba la sesión: cada entrada se volvía a resolver desde la raíz, cuatro recorridos del árbol por fichero, así que el coste crecía con el cuadrado del tamaño y en un `find /` el atacante se iba antes de que contestara. El árbol ya está en memoria y ahora se recorre una vez |
| **`file`** | `file`, `build-dirtyland-fs.sh`, `que_le_falta_al_senuelo.py` | Un binario `setuid` salía igual que cualquier otro ejecutable, que es justo lo que mira quien busca por dónde escalar; el de verdad los marca (`setuid ELF 64-bit`). Faltaban tres más: `/tmp` se anuncia como `sticky, directory`, un enlace roto dice `broken symbolic link to` y los dispositivos dan `character special (1/5)`. Y había una incoherencia al revés de las de siempre: el señuelo emulaba `file` mientras el Debian del que sale el pickle no lo trae, porque se monta con `--no-install-recommends`, así que `file /bin/su` contestaba como el de verdad mientras `which file` no lo encontraba. Se arregla metiendo `file` en `PACKAGES`, y **eso exige regenerar el pickle**; `que_le_falta_al_senuelo.py` comprueba ya las dos direcciones, lo que la máquina dice tener y no sabe ejecutar, y lo que sabe ejecutar y no declara |
| **El disco, en `stat`** | `stat` | Escribía `Device: 801h/2049d`, que decodifica a **`/dev/sda1`, un disco SATA**, en una máquina donde `lsblk`, `df`, `/etc/fstab` y `/proc/modules` hablan de NVMe: era el único que anunciaba otro disco, y ahora una prueba cruza los dos módulos. Además coreutils 9 pone `major,minor` en decimal, `Size:` va con tabulador, `Birth:` ya no dice `-` porque ext4 sí guarda esa fecha, y en `stat -t` el modo va en hexadecimal |
| **La línea de `uptime`** | `uptime`, `w`, `top` (`base.py`) | Los tres imprimen la misma línea y estaba escrita tres veces, las tres distintas: `uptime` y `w` rellenaban las horas con cero donde procps rellena con espacio, `top` decía `1 days`, y ninguna sabía escribir `45 min`, que es lo que sale en la primera hora tras arrancar. Ahora es una sola función |
| **El locale** | `pstree`, `lsblk`, `systemctl` | Los tres dibujan árboles y **los caracteres los eligen según el locale**. La sesión del señuelo no exporta `LANG` ni ningún `LC_*`, así que corre en POSIX y el dibujo es ASCII, pero escribíamos Unicode: `├─` donde va `|-` y el `●` de `systemctl status` donde va un `*`. Van atados por una prueba: si alguien añade un `LANG` UTF-8, falla y recuerda que hay tres módulos que repintar |
| Red | `ping` | Estaba mal de cuatro formas a la vez. Las estadísticas eran una cadena fija, la misma con seis paquetes que con uno y sin relación con los tiempos de encima. `localhost` tardaba 50 ms con `ttl=50`, cuando la vuelta local son centésimas de milisegundo y el TTL es 64. Cualquier nombre resolvía, a una IP inventada y distinta cada vez. Y a una IP literal le ponía el paréntesis, que es el formato de cuando le das un nombre. Ahora los nombres salen del `/etc/hosts` del propio señuelo y las estadísticas se calculan |
| Procesos | `ps` (en `base.py`), `pstree`, `pgrep` | `ps aux` salía **sin columna de órdenes**: el molde rellenaba la cadena de formato en vez del valor, la línea se pasaba de 80 columnas antes de llegar a `COMMAND` y `ps` recorta a la anchura del terminal. Además publicaba `VSZ`/`RSS` sin dividir, los dos pegados. Y `ps -ef` no listaba nada, solo la cabecera, porque el primer argumento se leía al estilo BSD y en `-ef` no encontraba ni `a` ni `x` ni `u`: ahora entiende `-e`, `-A`, `-f` y `-p PID`, que es la otra forma de teclearlo, tan común como `ps aux`. Los tres formatos están comprobados byte a byte contra procps de Debian 13, el PPID se sigue del mismo árbol que cuenta el resto del señuelo en vez de inventarse uno por fila, y la sesión ya no viene congelada en el JSON: se sintetiza para el usuario que esté dentro |
| Ficheros y permisos | `ls`, `cat`, `find`, `stat`, `file`, `fs.py` (`cd`, `head`, `tail`, `grep`, `less`, `more`) | Aplican permisos POSIX de verdad: cada `/home` ajeno es privado (`0750`) y solo root mira dentro, que Cowrie de fábrica no comprueba permisos de lectura. Además `ls -l` de un enlace lo describe en vez de resolverlo, y `stat` toma el desfase horario de `%z` en lugar de llevar `+0300` escrito a mano, que solo acierta de marzo a octubre |
| Integridad | `md5sum`, `shasum` | `sha1/224/256/384/512sum` y `b2sum` devuelven el hash real; antes contestaban "Exec format error" |
| Escalada | `base.py` (`su`), `sudo`, `bash`, `bashbuiltins` | `su` pide contraseña y, si es correcta, **cambia de identidad de verdad** (usuario, uid, prompt, home), y `exit` devuelve al anterior. `sudo` responde como un no-sudoers a un usuario normal y ejecuta la orden si quien llama es root; antes le pedía la contraseña a root y después le contestaba `root is not in the sudoers file`, un imposible que se vio en una sesión real. Su texto de uso era de la rama 1.8 mientras `sudo -V` declaraba 1.9.16p2, así que la versión sale ahora del listado de `dpkg`. Y un `sudo -V` de root no son cinco líneas, son 142, con opciones de compilación, rutas, *defaults* de sudoers y las variables que conserva: como aceptamos `root/root`, ese es el caso habitual, y el volcado vive en `ayudas-comandos.json` porque son datos y no código |
| **Los bucles** | `honeypot.py`, `bashbuiltins.py` | El cuerpo se repetía tres veces y ya, así que `i=0; while [ $i -lt 2 ]` daba tres vueltas donde van dos: **el número de vueltas de cualquier bucle contado estaba mal siempre**, y contar es para lo que se usa un `while`. Ahora cada vuelta devuelve el cuerpo más el propio bucle, así que la condición se vuelve a mirar con el entorno ya cambiado y el bucle termina solo; lo que no termina lo para un tope de cien vueltas. Con eso salieron cinco más: `break` y `continue` contestaban `command not found`, un `break` reiniciaba el bucle hasta reventar la pila, un `if` dentro del cuerpo ejecutaba las dos ramas porque los condicionales se resolvían antes de desenrollar, un bucle con algo pegado al `done` no era un bucle, y **`algo \| while read VAR` no existía**, que es como se recorre un fichero línea a línea en cualquier guion: ahora se ejecuta la izquierda y se da una vuelta por línea con la variable puesta. Y `((i++))` contestaba `i++: command not found` sin mover el contador, porque el evaluador solo sabía leer; ahora también asigna, y `((...))` se reescribe a `let` |
| **Lo que se quedó a medias** | `bashbuiltins`, `nohup`, `cat`, `honeypot.py` | **`time` contestaba `command not found`**, y eso no pasa en ningún bash: no es un binario, es una palabra clave del lenguaje. **`nohup` anunciaba el fichero y no ejecutaba nada**, así que la última línea de casi cualquier dropper (`nohup ./x &`) no hacía nada y el atacante se iba creyendo que su binario estaba en marcha. Y una que no estaba en ninguna lista: `protocol.pp` es una sola ranura, y ejecutar algo por dentro la dejaba apuntando al comando de dentro, así que al volver la tubería de fuera perdía su salida entera y `eval echo hola \| cat` no imprimía nada. Pasaba con todo lo que relanza una orden: `eval`, `command`, `builtin`, `source`, `nice`, `timeout`, `setarch` y `env` |
| **`x86_64` era un envoltorio, no un comando** | `setarch` *(nuevo)* | En Debian `/usr/bin/x86_64` es un enlace a `setarch`, y lo que hace es ejecutar lo que se le ponga detrás. Diez usos en 90 días, y lo más probable es `x86_64 -R ./payload`, que desactiva la aleatorización del espacio de direcciones para que un exploit salga fiable: sin emularlo, la orden de dentro no se ejecutaba nunca y la cadena se cortaba ahí. Van los cuatro nombres que enlazan a setarch en amd64, cada uno nombrándose por su `argv[0]` |
| **`head` metía una línea de más** | `fs.py`, `cat` | Partía el fichero por `\n` y escribía un salto detrás de cada trozo, incluido el vacío que deja el salto final, así que toda salida llevaba una línea en blanco de más y `head -2 fichero \| wc -l` sobre un fichero de una línea contestaba 2. Tirando del hilo salieron dos más: `cat -A` se aceptaba y no hacía nada, que es justo lo que se teclea para ver si un fichero trae tabuladores donde no debe, y `cat -n` separaba con dos espacios donde va un tabulador, así que un `cat -n \| cut -f2` se llevaba la línea entera |
| **`/proc` del proceso** | `sanitize-pickle.py`, `honeypot.py`, `cat` | `cat /proc/self/status` no devolvía ni una línea, y un status en blanco es peor que uno raro, porque no hay ningún Linux donde salga así. Lo lee cualquier cosa que quiera saber dónde ha caído: si hay un depurador enganchado (`TracerPid`), si vive en un contenedor (los `NS*`) o qué privilegios tiene (`Cap*`). Ahora salen como en una máquina de verdad, con `Seccomp: 0` y `NoNewPrivs: 0` donde Docker pone 2 y 1, y con el cgroup, que es lo que de verdad delata un contenedor: un dropper mira `/proc/1/cgroup` antes de instalarse y si ve `/docker/...` se da media vuelta. **Exige regenerar el pickle.** Y el dueño era siempre root, porque el status se hornea al construir el pickle con los datos del bash de root y el pickle es el mismo para todas las sesiones: entrando como usuario normal, `id` decía `uid=1004(alyosha)` y `grep Uid:` decía `Uid: 0`, el mismo proceso con dos dueños en dos órdenes seguidas. Las líneas que dependen de quién entró se corrigen **al leer**, y pasan por ahí todos los lectores (`cat`, `grep`, `head`, `tail`, `less`, `more`) y no solo `cat` |
| **`history` estaba tapado por un no-op** | `base.py`, `bashbuiltins` | Contestaba en blanco y el comando de verdad ya existía: Cowrie recorre `command_modules` en orden y el último que registra un nombre gana, así que el `Command_history` bueno de `base.py` lo tapaba el no-op de `bashbuiltins.py`, que se carga después. Ninguna prueba lo cazaba porque cada módulo por separado está bien: ahora hay una que lee los registros en el orden en que se cargan y comprueba que ningún no-op tape a un comando implementado |
| **Las descargas negaban su versión** | `descargas` *(nuevo)* | `wget --version`, `curl --version` y `tar --version` fallaban, y es lo primero que se mira, porque las opciones cambian entre versiones: un wget que no sabe decir qué wget es, no es un wget. El módulo no reescribe los tres, hereda de los de Cowrie y solo se pone delante para contestar `--version`. Y `gzip` no estaba de ninguna forma aunque el sistema de ficheros lo declara: un `gzip -d payload.gz`, que es el paso siguiente a la descarga en la mitad de los guiones, contestaba `No such file or directory` |
| **La persistencia por `crontab`** | `crontab` *(rehecho)* | **`crontab -` colgaba la sesión**, que es como se instala una tarea desde un guion y la forma más usada de persistir. Y lo que no colgaba, mentía: nada se guardaba, así que un `crontab -` seguido de `crontab -l` contestaba `no crontab for root`. Ahora se escribe donde lo escribe cron (`/var/spool/cron/crontabs/USUARIO`) para que un `cat` de esa ruta y el `crontab -l` cuenten lo mismo, con la cabecera de tres líneas que `crontab -l` no enseña |
| **`useradd` no era `useradd`** | `usuarios` *(nuevo)* | La imagen lo tenía apuntando a la misma clase que `adduser`, y son dos programas distintos: `adduser` es el envoltorio interactivo de Debian y `useradd` el binario de shadow, que no imprime ni pregunta nada. Un `useradd pepe` se quedaba pidiendo una contraseña, o sea colgaba el guion justo donde se crea la puerta trasera. Ahora están los cinco de shadow y lo que hacen se escribe de verdad en `/etc/passwd`, `/etc/group` y `/etc/shadow`, que es lo único que aguanta la comprobación siguiente: el atacante hace `id pepe` acto seguido |
| **`chattr +i` y `lsattr`** | `base.py` | Un `chattr +i` seguido de un `lsattr` se contradecían: el atacante protege su implante, de lo primero que hace quien deja algo en `/tmp`, y el sistema decía que no hay ninguna bandera puesta. `lsattr` ni existía. Las veintidós posiciones no están adivinadas: se midieron poniendo cada bandera en un contenedor con `CAP_LINUX_IMMUTABLE` |
| **`service` describía otra máquina** | `service` *(rehecho)* | `service --status-all` contestaba una lista fija con `cups`, `lightdm`, `bluetooth`, `avahi-daemon` y `open-vm-tools`: **un escritorio Ubuntu dentro de una máquina virtual de VMware**, cuando la leyenda es un servidor Debian 13. Se veía con dos órdenes seguidas, porque `systemctl` no lista ninguna de esas y `dpkg -l` no las declara. Ahora la lista sale de `/etc/init.d` y el estado de la tabla de `systemctl` |
| **`hostname -I` cambiaba el nombre de la máquina** | `base.py` | Lo peor que había: cualquier argumento se tomaba por un nombre nuevo, así que `hostname -I`, de lo primero que teclea quien acaba de entrar, dejaba al atacante con un prompt `root@-I:~#` para el resto de la sesión. Ahora entiende `-a -A -b -d -f -F -i -I -s -y` y sus largas, y la IP sale de `ip.py`, para que `hostname -I`, `ip a` e `ifconfig` no digan tres cosas distintas |
| **`$$`, `$(...)` y la barra** | `honeypot.py` | Tres del intérprete. **`echo $$` escribía `$$`**, y ese número nombra la mitad de los ficheros temporales de cualquier guion (`/tmp/.$$`): lo que se creaba era un fichero llamado literalmente `.$$`. **Una sustitución `$(...)` se resolvía al trocear**, antes de que corrieran las asignaciones de su propia línea, así que `i=$(expr $i + 1)` no avanzaba. Y **un operador escapado con barra volvía a ser operador**: en `expr 2 \> 1` el `2` acababa redirigido a un fichero llamado `1` |
| **`ls` no era `ls`** | `ls`, `paginador` | **Seguía en columnas aunque la salida no fuera un terminal**, y eso no es formato: `ls /etc \| wc -l` contaba 29 donde hay 60, así que todo lo que cuente o filtre la salida de `ls`, que es como se recorre un directorio desde un guion, salía mal. El reparto en columnas tampoco era el suyo: escribía de izquierda a derecha cuando el de verdad llena cada columna hacia abajo, y separaba con un espacio en vez de dos. Para saber si la salida va a un terminal se mira ahora la tabla de descriptores de Cowrie: con `next_command` se cazaban las tuberías pero no un `> fichero` |
| **Nueve de coreutils que faltaban** | `coreutils_mas` *(nuevo)*, `ulimit`, `env`, `uptime` | `arch`, `tty`, `stty`, `nice`, `timeout`, `realpath`, `paste`, `fold` y `expr` contestaban `No such file or directory`, que es la peor forma de fallar, porque significa que la máquina miente: `ls -l` los enseña, `which` los encuentra y `dpkg -l` declara coreutils. `expr` merece mención aparte, que es el que usa cualquier bucle escrito antes de que bash tuviera `$(( ))` y sigue apareciendo en los droppers copiados de sitios antiguos. Además `ulimit` tenía el cuerpo entero en un `pass` y `env` solo sabía listar (`env -i orden` se tragaba la orden) |
| **El código de salida al fallar** | `base.py` (mixin) y los dieciséis módulos que heredan de ella | **Casi ningún comando lo ponía**: escribían su queja y devolvían cero, así que `cat fichero \|\| wget URL -O fichero` se tragaba el respaldo y el atacante veía su guion seguir por la rama que no toca, cuando intentar algo y tener un plan B es la mitad de lo que hace un dropper. Se resuelve en un sitio, con una mixin que marca el fallo al escribir en la salida de error, y se hereda a mano porque hay comandos que escriben ahí sin fallar (el aviso de `apt`, el progreso de `wget`). El código no siempre es 1: `grep` y `sort` dan 2. Tres además colgaban o mataban la sesión: `mkdir /noexiste/x` reventaba con un `FileNotFoundError` que nadie cazaba, `tr a b fichero` no miraba el tercer operando y se quedaba esperando, y `uniq` no sabía leer ficheros |
| **La expansión de `${...}`** | `honeypot.py`, `base.py`, `bashbuiltins.py` | De las formas de `${...}` solo se entendían tres, y no por diseño: el operador se buscaba con un `find()` y ganaba el primero que apareciera. **Todo lo demás salía literal en pantalla**, que es la peor forma de fallar, porque un `${V/b/X}` impreso a pelo no lo escribe ningún shell. Dos decían una cosa y hacían otra: `${V:=x}` devolvía el valor y no lo guardaba, y `${V?msg}` se imprimía entero cuando lo que hace bash es avisar y no ejecutar el comando. Y `$#` ni llegaba entero, porque para el troceador esa almohadilla abre un comentario: `echo $#` imprimía un dólar suelto y se comía el resto de la línea. Con eso, las otras dos piezas del bucle de argumentos de cualquier guion: `set -- a b c` y `shift`, que era un no-op silencioso |
| **`local`, `return` y el entorno de un grupo** | `honeypot.py`, `bashbuiltins.py` | **Cada orden de un paréntesis o del cuerpo de una función se hacía su propia copia del entorno**, así que `(A=1; echo $A)` imprimía una línea vacía y una función no podía usar una variable que ella misma acababa de asignar. Ahora el grupo comparte el diccionario y quien lo lanza decide si vuelve hacia afuera: de una función sí, de un paréntesis no. Y `local` y `return` contestaban que solo valen dentro de una función, también dentro de una, así que **una función que empiece por `local`, la mitad de las de cualquier guion, no hacía nada** |
| **`wc`** *(rehecho)* | `wc`, `coreutils_extra` | **No imprimía nada en los dos casos normales**: escribía recorriendo la lista de opciones, y sin opciones esa lista está vacía, así que `wc fichero` y `algo \| wc` no sacaban ni una línea. Lo que hubo que medir es el ancho de la columna, que no sale de las cifras sino del tamaño en bytes de las entradas, y por una tubería ese tamaño no se sabe de antemano, así que coreutils reserva siete: los mismos números se pintan distinto según vengan de un fichero o de un `\|`. De paso, tres versiones del mismo paquete: `cut --version` decía coreutils 8.30, `chmod --version` 8.25 y `printenv --version` 9.7, en la misma máquina y con un `dpkg -l` que declara una. Ahora salen de una función común que lee el listado de dpkg |
| **`/bin/sh` es dash** | `bash.py`, `honeypot.py` | En Debian `/bin/sh` no es bash, es dash, y Cowrie registraba `sh`, `bash`, `/bin/sh` y `/bin/bash` en la misma clase: escribir `sh` abría una shell idéntica a la de la sesión, así que parecía que la orden no hacía nada. Ahora `sh` baja a `$ `, sus errores salen como `sh: 2: asd: not found` con el número de línea, y dentro de él las flechas escriben su secuencia y el tabulador mete un tabulador, porque dash no tiene edición de línea ni historial |
| Realismo del shell | `honeypot.py`, `seq`, `python`, `busybox` | `$RANDOM`, prompt de continuación `>` cuando un bucle queda a medias, cortocircuito real de `&&`/`\|\|`, y `$?` también incrustado en otro token (`echo rc=$?`), que antes salía literal. Se sustituye justo antes de ejecutar cada comando y no al analizar la línea, para que `cmd; echo $?` dé el código de `cmd` y no el de la línea anterior. Y `$TERM` se rellena en las sesiones de telnet, que no pasan por el `getPty()` de SSH |
| Telnet | `userauth.py` | Negociación telnet estilo Debian (evita el softmatch "Cowrie" de nmap) |

<b>Nuestro `apt` no instala nada, y es a propósito.</b> El de fábrica fingía la instalación y se delataba solo: en una sesión real del 30/08/2026 encadenó un `Permission denied` sobre el fichero de bloqueo a un `apt-get update` lanzado como <b>root</b>, el `-y` instalado como si fuera un paquete, un `.deb` de `i386` en una máquina que dice `x86_64` en todas partes, un `Segmentation fault` al ejecutar lo recién instalado y, treinta segundos después del permiso denegado, el mismo `apt-get` descargando 328 kB tan tranquilo.

Ahora solo se consulta lo ya instalado, leyendo el mismo `dpkg-packages.tsv` que usa `dpkg`, así que los dos no pueden contradecirse. Lo que no está, no se encuentra: quien pida `masscan` recibe `Unable to locate package`, que es la respuesta de un servidor con los repositorios recortados. Queda una imprecisión conocida: trixie trae `apt` 3.0, con otra presentación, y aquí tanto `apt` como `apt-get` dan la clásica.

<b>nano y los ficheros que no se pueden escribir.</b> Un editor que guarda en `/etc/passwd` siendo un usuario normal delata el señuelo al primer intento, y es de los primeros que se prueban. Los avisos no están redactados, son los de un GNU nano 8.4 de verdad, y salen en blanco sobre rojo, que es el estilo que nano reserva a los problemas de permisos.

| Situación | Lo que sale |
|---|---|
| Fichero legible pero no escribible (`/etc/passwd` como usuario normal) | `[ Directory '/etc' is not writable ]` y después `[ File '/etc/passwd' is unwritable ]` |
| Directorio por el que no se puede pasar (`/home/mihail`, modo `0750`) | `[ Path '/home/mihail' is not accessible ]` |
| Fichero que no se puede leer (`/etc/shadow`) | `[ Error reading /etc/shadow: Permission denied ]`, el búfer sale vacío y el título pasa a `New Buffer` |
| `^O` sobre algo que no se puede escribir | `[ Error writing /etc/passwd: Permission denied ]`, y el fichero no se toca |

La comprobación va <b>antes</b> de escribir. Confiar en que `fs.mkfile` falle no sirve, porque Cowrie da de alta el nodo sin mirar permisos, y entonces un usuario normal "guardaba" en `/etc/passwd` y nano contestaba `Wrote 1 line`.

<b>1. Dónde están.</b> Dentro de [`COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE`](COWRIE%20FAKE%20ENVIRONMENT/COMANDOS%20COWRIE) los ficheros están repartidos en tres subcarpetas, según la ruta que ocupan dentro de Cowrie:

| Subcarpeta | Ficheros | Qué son |
|---|---|---|
| `commands/` | 42 | Los comandos de la shell emulada |
| `shell/` | 1 (`honeypot.py`) | El intérprete: `$RANDOM`, `&&`, prompt de continuación |
| `telnet/` | 1 (`userauth.py`) | La negociación telnet |

Ya están en la VPS: se subieron con el repositorio en el apartado 3.4, así que no hay nada que transferir. Los módulos están en `/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE` (repartidos en `commands/`, `shell/` y `telnet/`) y la salida de `ps` en `/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json`.

Antes de seguir, comprobamos en la VPS que han llegado los 70 módulos y el JSON:

```bash
find "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" -path '*/tests/*' -prune -o -name '*.py' -print | wc -l
ls -la "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json"
```

<b>2. Colocar los módulos en `cmdpatch`.</b> En el repositorio están ordenados según su ruta dentro de Cowrie (`commands/`, `shell/`, `telnet/`), pero en el host viven todos juntos en una sola carpeta: quien decide a qué ruta va cada uno es el `docker-compose` del apartado siguiente. El `find` los recoge de las tres subcarpetas y los aplana en una sola. El `-prune` de `tests/` no es adorno: ahí vive la suite del apartado 3.7.10, y sin él se copiaría dentro de `cmdpatch/` y acabaría **montada como un comando más** dentro de Cowrie.

```bash
sudo find "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" -path '*/tests/*' -prune -o -name '*.py' -exec cp -t /opt/dirtyland/cowrie/cmdpatch/ {} +
sudo chown root:root /opt/dirtyland/cowrie/cmdpatch/*.py
sudo chmod 644 /opt/dirtyland/cowrie/cmdpatch/*.py
```

En la misma carpeta del repositorio viaja `txtcmds/`, que **no son módulos**: son salidas enlatadas que sustituyen a las de Cowrie. No las recoge el `find` de arriba (busca `*.py`) y no van a `cmdpatch/`, porque su ruta dentro de la carpeta **es** la ruta del binario en el señuelo:

```bash
sudo cp -a "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE/txtcmds/usr" /opt/dirtyland/cowrie/txtcmds/
sudo chown -R root:root /opt/dirtyland/cowrie/txtcmds
sudo find /opt/dirtyland/cowrie/txtcmds -type f -exec chmod 644 {} +
```

<b>Por qué hacen falta, y por qué cuelgan de `usr/bin/`.</b> Los enlatados de Cowrie viven en `txtcmds/bin/`, y en un Debian moderno cinco de ellos no se disparan nunca (`df`, `dmesg`, `mount`, `sync` y `stty`). No es que mientan, es que el comando se rompe:

<pre>
root@pc-dev-003-ignis:~# df -h
-bash: /usr/bin/df: cannot execute binary file: Exec format error
</pre>

El `getCommand()` de `shell/protocol.py` recorre el `PATH` y se queda con la primera ruta donde el fichero existe, sin resolver enlaces. Como `/usr/bin` va antes que `/bin`, `df` resuelve a `/usr/bin/df` y Cowrie busca el enlatado en `txtcmds/usr/bin/df`, que no existe. Cowrie mira en `[honeypot] txtcmds_path` antes que en los suyos, así que basta poner los que queremos cambiar.

| Fichero | Motivo |
|---|---|
| `usr/bin/dmesg` | El de Cowrie es el arranque de un <b>Debian Lenny de 2009</b>, kernel de 32 bits, y contradice al `uname`, al `/proc/version` y al `/proc/cpuinfo` de la leyenda. El nuestro cuadra con `dmidecode`, `lsblk`, el `meminfo` y la MAC de `ifconfig` |
| `usr/bin/stty` | El de Cowrie está vacío <b>y</b> en `bin/`, de ahí el `Exec format error` |
| `usr/bin/sync` | Igual. Sigue vacío a propósito, porque `sync` no imprime nada, pero el fichero tiene que existir |

`df`, `mount`, `getconf`, `top`, `nano` y `pico` no se arreglan aquí: son módulos de `commands/`, porque un fichero enlatado no ve los argumentos y `df` y `df -h` no dan la misma salida. Los de `vi` y `vim` no se tocan, que ahí el `E558` es de quien tiene que ser.

<b>3. Verificar.</b> Deben ser 70 ficheros y todos tienen que compilar. Esto no es un formalismo: si un módulo tiene un error de sintaxis, Cowrie arranca **sin ese comando** y el atacante recibe un "command not found" en un comando que debería existir, que es justo el tipo de detalle que delata un señuelo.

```bash
ls /opt/dirtyland/cowrie/cmdpatch/*.py | wc -l
sudo env PYTHONPYCACHEPREFIX=/tmp/pyc-check python3 -m py_compile /opt/dirtyland/cowrie/cmdpatch/*.py && echo "los 70 modulos compilan"
```

El `PYTHONPYCACHEPREFIX` manda la caché de compilación a `/tmp` para no dejar un `__pycache__` dentro de `cmdpatch`, que es la carpeta que después se recorre para generar los montajes.

<b>4. La salida de `ps`.</b> Cowrie no la calcula: la lee enlatada de un `ps_command_output.json`. El de fábrica es de otra máquina (muestra `mysql`, `ejabberd`, `nginx`, `exim` e incluso `iprt-VBoxWQueue`, que delata VirtualBox) y no contiene nada de nuestra leyenda. El del repositorio (carpeta **COWRIE FAKE ENVIRONMENT**) sí es coherente: systemd, NetworkManager, sshd y el `pm2`/`node` del proyecto de `admin`.

```bash
sudo cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json" /opt/dirtyland/cowrie/etc/ps_command_output.json
python3 -c "import json; json.load(open('/opt/dirtyland/cowrie/etc/ps_command_output.json')); print('JSON OK')"
```

<b>5. Los textos de `--help`.</b> Otro fichero de datos, por la misma razón que el anterior: son las ayudas de los 49 comandos, **medidas de sus binarios reales dentro de un Debian 13.7**, y meterlas dentro del código haría ilegibles las dos cosas. Sin este fichero nada se rompe (los comandos se comportan como antes) pero `ls --help` vuelve a listar el directorio.

```bash
sudo cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ayudas-comandos.json" /opt/dirtyland/cowrie/etc/ayudas-comandos.json
python3 -c "import json; d=json.load(open('/opt/dirtyland/cowrie/etc/ayudas-comandos.json')); print(len(d)-1, 'ayudas')"
```

<b>Casi ningún comando atendía `--help`.</b> De los 47 módulos que había, la mayoría ignoraba la opción y hacía su trabajo: `ls --help` listaba el directorio, `nproc --help` contestaba `12`, `pwd --help` soltaba `/root`. Ahora el enganche está en un solo sitio (`runCommand`), así que no puede olvidarse ninguno, y va antes de instanciar el comando para que la ayuda pase por la tubería: `ls --help | head -3` funciona. El `-h` no se toca, porque en la mitad de estos comandos significa otra cosa (`df -h`, `ls -h`).

Las ayudas se midieron dentro de un `debian:trixie` y no valen las de otra distribución: medidas antes sobre Ubuntu, 27 de 46 no coincidían. Las versiones de los 18 paquetes con los que se midió viajan en el propio JSON, en su clave `_medido`. Para rehacerlas:

```bash
docker run -d --name debian13 debian:trixie sleep infinity
```

Este fichero llega en la transferencia del paso 2; si se ha saltado, el `cp` fallará con un `No such file or directory` y la alternativa es escribirlo en su destino y pegar dentro el contenido del repositorio:

```bash
sudo nano /opt/dirtyland/cowrie/etc/ps_command_output.json
```

Mejor el `scp`: son unas 1.100 líneas, y pegar ese volumen en una terminal es lento y propenso a que el portapapeles recorte algo. Sea cual sea la vía, la validación con `json.load` de arriba es la que confirma que ha llegado entero: si el JSON está truncado, Cowrie arranca igual pero el comando `ps` deja de responder.

`netstat.py` y `free.py` **ya vienen parcheados** en el repositorio: el `netstat` apunta a `/run/systemd/private` en lugar del `@/com/ubuntu/upstart` de Ubuntu, y el `free` lee `/opt/honeyfs/proc/meminfo`. Este último es la razón de que el saneador del pickle escribiera también en el `honeyfs`: `free` toma el dato del disco, así que ambos deben decir 16 GB.

> [!IMPORTANT]
> Los módulos se montan en **solo lectura** encima de los originales de la imagen, sin reconstruirla. Sustituir o añadir cualquiera de ellos exige recrear el contenedor (`--force-recreate`); un `restart` solo basta cuando se ha editado el contenido de un fichero que ya estaba montado.

<b>6. El `protocol.py` de Cowrie, parcheado.</b> Éste **no viene del repositorio**: es un fichero de la propia imagen que corregimos, igual que el `mssql.py` de Dionaea. Se saca del contenedor, se parchea y se monta encima.

Lo que arregla se ve en un solo intento, y se vio en la máquina: escribe una letra en `[sudo] password for root: `, bórrala, y el cursor **retrocede sobre el prompt y se come una letra del mensaje**. Repítelo y se borra el mensaje entero. Las flechas arriba/abajo, además, **pintan el comando anterior** en el hueco de la contraseña, y `Ctrl-L` repinta la línea de entrada con la contraseña dentro, en claro.

El motivo: `characterReceived()` sí se calla el eco cuando hay una contraseña en curso, pero las teclas de **edición** no están definidas en esa clase (se heredan de `recvline`, de Twisted, que siempre escribe en el terminal). Y sin eco no hay nada en pantalla que borrar, así que lo único que hay delante del cursor es el propio prompt.

Se saca del contenedor **siempre**, también al redesplegar: así, si algún día sube la versión de Cowrie, el parcheador se encuentra un fichero que no reconoce y se planta en vez de montar algo a medias.

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/shell/protocol.py /opt/dirtyland/cowrie/parches/protocol.py
```

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/parche-protocol.py" /opt/dirtyland/cowrie/
```

```bash
sudo /opt/dirtyland/cowrie/parche-protocol.py /opt/dirtyland/cowrie/parches/protocol.py
```

**Por qué un parche y no el fichero entero.** Son 547 líneas de Cowrie que no son nuestras y cambiamos cinco métodos; traerlas obliga a rehacerlas en cada actualización de la imagen. Es el mismo trato que le damos al `mssql.py` de Dionaea.

Ejecutarlo dos veces no rompe nada: dice `ya estaba parcheado` y se va. Y `test_parche_protocol.py` (apartado 3.7.10) no comprueba que el texto cambie: **pulsa las teclas** contra un terminal de mentira, antes y después, y verifica que durante una contraseña no le llega nada. El montaje lo pone el generador del apartado siguiente, que <b>se para si este fichero falta</b>: un compose sin esa línea arranca perfectamente y deja el prompt comiéndose a sí mismo, sin dar ningún error.

#### 3.4.2.9 El bloque definitivo de Cowrie en el docker-compose.

Aquí se cierra el servicio `cowrie` del compose. El servicio en sí **ya existe** desde el apartado 3.4: la imagen fijada, los límites, la red, los puertos y la zona horaria se pusieron con la parte 1 y no se tocan. Lo único que falta son sus montajes: los 70 módulos de comandos, el pickle, el honeyfs, la salida de `ps` y las alertas de Telegram.

Son muchos y no hay forma de acortarlos: Docker no admite comodines, y montar la carpeta entera sobre `commands/` **no vale**, porque taparía los ~40 comandos que Cowrie ya trae y solo quedarían los nuestros. La alternativa es no escribirlos a mano.

<b>1. Generar el bloque `volumes` entero.</b> Y no solo las líneas de los comandos, porque esa parte <b>crece</b>: hoy son 70 módulos y cada comando que añadamos es una línea más. Mantenerlas a mano significa que algún día se añade un comando, se olvida su montaje, y el contenedor sigue ejecutando el de fábrica <b>sin dar ningún error</b>. Un fallo así no se nota hasta que un atacante ve una salida que no cuadra.

El guion vino con el repositorio, así que solo hay que colocarlo en el árbol:

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/DOCKER-COMPOSE/generar-volumes-cowrie.sh" "/tmp/dirtyland-repo/DOCKER-COMPOSE/montajes-dionaea.sh" /opt/dirtyland/
```

Imprime el bloque completo con los montajes fijos, los tres de Telegram y un montaje por módulo, mandando cada uno a su ruta correcta (`honeypot.py` a `shell/`, `userauth.py` a `telnet/`, el resto a `commands/`):

```bash
sudo /opt/dirtyland/generar-volumes-cowrie.sh
```

Y con `--apply` lo sustituye directamente en el `docker-compose.yml`, que es la forma de no volver a pegar nada a mano:

```bash
sudo /opt/dirtyland/generar-volumes-cowrie.sh --apply
```

Antes de tocar nada hace una copia con fecha y después valida el resultado con `docker compose config`; si no fuera válido, restaura la copia y sale con error. Solo se toca el servicio `cowrie`. El bloque se sustituye <b>entero</b>, así que los montajes que ya hubiera se vuelven a escribir desde su lista fija, y si apareciera uno que el guion no conoce <b>se para antes de tocar nada</b> y lo nombra, en lugar de borrarlo en silencio. Hay que volver a lanzarlo **cada vez que se añada un comando emulado**.

> [!WARNING]
> Generarlas es preferible a escribirlas porque el error típico no da la cara: si falta un montaje, el comando afectado sigue existiendo con la versión original de Cowrie y solo se nota cuando delata el señuelo. El caso más traicionero es <b>`__init__.py`</b>: es la lista de comandos que Cowrie carga al arrancar, y es donde está registrado `shasum`. Si se montan los 44 ficheros "de comandos" pero se olvida ese, `shasum.py` estará dentro del contenedor y aun así `sha256sum` seguirá sin funcionar, porque nadie lo ha cargado. Deben ser <b>45 líneas</b>, no 44.

La zona horaria va por duplicado a propósito, por lo que se explicó en el 3.4.2.4: la variable `TZ` cubre a los procesos del contenedor y el montaje de `/etc/localtime` a quien lea el fichero.

<b>2. Validar y recrear solo Cowrie.</b> El `--force-recreate` obliga a construir el contenedor de cero para que relea toda la configuración; un `up -d` a secas puede decidir que nada "esencial" ha cambiado y no recrear nada:

```bash
cd /opt/dirtyland && sudo docker compose config >/dev/null && echo "compose OK"
sudo docker compose up -d cowrie --force-recreate
```

<b>3. Comprobar que ha entrado todo.</b> Primero el recuento de montajes desde el host, y después que los parches se ven <b>desde dentro</b> del contenedor, que es la única forma de descartar el fallo silencioso del montaje mal escrito.

Deben salir <b>70</b> montajes de `cmdpatch` y <b>17</b> del resto:

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -c cmdpatch
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -v cmdpatch | grep -c .
```

Esos 17 son los 16 que declaramos nosotros (el volumen `cowrie-var`, `/etc/localtime`, `cowrie.cfg`, `userdb.txt`, `fs.pickle`, el `honeyfs`, las `keys/`, los `txtcmds/`, el `ps_command_output.json`, el `dpkg-packages.tsv` de `fs/`, el `ayudas-comandos.json`, los tres de Telegram, la carpeta `geoip/` de las banderas y el `protocol.py` parcheado del apartado anterior) <br><b>más un volumen anónimo</b> que no hemos puesto: `/var/lib/docker/volumes/0b698ec4d374d6d9...881a/_data`

Ese nombre en hexadecimal es un <b>volumen anónimo</b>: lo crea Docker porque la imagen de Cowrie declara un `VOLUME` que nuestro compose no mapea. Es normal y no hay que borrarlo. Los que declaramos nosotros llevan el prefijo del proyecto (`dirtyland_cowrie-var`). Para ver qué ruta ocupa dentro y qué declara la imagen:

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{printf "%s  ->  %s  (%s)\n" .Source .Destination .Type}}{{end}}' | grep -v cmdpatch
sudo docker image inspect cowrie/cowrie:3.0.10 -f '{{json .Config.Volumes}}'
```

El `grep -c .` del segundo comando no es un adorno: `println` deja una línea en blanco al final y un `grep -vc` la contaría como un montaje más. Si los números no cuadran, mejor mirar la lista que adivinar:

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -v cmdpatch | grep . | sort
```

Si aparece algo inesperado, por ejemplo rutas de `cowrie/output/` del montaje antiguo de `netstat.py` y `free.py`, es que han quedado líneas viejas en el compose: ahora esos dos ficheros vienen de `cmdpatch`, así que hay que borrarlas o el mismo comando estaría montado dos veces.

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from pathlib import Path
base = Path('/cowrie/cowrie-git/src/cowrie')
print('netstat parcheado (systemd):', '/run/systemd/private' in (base/'commands/netstat.py').read_text())
print('honeypot parcheado (RANDOM):', 'RANDOM' in (base/'shell/honeypot.py').read_text())
print('shasum registrado en __init__:', 'shasum' in (base/'commands/__init__.py').read_text())
"
```

Las tres respuestas deben ser `True`. La última es la que confirma que `__init__.py` está montado y que, por tanto, los comandos nuevos se cargan.

```bash
sudo docker logs dirtyland_cowrie 2>&1 | grep -aE 'output engine|\[telegram\]' | tail -5
```

Deben salir dos motores de salida (`jsonlog` y `telegram`) <b>y además</b> una línea `[telegram] tokens cargados de /opt/dirtyland/Telegram Reports/telegram.cfg`.

Esa segunda línea es la que importa: la escribe <b>nuestro</b> plugin al arrancar. Si aparece `Loaded output engine: telegram` pero no hay ninguna línea `[telegram]`, lo que se ha cargado es el plugin de fábrica y el nuestro está inerte.

> [!WARNING]
> Cowrie lee su configuración <b>únicamente al arrancar</b>, así que un cambio en el `cowrie.cfg` o en un fichero montado no surte efecto hasta recrear el contenedor. Si en algún momento se edita solo el `cowrie.cfg` sin tocar el compose, basta un `sudo docker restart dirtyland_cowrie` para que lo relea.

Si las alertas no llegan, podemos comprobar que Cowrie está leyendo realmente la sección de Telegram de nuestro fichero de configuración:

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from cowrie.core.config import CowrieConfig as c
print('enabled:', c.get('output_telegram','enabled', fallback='NO EXISTE'))
"
```

#### 3.4.2.10 El `cowrie.cfg` definitivo.

Durante los apartados anteriores hubo que abrir este fichero varias veces. Para tener orden y claridad, aquí está la versión final y completa, que es la que debe quedar.

<b>Antes del fichero, las claves de host.</b> Cowrie, si no se le dan, se las fabrica él con `RSA_KEY_SIZE = 2048` escrito en su código. Un Debian 13 con OpenSSH 10 tiene la RSA de **3072 bits**, que es el valor por defecto de `ssh-keygen` desde OpenSSH 8.0. Es una diferencia que se ve **sin entrar y sin autenticarse**, con un escaneo desde fuera:

<pre>
nmap -p22 -sV -A [IP VPS]
</pre>

> [!CAUTION]
> <b>Ese `nmap` NO se ejecuta aquí: aquí no funcionaría.</b> Va en `<pre>` y no en un bloque de copiar por ese motivo. La máquina está <b>sellada</b> durante todo el apartado 3.4 y no se expone hasta el <b>3.8.2</b>, así que un escaneo desde fuera contesta ahora mismo:
>
> <pre>
> 22/tcp filtered ssh
> </pre>
>
> Y eso es lo **correcto** en este punto, no un fallo. Se enseña porque explica <b>por qué</b> hacen falta las claves de host que se generan debajo.

<pre>
| ssh-hostkey:
|   2048 ab:92:6a:... (RSA)      <-- Cowrie
|   3072 ...                     <-- lo que tendria un Debian 13 de verdad
</pre>

Así que no se las inventa Cowrie: las genera `ssh-keygen`, el mismo programa que las crea en cualquier Debian. Es el criterio de siempre, lo de serie se copia y no se inventa, aplicado a lo primero que ve un escáner:

```bash
sudo ssh-keygen -q -t rsa     -f /opt/dirtyland/cowrie/keys/ssh_host_rsa_key     -N "" -C ""
sudo ssh-keygen -q -t ecdsa   -f /opt/dirtyland/cowrie/keys/ssh_host_ecdsa_key   -N "" -C ""
sudo ssh-keygen -q -t ed25519 -f /opt/dirtyland/cowrie/keys/ssh_host_ed25519_key -N "" -C ""
```

El `-C ""` es higiene de ficheros <br>.
`ssh-keygen` pone por defecto un comentario `usuario@maquina` con el <b>hostname real de la VPS</b>, y queda escrito en el `.pub` y dentro de la clave privada. <br>
Un nmap no lo ve, por red, porque el protocolo manda la clave y no la etiqueta, pero estos ficheros **salen de la máquina** en el respaldo del 3.7.11. Tampoco se generan con `ssh-keygen -A`, porque esa opción escribe siempre en el `/etc/ssh` del anfitrión, que es donde viven las claves <b>reales</b> del servidor: las tres órdenes de arriba hacen lo mismo en el directorio del señuelo.

Cowrie las lee desde dentro del contenedor, así que tienen que pertenecerle. El uid se pregunta, no se supone, igual que en el buzón de Telegram del apartado 3.4.2.7:

```bash
CU=$(sudo ps -o uid= -p $(sudo docker inspect -f '{{.State.Pid}}' dirtyland_cowrie) | tr -d ' ') && sudo chown "$CU:$CU" /opt/dirtyland/cowrie/keys/* && sudo chmod 600 /opt/dirtyland/cowrie/keys/*_key && sudo chmod 644 /opt/dirtyland/cowrie/keys/*.pub && ls -ln /opt/dirtyland/cowrie/keys
```

Si las claves privadas no son suyas, Cowrie arranca **sin SSH** y lo dice con un `PermissionError: [Errno 13]` sobre `ssh_host_rsa_key` en el log; el telnet, en cambio, sigue funcionando, así que el señuelo parece medio vivo.

Se vacía primero, para no acabar mezclando lo nuevo con lo que fuera quedando de las ediciones anteriores:

```bash
sudo truncate -s 0 /opt/dirtyland/cowrie/etc/cowrie.cfg
```

Y se abre para pegar dentro el contenido:

```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```

```ini
[honeypot]
hostname = pc-dev-003-ignis
contents_path = /opt/honeyfs
txtcmds_path = /opt/txtcmds
idle_timeout = 3000
interactive_timeout = 7200
internet_facing_ip = [IP VPS]

[ssh]
version = SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
rsa_public_key = /opt/cowrie-keys/ssh_host_rsa_key.pub
rsa_private_key = /opt/cowrie-keys/ssh_host_rsa_key
ecdsa_public_key = /opt/cowrie-keys/ssh_host_ecdsa_key.pub
ecdsa_private_key = /opt/cowrie-keys/ssh_host_ecdsa_key
ed25519_public_key = /opt/cowrie-keys/ssh_host_ed25519_key.pub
ed25519_private_key = /opt/cowrie-keys/ssh_host_ed25519_key

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[shell]
filesystem = /cowrie/cowrie-git/src/cowrie/data/custom-fs.pickle
processes = /opt/ps_command_output.json
kernel_version = 6.12.74+deb13+1-amd64
kernel_build_string = #1 SMP PREEMPT_DYNAMIC Debian 6.12.74-2 (2026-03-08)
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026

[output_telegram]
enabled = true
```

Clave por clave:

- `contents_path` y `filesystem` son las dos mitades del sistema de ficheros falso: el primero apunta al **contenido** (honeyfs) y el segundo a los **metadatos** (pickle).
- `txtcmds_path` es la carpeta de salidas enlatadas del apartado 3.4.2.8. Es una ruta de **anulación**: Cowrie mira aquí primero y, si el comando no está, sirve la suya. Por eso solo hay que poner los que se quieren cambiar (`dmesg`, `stty` y `sync`) y no hay riesgo de tapar el resto, al contrario de lo que pasa con `commands/`.
- `processes` es de dónde sale la salida de `ps` (el `ps_command_output.json` del apartado 3.4.2.8). <b>Va en `[shell]`, no en `[honeypot]`</b>: Cowrie la lee con `CowrieConfig.get("shell", "processes", fallback=None)`, y en la sección equivocada la lectura devuelve `None` sin un solo error, con lo que el señuelo enseña los procesos de fábrica, que son de otra máquina.
- `[ssh] version` es el banner que anuncia el servicio, y es **la clave que lee nmap**. El valor **se copia de un Debian 13 real, no se deduce**, porque el numero del banner y el del paquete no coinciden: el paquete es `1:10.0p1-7+deb13u4` (p1) y el banner dice `10.0p2` (p2), porque Debian aplica los parches de p2 sin subir la versión del paquete. Se saca levantando el sshd de serie en un contenedor `debian:13` y leyendo la primera línea que escupe:

  ```bash
  sudo docker run --rm --network host debian:13 bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server >/dev/null && mkdir -p /run/sshd && ssh-keygen -A >/dev/null 2>&1 && /usr/sbin/sshd -p 2299 -o PidFile=/tmp/p && sleep 2 && exec 3<>/dev/tcp/127.0.0.1/2299 && head -1 <&3'
  ```

  <pre>
  SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
  </pre>

  El `--network host` es por lo mismo que en el apartado 3.4.2.3: en la VPS, el tráfico de `apt` por la red por defecto de Docker cae en la `policy drop` del cortafuegos.

Que esta clave esté puesta importa: con solo `[shell] ssh_version`, `nmap -sV` seguía reportando `OpenSSH 9.2p1 Debian 12`, el valor por defecto de la imagen, mientras el resto del señuelo decía trixie.
- **Los avisos de Telegram cubren el telnet sin configurar nada, y dicen por dónde entraron.** Cowrie marca `protocol` en **todos** los eventos de una sesión (lo fija `EventLog` al crearla), así que el plugin no tiene que deducirlo del puerto ni del tipo de evento. Los criterios son **los mismos** que ya tenía el SSH: solo avisan `login.success`, `file_download` y `file_upload`, y se agrupan los comandos. Abrir el 23 no sube el volumen de notificaciones por sí mismo, solo añade su origen.

  La primera línea del aviso lo dice, que es lo único que se lee en la notificación del móvil sin abrirla:

  <pre>
  [Cowrie vía Telnet]

  Event: cowrie.login.success
  </pre>

**Ahí iba el `sensor` de Cowrie, y se quitó.** La cabecera era `[Cowrie 9ee5ca58e312] via Telnet`. Ese identificador es el campo `sensor`, que por defecto es el <b>hostname del contenedor</b>, o sea su id de Docker, así que <b>cambia en cada `--force-recreate`</b>. Y como solo hay un señuelo, tampoco distinguía entre nada.

  El resumen es **uno solo para los dos protocolos**: no hay uno de SSH y otro de telnet. El reparto de sesiones va en su primera línea:

  <pre>
  [Cowrie] Resumen --- ultimos 30 min
  Sesiones: Telnet: 91, SSH: 34
  Avisos callados: 6 (127 eventos)
  </pre>

  Ese reparto se cuenta **antes** de los filtros, sobre `cowrie.session.connect`: si se contara después solo reflejaría lo que ya se ha avisado, y el resumen es justo el único sitio donde se ve el tráfico que no genera aviso.

  Las dos primeras líneas dicen cosas que antes no decían, y las dos por el mismo motivo (el resumen afirmaba más de lo que sabía):

  **La ventana va escrita.** Si en media hora no hay nada que callar, no se manda resumen; pero los contadores siguen corriendo, así que las sesiones de ese rato salen en el siguiente. Antes eso no se decía y se leían como de su media hora: 40 sesiones tranquilas aparecían sumadas a las 3 del intervalo bueno. No se arregla tirándolas (se perderían), se arregla diciendo el periodo de verdad, que es el tiempo desde el último resumen **enviado**.

  **Un aviso callado es uno, tenga los comandos que tenga.** Decía `Eventos silenciados: 127`, y 127 eran los comandos de las sesiones que no se avisaron, no los avisos. Una sola sesión callada de 300 comandos se leía como 300 mensajes escondidos. Ahora se dicen las dos cosas, y el número grande va entre paréntesis, que es donde le corresponde.

- **`[telnet]` está activo**, y llegar aquí costó arreglar tres cosas que se sostienen entre sí. Quedan escritas porque ninguna de las tres da un error que se entienda solo.

  **1. El fallo que tumbaba todas las sesiones.** Cowrie pide `DO TERMINAL-TYPE` al conectar, y su propio `enableRemote` devolvía `False` para esa opción. Twisted, en la rama que se ejecuta cuando el cliente acepta algo que hemos pedido *nosotros*, lleva una aserción literal:

  <pre>
  def will_no_true(self, state, option):
      # Peer agreed to enable an option in response to our request.
      ...
      assert self.enableRemote(
          option
      ), "enableRemote must return True in this context (for option {!r})"
  </pre>

  O sea: pedimos una opción y, cuando nos la concedían, la rechazábamos. La excepción corta la conexión a los 16 ms, y como cualquier cliente de telnet ofrece TERMINAL-TYPE, **se caían todas**. La causa de fondo es la de siempre aquí: la lista de opciones estaba escrita **dos veces** ---una en `connectionMade`, otra en `enableRemote`--- y habían dejado de coincidir. Ahora hay una sola, `OPCIONES_SOLICITADAS`, y los dos sitios la usan.

  **2. El banner sale del honeyfs, no de la configuración.** Cowrie hace `read_honeyfs_bytes("etc/issue.net")`; si falta, escribe `ERROR: Failed to load /etc/issue.net` y usa un banner **vacío**. Un telnet de Debian real imprime esa línea antes del `login:`, así que un banner vacío delata. El honeyfs solo tenía `/home`, de modo que `build-dirtyland-fs.sh` exporta ahora también `issue`, `issue.net` e `inetd.conf` **desde el mismo contenedor que genera el pickle**: así el listado y el contenido salen de la misma foto y no pueden discrepar.

  **3. Coherencia del señuelo.** Una máquina que contesta en el 23 tiene que parecer una que sirve telnet. Se añaden `openbsd-inetd` e `inetutils-telnetd` a los paquetes del generador (en Debian 13 `telnetd` a secas es solo un envoltorio de transición) y `/usr/sbin/inetd` al `ps_command_output.json`. Sin eso, quien entrase por el 23 vería un `ps aux` que no explica cómo ha entrado.

**4. El puerto tiene que llegar, y no llegaba.** Lo de arriba es el contenido del señuelo, y nada de eso se ve desde fuera si el paquete no entra. Hacen falta <b>dos</b> piezas más, en dos ficheros distintos, y faltaban las dos: el `docker-compose` tiene que publicar el 23 del contenedor, y el cortafuegos tiene que dejarlo pasar hasta ahí.

  Las cinco piezas (la sección `[telnet]`, la negociación, el banner, la coherencia del disco y la exposición) tienen que estar de acuerdo. Las tres primeras se comprueban desde dentro; la última **solo** se comprueba desde fuera, con el `nc` del apartado 3.8.2.
- `idle_timeout = 3000` (50 minutos) cierra sesiones **inactivas**. Lo lee el shell y el telnet; la ruta SSH no.
- `interactive_timeout = 7200` es el tope **absoluto** de la sesión SSH, y no se reinicia al teclear. Su valor por defecto son 300 segundos: sin esta línea, toda sesión SSH cae a los 5 minutos exactos, activa o no, y sin mensaje. Los dos límites evitan que las sesiones abandonadas por los bots compitan contra el `pids_limit` y la memoria del contenedor.
- `internet_facing_ip` hace que Cowrie use la IP pública del señuelo en lugar de la interna del contenedor (`172.20.0.10`), que sería un dato incoherente para quien está dentro. **Hay que sustituir el `[IP VPS]`**: Cowrie copia el valor tal cual a `SSH_CONNECTION`, y el corchete ---más el espacio, que deja la variable en cinco campos en vez de cuatro--- se ve en el primer `env`.
- `[output_telegram]` es lo que activa el motor de alertas del apartado 3.4.2.7. El nombre está impuesto por el cargador de Cowrie, que se queda con el primer trozo del nombre de la sección; por eso el plugin se monta sobre `telegram.py`. Los tokens no van aquí, sino en el `telegram.cfg`.

Siendo, gracias al `docker-compose`, cada ruta del contenedor pareja de una del anfitrión:

| Dentro del contenedor | En el anfitrión | Qué es |
|---|---|---|
| `/opt/honeyfs` | `/opt/dirtyland/cowrie/honeyfs` | el contenido de los ficheros |
| `/cowrie/cowrie-git/src/cowrie/data/custom-fs.pickle` | `/opt/dirtyland/cowrie/fs/fs.pickle` | los metadatos del disco falso |
| `/opt/ps_command_output.json` | `/opt/dirtyland/cowrie/etc/ps_command_output.json` | la salida de `ps` |
| `/opt/dpkg-packages.tsv` | `/opt/dirtyland/cowrie/fs/dpkg-packages.tsv` | la lista de `dpkg -l` (3.4.2.3) |
| `/opt/txtcmds` | `/opt/dirtyland/cowrie/txtcmds` | las salidas enlatadas que sustituimos (3.4.2.8) |
| `/opt/cowrie-keys` | `/opt/dirtyland/cowrie/keys` | las claves de host SSH |
| `/cowrie/cowrie-git/src/cowrie/commands/` | `/opt/dirtyland/cowrie/cmdpatch/` | los módulos de comandos |

Como se ha editado solo el `cowrie.cfg`, en principio basta con que Cowrie lo relea:

```bash
sudo docker restart dirtyland_cowrie
```

Y acto seguido <b>comprobamos que el contenedor ve de verdad la versión nueva</b>, que no es paranoia:

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from cowrie.core.config import CowrieConfig as c
print('hostname:', c.get('honeypot','hostname'))
print('telegram:', c.get('output_telegram','enabled', fallback='NO EXISTE'))"
```

> [!WARNING]
> Si ahí sale un valor viejo (o `NO EXISTE` pese a haber escrito la sección), el `restart` no basta y hay que recrear:
>
> ```bash
> sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d cowrie --force-recreate
> ```
>
> El motivo es que Docker ata el bind-mount de un fichero suelto al <b>inodo</b>, no a la ruta. Si el editor modifica el fichero en su sitio, el contenedor ve el cambio, pero varios editores, `nano` entre ellos según la versión, escriben un temporal y lo renombran encima, y eso crea un inodo nuevo que el contenedor ya no sigue. Se comprueba comparando los dos:
>
> ```bash
> stat -c %i /opt/dirtyland/cowrie/etc/cowrie.cfg
> sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "import os; print(os.stat('/cowrie/cowrie-git/etc/cowrie.cfg').st_ino)"
> ```
>
> Se usa Python porque la imagen de Cowrie no trae `stat`. Afecta a todos los ficheros sueltos que montamos; a los montajes de directorio (`honeyfs`, `txtcmds`, `keys`) no les pasa.

#### 3.4.2.11 Verificación interna del señuelo (sin exponer).

Lo primero es lo que se ve **antes de entrar**, que es lo que mira un escáner. El banner y las claves de host:

```bash
ssh-keyscan -p 2222 -T 10 172.20.0.10 2>/dev/null | ssh-keygen -lf -
```

<pre>
3072 SHA256:... [172.20.0.10]:2222 (RSA)
256 SHA256:... [172.20.0.10]:2222 (ECDSA)
256 SHA256:... [172.20.0.10]:2222 (ED25519)
</pre>

**La RSA tiene que decir 3072.** Si dice `2048`, Cowrie se ha fabricado las suyas: o las claves del apartado 3.4.2.10 no están, o no le pertenecen (mira el log buscando `PermissionError`), o el `[ssh]` del `cowrie.cfg` no las apunta. Las otras dos son 256 por definición, igual que en un Debian real.

Y que el banner sea el que anunciamos, que es lo que lee `nmap -sV`:

```bash
timeout 5 bash -c 'exec 3<>/dev/tcp/172.20.0.10/2222; head -1 <&3'
```

<pre>
SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
</pre>

Tiene que salir **el sufijo entero**, `Debian-7+deb13u4`, no `Debian-7` a secas. Ese `-7` es la revisión del paquete de Debian, no la versión de la distribución, pero recortado deja a `nmap -sV` diciendo `OpenSSH 10.0p2 Debian 7`, que se lee como un Debian 7 de 2013 sirviendo un OpenSSH de 2026. Y sobre todo **contradice al `[shell] ssh_version` de la propia configuración**, que sí lleva el sufijo: fuera una cosa y dentro otra.

Después, el shell falso, conectándonos directamente al contenedor por su IP interna:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alyosha@172.20.0.10
```

<b>1. Identidad y contenido.</b>

```bash
whoami
hostname
ls -la /home
cat /etc/debian_version
uname -a
cat ~/.bashrc
```

<b>2. Que ningún comando delate el entorno real.</b> Todos deben contar la misma historia (Debian 13, i5-12400, 16 GB, sin rastro de Docker ni de la VPS):

```bash
cat /etc/os-release
free -h
dpkg -l | wc -l
dpkg -l | grep -E ' (openssh-server|nano|inetutils-telnetd) '
cat /proc/version
cat /proc/cpuinfo
groups alyosha
ps aux
netstat -tulpn
```

Concretamente: `cat /etc/os-release` ya devuelve contenido (antes salía vacío); `free -h` dice 16 GB y no los 2 GB reales; `dpkg -l` lista **cientos** de paquetes con las versiones reales de Debian 13 (y en particular su `openssh-server` tiene que ser el mismo `1:10.0p1-7+deb13u4` del que sale el banner del apartado anterior, y aparecer `inetutils-telnetd`, que es lo que explica el puerto 23); `cat /proc/version` coincide con `uname -a` y ya no lleva el sufijo `-cloud`; `cat /proc/cpuinfo` muestra el Intel Core i5-12400 sin el flag `hypervisor`; `groups alyosha` incluye el grupo `sudo`; `ps aux` muestra los procesos de la leyenda (systemd, pm2, node ignis-api) y ninguno ajeno; y `netstat` ya no menciona el `upstart` de Ubuntu.

> [!WARNING]
> El `ps aux` merece mirarse con calma, porque su fallo no da error. Si ahí aparecen <b>`mysql`, `ejabberd`, `www-data`, `Debian-exim`</b> o `iprt-VBoxWQueue`, Cowrie está usando su fichero de fábrica en vez del nuestro, y la causa casi siempre es la misma: la clave `processes` puesta en `[honeypot]` en lugar de en `[shell]`. Cowrie no avisa de una clave que no encuentra, simplemente carga su valor por defecto y el señuelo enseña los procesos de otra máquina. Ese `iprt-VBoxWQueue` es, además, un delator inmediato: anuncia VirtualBox.

<b>3. Que los homes ajenos son privados.</b> Conectados como `alyosha`, no debemos poder mirar dentro de otro usuario. Las cuatro órdenes tienen que responder "Permission denied" (si en vez de eso listan contenido, el problema no está en los módulos sino en el pickle: los homes habrán quedado en `0755`, ver 3.4.2.4):

```bash
ls /home/admin/
cd /home/admin/
cat /home/admin/.bash_history
find /home/admin -name '*.env'
```

<b>4. Que la escalada funciona.</b> `su` debe pedir contraseña, fallar con una incorrecta y **cambiar de identidad** con la correcta; al salir, volvemos a ser quienes éramos:

```bash
su root            # contraseña incorrecta -> "su: Authentication failure"
su root            # con la del userdb -> el prompt pasa a "#"
whoami
ls /home/admin/    # como root, ahora sí se ve
exit
whoami             # volvemos a alyosha
sudo -l            # responde como un no-sudoers
```

<b>5. Que la shell se comporta como bash.</b> Estos son los detalles que un bot usa para tantear si hay un emulador detrás:

```bash
echo $RANDOM       # un entero distinto cada vez (0..32767)
echo $RANDOM
sha256sum /etc/hostname
echo hola | cat
echo a && echo b   # salen las dos
false && echo b    # no sale nada
false || echo b    # sale b
noexiste && echo b # "command not found" y b NO se ejecuta
echo $?            # 127
while IFS= read -r line     # queda a medias: aparece el prompt ">" (Ctrl-C para salir)
cd /proc/; cat self/cmdline # "catself/cmdline", pegado al prompt y sin salto de línea
```

<b>Además, todo esto ya nos debería de notificar al Telegram.</b>

El sistema de ficheros, los comandos y las alertas de Cowrie quedan terminados y verificados por dentro. El honeypot sigue <b>sin exponer</b> a Internet.

### 3.4.3 Personalización de Dionaea como máquina Windows.

Dionaea emula servicios de Windows (SMB, RPC, MSSQL) y vive en su propia IP, separada de la de Cowrie, porque exponer servicios Windows y un SSH de Debian en la misma dirección es una incoherencia detectable que quema antes la reputación de la IP. En este apartado le damos una identidad Windows creíble: reducimos sus servicios a los coherentes y personalizamos el banner SMB.

#### 3.4.3.1 Reducción de servicios de Dionaea.

<b>¿Por qué apagar servicios en vez de dejarlos todos?</b> Más puertos captan más ataques, pero un Windows real no expone SIP, MQTT, MongoDB ni WireGuard a la vez. Cada puerto incoherente acelera que un escáner nos catalogue como señuelo y queme la IP.

Dionaea trae diecisiete servicios por defecto. Para dar coherencia a una máquina Windows con pocos servicios, dejamos solo los que un Windows real expondría: SMB (445), RPC/epmap (135) y MSSQL (1433), más NetBIOS (`nbns`), que acompaña siempre a SMB en una máquina Windows.

El directorio ya existe (se creó con el árbol del apartado 3.4). Solo hay que poblarlo, copiando los ficheros reales desde el contenedor que ya está en marcha:

```bash
for s in epmap mssql nbns; do sudo docker cp "dirtyland_dionaea:/opt/dionaea/etc/dionaea/services-available/$s.yaml" "/opt/dirtyland/dionaea/services-enabled/$s.yaml"; done
```

```bash
ls -la /opt/dirtyland/dionaea/services-enabled/
```

> [!IMPORTANT]
> Se copia del contenedor <b>en marcha</b>, y no de uno creado al vuelo con `docker create`, porque en la imagen esos ficheros <b>no existen</b>: los genera el `entrypoint` al arrancar, que es la peculiaridad del apartado 3.4.3.3. Con `docker create` el contenedor nunca arranca, así que el `docker cp` responde `Could not find the file ... in container`.
>
> Son <b>tres</b> ficheros y falta el cuarto: el `smb.yaml` <b>no se copia</b>, se escribe a mano en el apartado siguiente, porque es el que lleva la identidad Windows. Y `nbns` se queda aunque su puerto no se publique: una máquina Windows que habla SMB también habla NetBIOS, y tenerlo configurado mantiene la coherencia sin abrir nada.
>

#### 3.4.3.2 Banner SMB personalizado (Windows 7 SP1).

El `path` va entre comillas simples y con <b>una sola</b> barra invertida. En un escalar YAML sin comillas no existen los escapes, así que se acabarían anunciando dos barras, y eso lo ve cualquiera que enumere los recursos compartidos.

<b>¿Por qué Windows 7 SP1?</b> Es el sistema que más malware automatizado sigue atrayendo por SMB (EternalBlue y derivados), y el nombre autogenerado (`WIN-` más caracteres aleatorios) con el workgroup por defecto encaja con una caja de datacenter sin relación con nadie.

El `smb.yaml` **viene con el repositorio**, en la carpeta `DIONAEA`, así que se copia como todo lo demás y no se teclea:

```bash
sudo cp "/tmp/dirtyland-repo/DIONAEA/smb.yaml" /opt/dirtyland/dionaea/services-enabled/smb.yaml
sudo chown root:root /opt/dirtyland/dionaea/services-enabled/smb.yaml
sudo chmod 644 /opt/dirtyland/dionaea/services-enabled/smb.yaml
```

Su contenido, para saber qué anuncia:

<pre>
- name: smb
  config:
    os_type: 4
    os_arch: 64
    primary_domain: WORKGROUP
    oem_domain_name: WORKGROUP
    server_name: WIN-K7M9XQ2P4RS
    native_os: Windows 7 Professional 7601 Service Pack 1
    native_lan_manager: Windows 7 Professional 6.1
    shares:
      IPC$:
        comment: Remote IPC
        type: ipc
      ADMIN$:
        comment: Remote Admin
        path: 'C:\Windows'
        type: disktree
</pre>

Este es el único de los cuatro que llevamos nosotros; los otros tres son los de serie de Dionaea y por eso se copiaron del contenedor. Mismo criterio que con el `issue.net` de Cowrie: lo de serie se copia de donde sale, lo de la leyenda lo traemos del repositorio.

#### 3.4.3.3 Por qué el bloque de Dionaea ya está listo.

**Aquí no hay nada que editar.** El servicio `dionaea` del `docker-compose` vino ya completo con la parte 1 del repositorio (apartado 3.4): sus puertos atados a `[IP VPS 2]`, la variable `DIONAEA_FORCE_INIT_CONF=1` y el montaje de `services-enabled` en **solo lectura**. Este apartado existe para explicar esas dos últimas, porque ninguna se adivina y las dos dan síntomas que no apuntan a su causa.

Se comprueba que están donde deben (en YAML una indentación mal puesta equivale a no haber escrito nada, y el compose no se queja):

```bash
cd /opt/dirtyland && sudo docker compose config --format json | python3 -c "import json,sys; d=json.load(sys.stdin)['services']['dionaea']; print('environment:', d.get('environment')); print('volumes:'); [print('  ', v['source'], '->', v['target'], '(ro)' if v.get('read_only') else '') for v in d['volumes']]"
```

<pre>
environment: {'DIONAEA_FORCE_INIT_CONF': '1'}
volumes:
   dionaea-var -> /opt/dionaea/var 
   /opt/dirtyland/dionaea/services-enabled -> /opt/dionaea/etc/dionaea/services-enabled (ro)
</pre>

> [!NOTE]
> <b>`DIONAEA_FORCE_INIT_CONF=1` no es opcional</b>, y el motivo no se adivina. La imagen no trae la configuración hecha: la guarda en `/opt/dionaea/template/etc` y su `entrypoint.sh` la copia al arrancar, pero solo si el directorio de destino no existe:
>
> ```sh
> test ! -d /opt/dionaea/etc/dionaea && init_etc
> ```
>
> Y aquí está la trampa: al montar nuestro `services-enabled` <b>dentro</b> de esa ruta, Docker crea los directorios padre, así que ya existe antes de que el entrypoint mire. La condición falla y Dionaea arranca sin `dionaea.cfg`; la variable fuerza la copia. El síntoma, si falta, desconcierta: bucle de reinicio repitiendo `Could not read config file`, que no apunta a la causa.
>

> [!NOTE]
> <b>El montaje va en solo lectura (`:ro`), y eso sostiene la reducción de servicios.</b> En <b>cada</b> arranque el entrypoint vuelve a enlazar los diecisiete servicios dentro de `services-enabled`. El `:ro` se lo impide, así que nuestros cuatro ficheros mandan siempre. En el log se ve, y es la señal de que funciona:
>
> ```bash
> cp: cannot create symbolic link './etc/dionaea/services-enabled/mysql.yaml': Read-only file system
> ```
>
> Sin el `:ro`, Dionaea volvería a levantar SIP, MQTT, MongoDB y compañía en el primer reinicio, deshaciendo el apartado 3.4.3.1 sin que nadie se enterara.

El montaje está puesto <b>desde el primer arranque</b>, con el directorio aún vacío, y Dionaea arranca igual: el entrypoint puebla `services-available`, que no está montado, y de ahí salen los tres ficheros de serie que copiamos antes. Por eso este apartado no toca el `docker-compose`.

Como el compose no cambia, basta con recrear Dionaea para que recoja los servicios nuevos:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d dionaea --force-recreate
```

#### 3.4.3.4 Qué captura cada puerto, y por qué.

Medido sobre la base de Dionaea tras tres meses. Los tres puertos están abiertos y con DNAT, así que la diferencia es del propio Dionaea:

| Puerto | Conexiones | Binarios | Qué deja |
|---|---|---|---|
| 445 (SMB) | 15.339 | **160** | Es el único módulo que implementa lo bastante del protocolo como para aceptar la escritura de un fichero |
| 1433 (MSSQL) | 287 | 0 | 93 comandos SQL. No hay motor detrás, así que `xp_cmdshell` nunca llega a ejecutar la descarga |
| 135 (RPC) | 135 | 0 | 25 binds y 16 peticiones, todas reconocimiento. Ni un intento de explotación |

Que los dos últimos no den binarios no es un fallo: dan inteligencia. En el 1433 se ve a unos atacantes borrando la persistencia de otros, y toda conexión se denuncia igual, como fuerza bruta y escaneo.

> [!CAUTION]
> Si consultas la base a mano, `mssql_command_cmd` es un **BLOB**: un `LIKE` contra él no casa nunca y devuelve vacío **en silencio**. Hay que envolverlo en `CAST(... AS TEXT)`. El colector ya lo hace.

#### 3.4.3.5 Verificación de Dionaea (sin exponer).

Comprobamos que los tres puertos están publicados y atados a la IP nueva:

```bash
sudo docker port dirtyland_dionaea
sudo nft list chain ip nat DOCKER | grep -E '[IP VPS 2]'
```

Tiene que verse así:

<pre>
135/tcp -> [IP VPS 2]:135
445/tcp -> [IP VPS 2]:445
1433/tcp -> [IP VPS 2]:1433
# Warning: table ip nat is managed by iptables-nft, do not touch!
		ip daddr [IP VPS 2] tcp dport 135 counter packets 0 bytes 0 dnat to 172.20.0.20:135
		ip daddr [IP VPS 2] tcp dport 445 counter packets 0 bytes 0 dnat to 172.20.0.20:445
		ip daddr [IP VPS 2] tcp dport 1433 counter packets 0 bytes 0 dnat to 172.20.0.20:1433
</pre>

Los tres puertos publicados, cada uno atado a la IP de Dionaea, y una regla `dnat` por puerto apuntando a `172.20.0.20`. Lo que <b>no</b> debe aparecer es ninguna regla con la IP de Cowrie: si sale, los dos señuelos estarían compartiendo IP y el reparto por interfaz que montamos en el compose no estaría surtiendo efecto.

Los contadores a cero son lo normal aquí: nadie ha llegado todavía porque seguimos sellados.

> [!WARNING]
> Aquí <b>no sirve `ss -tlnp`</b>: no aparecerá nada escuchando en esa IP, y eso es lo esperado. Configuramos el daemon de Docker con `"userland-proxy": false`, así que Docker <b>no levanta ningún proceso que ocupe el puerto en el host</b> y la publicación se resuelve enteramente con DNAT en `nftables`.
>
> Con el proxy en su valor por defecto sí verías sockets, pero a cambio de un proceso `docker-proxy` por puerto y, sobre todo, de que el contenedor viera como origen la IP de Docker en lugar de la del atacante. La IP de origen es justo el dato que queremos capturar.

Para verificar el banner necesitamos herramientas de fingerprint, que instalamos en el host:

```bash
sudo apt install -y nmap smbclient
```

Y comprobamos que el banner SMB anuncia la identidad Windows correcta:

```bash
nmap -p 445 --script smb-os-discovery [IP VPS 2]
```

Debe devolver "Windows 7 Professional 7601 Service Pack 1", nombre "WIN-K7M9XQ2P4RS" y workgroup "WORKGROUP".

Y, **lo que no puede salir por ninguno de los tres puertos, es la palabra "honeypot"**:

```bash
nmap -sV --version-intensity 2 -p 135,445,1433 [IP VPS 2]
```

<pre>
135/tcp  open  msrpc?
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s?
</pre>

Los tres **sin identificar** es el resultado bueno. Si el 1433 dice `Dionaea honeypot MS-SQL server`, el parche del apartado 3.4 no está puesto: o el fichero no se montó, o el `sed` no mordió. Y si el 445 dijera `Dionaea honeypot smbd`, sería que el `smb.yaml` del 3.4.3.2 no está surtiendo efecto: esa firma de nmap exige el nombre de máquina de fábrica (`HOMEUSER-` y seis caracteres), así que cambiarlo es justo lo que la esquiva.

Sin identificar no es lo mismo que "parece un Windows". nmap reconoce a un Windows real como `Microsoft Windows RPC` y `Microsoft Windows 7 - 10 microsoft-ds`; aquí devuelve datos que no encajan con ninguna firma suya. Es un escalón mejor que anunciarse como honeypot y uno peor que un Windows de verdad, y es hasta donde llega Dionaea, que es de interacción baja o media: sostiene el fingerprint inicial de SMB, que es lo que ve un escáner automático, pero no implementa una sesión completa, así que un `smbclient -L` falla con `NT_STATUS_CONNECTION_DISCONNECTED`. En la misma línea, `smb-protocols` enseña que solo habla <b>SMBv1</b> (`NT LM 0.12`), cuando un Windows 7 SP1 real ofrece además `2.0.2` y `2.1`: no es configurable, es el motor. Y tiene una contrapartida que conviene no "arreglar", porque lo que llega al 445 son bots que buscan EternalBlue, o sea SMBv1 justamente.

Finalmente, igual que hicimos con la IP de Cowrie, comprobamos <b>desde una máquina externa</b> (no desde la propia VPS) que la IP nueva sigue sellada:

```bash
IP2=[IP VPS 2]; for p in 445 135 1433; do nc -vz -w 3 $IP2 $p; done
```

Y en Windows, que no trae `nc`:

```powershell
$ip2 = '[IP VPS 2]'; foreach ($puerto in 445,135,1433) { $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($ip2,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $ip2, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

¡Nos tiene que dar error! `[(tcp) timed out: Operation now in progress]`, o `cerrado o filtrado` en los tres si lo has hecho desde PowerShell.

> [!IMPORTANT]
> <b>Todo sigue sellado. Dionaea aún no está expuesto a Internet</b>, igual que Cowrie.

### 3.4.4 Monitorización del host real (segundo bot de Telegram).

Esto no vigila el honeypot, vigila el <b>anfitrión</b> que lo sostiene: confirma que la actividad del servidor es la esperada y avisa de cualquier desviación. Va con un segundo bot de Telegram, independiente del de Cowrie.

<b>1. Crear el bot y obtener sus credenciales.</b> Igual que con el de Cowrie, se crea con `@BotFather` y hay que <b>escribirle algo al bot</b> antes de pedir el `chat_id`, o `getUpdates` viene vacío. Reutilizamos el mismo script en base64 del apartado 3.4.2.7, que pide el token y devuelve el chat:

```bash
bash <(echo "cmVhZCAtcCAiRW50ZXIgeW91ciBib3QgdG9rZW46ICIgVE9LRU4KaWYgWyAteiAiJFRPS0VOIiBdOyB0aGVuIGVjaG8gIlRva2VuIGlzIGVtcHR5LiI7IGV4aXQgMTsgZmkKZWNobyAiT2J0YWluaW5nIENoYXQgSUQuLi4iClJFU1BPTlNFPSQoY3VybCAtcyAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRUT0tFTi9nZXRVcGRhdGVzIikKQ0hBVF9JRD0kKGVjaG8gIiRSRVNQT05TRSIgfCBncmVwIC1vRSAnImNoYXQiOlx7ImlkIjotP1swLTldKycgfCB0YWlsIC0xIHwgc2VkICdzLy4qImlkIjovLycpCmlmIFsgLXogIiRDSEFUX0lEIiBdOyB0aGVuCiAgZWNobyAiRXJyb3I6IE5vIGNoYXQgZm91bmQuIFNlbmQgYSBtZXNzYWdlIHRvIHlvdXIgYm90IGZpcnN0LiIKICBleGl0IDEKZmkKZWNobyAiQ2hhdCBJRDogJENIQVRfSUQiCg==" | base64 -d)
```

<b>El `CHAT_ID` es exactamente el mismo que el del primer bot</b>, así que el comando de arriba es opcional y solo sirve para confirmarlo. En una conversación privada el `chat_id` es tu propio identificador de usuario de Telegram, y ese número no cambia según el bot con el que hables.

Lo que sí es distinto es el token, y con él el bot. Que compartan número de chat no mezcla nada, porque la conversación con este bot es otra ventana. Y esa separación es el objetivo: las alertas del señuelo serán constantes en cuanto se exponga y las del anfitrión deben ser rarísimas, así que mezcladas se perderían entre el ruido.

<b>2. Guardar las credenciales.</b> El directorio ya existe, se creó con el árbol del apartado 3.4:

```bash
sudo nano /opt/dirtyland/monitor/telegram.env
```

El token y chat_id del segundo bot:

```bash
BOT_TOKEN="<TOKEN>"
CHAT_ID="<CHAT_ID>"
```

<b>3. Restringir el fichero</b>, que contiene el token:

```bash
sudo chmod 600 /opt/dirtyland/monitor/telegram.env
sudo chown root:root /opt/dirtyland/monitor/telegram.env
ls -l /opt/dirtyland/monitor/telegram.env
```

El resumen diario consulta la base de datos interna de Dionaea, así que necesitamos `sqlite3` en el host:

```bash
sudo apt install -y sqlite3
```

Localizamos dónde guarda Docker el volumen de Dionaea en el host:

```bash
sudo docker volume inspect dirtyland_dionaea-var --format '{{ .Mountpoint }}'
```

Y dentro de ese volumen, la ruta real de la base de datos:

```bash
sudo find /var/lib/docker/volumes/dirtyland_dionaea-var/_data -name '*.sqlite'
```

> [!WARNING]
> El `find` devuelve <b>dos</b> ficheros `.sqlite`. El bueno, donde Dionaea escribe de verdad, es el que está en el subdirectorio `lib/dionaea/`:
> `/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite`
> El otro, en la raíz del volumen, está vacío (es un resto de la inicialización). Esa es la ruta que usa la variable `DIONAEA_DB` dentro del script del resumen diario.

<b>Esta base es lo único que dice si Dionaea sigue vivo</b>, y por eso el resumen diario mira cuándo fue la última conexión que anotó, no solo cuántas hubo hoy. Se quedó una vez en bucle y no registró nada durante cinco días mientras todo lo que se suele mirar decía que estaba perfecto: `docker ps` daba `Up 6 days`, el proceso existía quemando un núcleo y el DNAT seguía contando paquetes por el 445. El resumen escribía "(sin conexiones)", que se lee como "hoy no ha atacado nadie". Ni "¿está levantado?" ni "¿existe el proceso?" sirven, porque las dos cosas eran ciertas mientras el señuelo estaba muerto para lo que sirve. Ahora, si pasan más de <b>6 horas</b> sin una conexión anotada, el resumen lo dice en grande y con la orden de diagnóstico escrita (`docker top dirtyland_dionaea`: si el `TIME` son días, es eso).

Podemos comprobar el esquema de la base para entender qué consulta el script (la tabla que nos interesa es `connections`):

```bash
sudo sqlite3 /var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite ".tables"
```

Esta consulta a la base de Dionaea desde el host es necesaria porque Dionaea, a diferencia de Cowrie, <b>no dispone de plugins de salida hacia servicios de mensajería</b> como Telegram. Su única vía de alerta es que un proceso externo (nuestro script) lea periódicamente sus registros.

Vinieron con el repositorio, así que se copian y se les da permiso de ejecución: la función de envío (`send-alert.sh`), la vigilancia SSH en tiempo real (`ssh-watch.sh`), el resumen diario (`daily-digest.sh`), la vigilancia de Dionaea (`dionaea-watch.sh`), la de los proxys de acceso (`proxy-watch.sh`), el ensayo de todos los avisos (`probar-avisos.sh`), el cortacircuitos (`breaker-watch.sh`), la cuota diaria (`cuota-watch.sh`) y la comprobación de cuentas del resumen (`estado-cuentas.py`).

Los dos últimos avisan por el bot del anfitrión y no por el del señuelo: cuando salta el cortacircuitos, las tres plataformas de abuse.ch dejan de publicar, porque comparten cuenta, y eso no es un ataque sino una avería nuestra, que en el canal del honeypot se perdería entre decenas de avisos al día. Corren cada 5 minutos, no gastan cuota de ninguna API y solo hablan en los cambios de estado.

Los otros dos <b>no se ejecutan</b>, son librerías que los vigilantes cargan con `source`: `lib-ips.sh` es la definición compartida de "qué IPs somos nosotros" y `lib-telegram.sh` la de "cómo se parte un mensaje para que Telegram lo entregue entero". El `chmod +x` las deja fuera a propósito, porque marcar como ejecutable algo sin `shebang` solo invita a intentar lanzarlo.

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/send-alert.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/ssh-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/daily-digest.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/breaker-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/cuota-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-ips.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-paises.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-telegram.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/estado-cuentas.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/DIONAEA/dionaea-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/proxy-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/probar-avisos.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/comandos-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/auditd-watch.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/baneadas-diario.sh" /opt/dirtyland/monitor/
```

```bash
sudo chmod +x /opt/dirtyland/monitor/send-alert.sh /opt/dirtyland/monitor/ssh-watch.sh /opt/dirtyland/monitor/daily-digest.sh /opt/dirtyland/monitor/dionaea-watch.sh /opt/dirtyland/monitor/proxy-watch.sh /opt/dirtyland/monitor/probar-avisos.sh /opt/dirtyland/monitor/breaker-watch.sh /opt/dirtyland/monitor/cuota-watch.sh /opt/dirtyland/monitor/comandos-watch.sh /opt/dirtyland/monitor/estado-cuentas.py /opt/dirtyland/monitor/auditd-watch.py /opt/dirtyland/monitor/baneadas-diario.sh
```

<b>`proxy-watch.sh` vigila los relays SOCKS de acceso a la VPS.</b> Cada 30 minutos le pregunta a la API pública de Mullvad si tus tres proxys siguen `active`, y avisa por el bot del anfitrión cuando uno cae, vuelve o desaparece de la lista. La VPS no puede probarlos de verdad, porque viven dentro del túnel de Mullvad y no es cliente suyo, pero ese indicador es exactamente lo que se puso en `false` las dos veces que se cayó un relay. Solo habla en los cambios de estado.

Lo que no detecta es un relay que cambie de IP de salida sin darse de baja. Es raro, el síntoma es que no entras, y se comprueba a mano desde tu equipo:

```bash
curl -x socks5h://PROXY:1080 https://am.i.mullvad.net/ip
```

La lista de relays que vigila sale de un fichero, `proxys.conf`, y **tiene que ser la misma** que la de tu `~/.ssh/config`. En vez de escribirla otra vez a mano (que es pedir que un día se queden distintos y el vigilante mire relays que ya no usas), **se saca del propio `config`**.

**Desde tu equipo** (no en la VPS), que es donde está el `config`. En Linux, se leen los relays y se mandan directos a la VPS:

```bash
grep -oE '[a-z0-9]([a-z0-9-]*[a-z0-9])?\.relays\.mullvad\.net' ~/.ssh/config | awk '!seen[$0]++' | ssh dirtyland 'cat > /tmp/proxys.conf'
```

Y en Windows, lo mismo con PowerShell (construye el fichero y lo sube):

```powershell
(Select-String -Path "$env:USERPROFILE\.ssh\config" -Pattern '[a-z0-9]([a-z0-9-]*[a-z0-9])?\.relays\.mullvad\.net' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Select-Object -Unique) -join "`n" | Out-File "$env:TEMP\proxys.conf" -Encoding ascii; scp "$env:TEMP\proxys.conf" dirtyland:/tmp/proxys.conf; Remove-Item "$env:TEMP\proxys.conf"
```

Y **de vuelta en la VPS**, se pone en su sitio y se comprueba que salieron tus tres relays:

```bash
sudo install -o root -g root -m 644 /tmp/proxys.conf /opt/dirtyland/monitor/proxys.conf && rm /tmp/proxys.conf && sudo apt install -y jq && cat /opt/dirtyland/monitor/proxys.conf
```

<b>Por qué se saca del `config` y no se escribe.</b> El aviso "SIN ACCESO" salta cuando caen todos los relays de `proxys.conf`, sean los que sean, pero el vigilante solo conoce los que estén en ese fichero: un relay que uses y que no figure aquí no lo vigila nadie. Generándolo del `config` no pueden divergir.

`jq` es para leer la respuesta de la API de Mullvad sin adivinar. El script trae un plan B de texto por si no está, pero es más frágil ante un cambio de formato: si `jq` está, se usa `jq`.

<b>Y la tabla de países</b>, que es lo que pone la banderita al lado de cada IP. Va en su propia carpeta porque el contenedor de Cowrie la monta entera (apartado 3.4.2.9): el plugin del señuelo también la usa.

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/paises.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/generar-tabla-paises.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/nombres.txt" /opt/dirtyland/geoip/ && sudo chmod 755 /opt/dirtyland/geoip/*.py && sudo chmod 644 /opt/dirtyland/geoip/*.txt
```

Y ahora **se generan las tablas**. Tarda menos de un minuto y descarga unos 45 MB:

```bash
sudo /opt/dirtyland/geoip/generar-tabla-paises.py
```

<pre>
tabla de paises en /opt/dirtyland/geoip:
  registro-v4.txt      150124 tramos
  registro-v6.txt      136067 tramos
  ubicacion-v4.txt     358154 tramos
  ubicacion-v6.txt     348330 tramos
</pre>

<b>Las tablas no viajan en el repositorio, y es a propósito.</b> Son datos derivados: los produce ese mismo guion de fuentes públicas y la máquina los rehace cada quince días por cron. Versionarlos serían 17 MB reescritos enteros en cada regeneración, y es el mismo criterio que con el `fs.pickle` y el `dpkg-packages.tsv`: lo que se genera no se versiona.

<b>Esta copia va después de crear el contenedor (3.4.2.9) y no pasa nada.</b> El plugin carga la tabla la primera vez que tiene que poner una bandera, no al arrancar. Si la cargara al arrancar, en una instalación desde cero encontraría la carpeta vacía y se quedaría sin tabla para siempre, porque un `import` solo ocurre una vez: las alertas saldrían sin bandera y nada lo diría. Hay una comprobación que verifica que siga siendo así.

Se comprueba con dos IP conocidas:

```bash
python3 /opt/dirtyland/geoip/paises.py 8.8.8.8 1.1.1.1 212.174.1.1 130.12.182.131 192.168.1.1
```

<pre>
8.8.8.8 🇺🇸 Estados Unidos
1.1.1.1 🇦🇺 Australia
212.174.1.1 🇹🇷 Turquia
130.12.182.131 🇸🇮 Eslovenia (bloque de 🇺🇸 Estados Unidos)
192.168.1.1
</pre>

La última no lleva nada y es lo correcto: una IP privada no es de ningún país, y además suele ser nuestra.

Son dos fuentes porque son dos preguntas distintas. La <b>ubicación</b> sale de [db-ip.com](https://db-ip.com), base *IP to Country Lite*, y dice dónde está la máquina, que es lo que responde AbuseIPDB y lo que espera quien mira una bandera; el <b>registro</b> sale de los cinco RIR y dice quién es el titular del bloque. Coinciden en el 92% de las IP, y donde discrepan es en la nube y en los rangos alquilados, que es el perfil de la infraestructura desde la que atacan a un señuelo, así que el aviso enseña las dos cuando no coinciden. Se consulta en disco y nunca por red, a saltos sobre un fichero ordenado, sin gastar cuota de AbuseIPDB.

> [!WARNING]
> <b>`sendMessage` tiene tres límites, y el peligroso es el segundo.</b>
>
> | Límite | Qué pasa al pasarse |
> |---|---|
> | 4096 caracteres de texto renderizado | La API devuelve 400 y el fallo se ve |
> | 100 *entities*, o sea tramos con formato | <b>No avisa</b>: contesta `"ok":true`, entrega el texto entero y descarta en silencio las que sobran, de la última hacia atrás |
> | Unos 20 mensajes por minuto al mismo chat | 429, y un trozo rechazado no se reintenta nunca |
>
> El segundo tiene una consecuencia fea: al perder su `<code>`, la IP del atacante queda suelta en el texto, y a una IP suelta el cliente de Telegram le pone enlace automático, así que la alerta acaba ofreciendo un enlace pulsable hacia la máquina del atacante. De ahí la regla al escribir estos mensajes: <b>toda IP hostil y toda URL de descarga van dentro de un `<code>`</b>.
>
> `lib-telegram.sh` cuenta las tres cosas y trocea en varios mensajes en lugar de recortar, repitiendo la cabecera y numerando `(1/3)`, siempre por salto de línea para no dejar un enlace a medias. Trocea hasta `TG_MAX_TROZOS`, que vale 4: una ráfaga de mil IPs serían 25 mensajes, por encima del ritmo que admite Telegram. Lo que sobra no se muestra y el aviso dice cuántas líneas se omitieron, y no se pierde nada: las conexiones siguen en la base de Dionaea y las IPs siguen su camino hacia AbuseIPDB.

> [!CAUTION]
> <b>Todo lo que escribe el atacante se escapa antes de meterlo en el mensaje.</b> La URL de descarga que registra Dionaea la elige él, y le basta con meter un signo de menor-que para que Telegram conteste `400 can't parse entities`. Entonces no se pierde el formato, <b>se pierde el aviso entero</b>, porque el vigilante marca el evento como visto igualmente: es una forma barata de dejarnos ciegos justo cuando hay algo que ver. Por eso `tg_escapar` y `tg_recortar` se aplican a todo campo ajeno, y el hash solo se convierte en enlace si es hexadecimal.
>
> Ojo con una trampa de bash: desde la 5.2, un `&` suelto en el lado derecho de `${var//patrón/reemplazo}` significa "el texto que se acaba de encontrar", así que al escapar el signo de menor-que ese `&` se expande al propio carácter y el reemplazo lo deja tal cual. El escapado no sirve de nada y el resultado casi parece correcto.

Y una nota sobre el bloque de malware: <b>se agrupa por hash, y se cuentan conexiones distintas, no filas de la base</b>. Sin agrupar, un bot que sube el mismo fichero varias veces llena el aviso de repeticiones. Además, según la versión, Dionaea puede apuntar la misma descarga dos veces (un incidente `.hash` y otro `.unique`), así que contar filas diría "x4" donde hubo dos subidas reales.

Se puede comprobar sin tocar la red ni gastar una llamada, desde el propio repositorio:

```bash
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-lib-telegram.sh"
```

Y las de los otros dos vigilantes, que tampoco tocan la red ni la base real (**18 ok** y **12 ok**, 0 fallos):

```bash
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-breaker-watch.sh"
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-cuota-watch.sh"
```

```bash
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-ssh-watch.sh"
```

```bash
python3 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test_botones_cowrie.py"
```

<b>Un botón "Block IP" por cada IP listada, y por qué eso no se desmadra.</b> El resumen de Cowrie enseña varias IPs y traía un solo botón, el de la más insistente, así que de un vistazo parecía que solo una era accionable. Los botones no crecen sin control porque siguen a la lista, y la lista ya estaba acotada a las cinco IPs más insistentes. Uno por fila, porque la etiqueta de una IPv6 llega a 45 caracteres y dos por fila se cortan en un móvil.

Por debajo hacía falta arreglar que `_update_button` mandaba un teclado nuevo con un único botón, así que pulsar el de una IP borraba los de las demás. Ahora el teclado se deriva de un estado (`message_id -> {ip: estado}`) y hay un solo sitio que lo dibuja.

Las IPs del resumen son el enlace a AbuseIPDB, no un `<code>` para copiar. Sigue siendo seguro: lo que el `<code>` evitaba era que Telegram convirtiera la IP suelta en un enlace hacia `http://esa-ip`, y dentro de un `<a>` nuestro el destino lo ponemos nosotros.

> [!WARNING]
> <b>De qué IP avisa `ssh-watch.sh`, y por qué es un control y no un detalle.</b> El nombre de usuario que sshd escribe en el log lo elige quien se conecta, espacios incluidos, así que la línea contiene texto del atacante <b>antes</b> de la IP real:
>
> ```
> Invalid user "admin from [IP VPS] port 22" from 203.0.113.9 port 51234
> ```
>
> Cogiendo la primera coincidencia de `from `, cualquiera podía decidir qué dirección aparece como origen en tu alerta. Y poniendo una IP tuya, `marca_propia` la sellaba con `(nuestro 😇)`: el aviso de una intrusión ajena pasaba por una comprobación tuya. Se ancla con `" port "` detrás y se coge la última, que es la que añade sshd. `daily-digest.sh` hace lo mismo.

Reconstruye la alerta rota de aquel día y verifica que con el formato antiguo se pasaba de 100 *entities*, que con el actual se queda en 73, que el troceo respeta los tres límites sin mentir sobre lo que recorta, y que una URL con etiquetas dentro no puede tumbar el aviso. Deben salir **54 ok y 0 fallos**.

Para ensayar una ráfaga de verdad contra la base real, sin esperar a que vuelva a ocurrir y sin mover el estado del vigilante, `--test` admite cuántas conexiones mirar hacia atrás (40 por defecto):

```bash
sudo /opt/dirtyland/monitor/dionaea-watch.sh --test 400
```

Conviene hacerlo al menos una vez: el `--test` a secas genera cuatro líneas, y con cuatro líneas no se prueba nada del troceo.

Deben quedar todos, y los ejecutables ser de `root`:

```bash
ls -la /opt/dirtyland/monitor/
```

Probamos el envío básico:

```bash
sudo /opt/dirtyland/monitor/send-alert.sh "Prueba de conexión del sistema de monitorización del host"
```

El watcher SSH en tiempo real se instala como servicio systemd (y no como tarea de cron) porque debe estar escuchando el log de forma continua y reaccionar en el momento, no cada X minutos; systemd además lo levanta solo si se cayera y lo arranca con la máquina:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-sshwatch.service" /etc/systemd/system/dirtyland-sshwatch.service
```

La unidad **viene con el repositorio**, igual que la del vigilante de baneos del apartado 3.4.2.7, así que no hay que teclearla. Su contenido, para saber qué hace:

<pre>
[Unit]
Description=Dirtyland SSH watcher (Telegram alerts)
After=network.target ssh.service

[Service]
Type=simple
ExecStart=/opt/dirtyland/monitor/ssh-watch.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
</pre>

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dirtyland-sshwatch.service
sudo systemctl status dirtyland-sshwatch.service --no-pager
```

<b>Y el vigilante de órdenes.</b> El de SSH avisa de que <b>alguien ha entrado</b>; este cuenta <b>qué está haciendo</b>. Son dos mitades distintas y ninguna sustituye a la otra: la primera lee el log de `sshd` y no depende del shell; la segunda lee lo que se teclea.

La idea de fondo es la que hace útil todo este apartado: **a esa máquina no se entra nunca**, así que lo normal es que este canal esté callado durante semanas. Ese silencio es la prueba de que no hay nadie dentro. Una sola línea es motivo para mirar.

Son dos piezas. La primera se instala en `/etc/profile.d/`, y es la que anota cada orden en el journal:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/registro-comandos.sh" /etc/profile.d/dirtyland-registro.sh
```

Y **hay que cargarlo también desde `/etc/bash.bashrc`**, que no es duplicar por si acaso: cada sitio cubre unos shells que el otro no ve. La orden es idempotente, así que se puede repetir sin miedo:

```bash
grep -q dirtyland-registro /etc/bash.bashrc || printf '\n# Dirtyland: registro de ordenes (apartado 3.4.4)\n[ -r /etc/profile.d/dirtyland-registro.sh ] && . /etc/profile.d/dirtyland-registro.sh\n' | sudo tee -a /etc/bash.bashrc >/dev/null; grep -c dirtyland-registro /etc/bash.bashrc
```

Tiene que responder `1`.

> [!WARNING]
> <b>Sin esa segunda línea hay un punto ciego, y es justo el peor.</b> `/etc/profile.d/` solo lo leen los shells de <b>login</b>, y un shell de root abierto con `sudo su`, `sudo -s` o `sudo bash` no lo es, así que no se registra nada de lo que se teclee dentro: verías `cmd=sudo su` y después silencio absoluto, sin ningún error. Lo difícil de ver era que dependía de cómo te hicieras root, porque con `sudo -i` o `sudo su -` sí funcionaba.
>
> En Debian el `/etc/profile` carga además `/etc/bash.bashrc`, así que un shell de login pasa por los dos sitios. Por eso el fichero lleva una guarda `DIRTYLAND_REGISTRO`: sin ella, la misma orden se anotaría dos veces.

<b>No lleva `#!` ni bit de ejecución, y es correcto</b>: no se ejecuta, lo carga el shell con `source`. Coge las órdenes tecleadas en un `bash` interactivo <b>tal como se escriben</b>, incluido lo que un auditor de llamadas al sistema no ve: los *builtins* (`cd`, `export`, `history -c`) y la tubería entera como una sola línea. No coge lo que ejecuta un demonio, ni una shell que no sea `bash`, y quien ya tiene shell puede desactivarlo con `unset PROMPT_COMMAND`. Para eso está la segunda mitad.

<b>Y la segunda mitad: auditar las ejecuciones.</b> Lo de arriba se apoya en `PROMPT_COMMAND`, así que solo ve lo que se teclea **en un bash**. No ve un `sh`, ni un `python -c`, ni lo que lance un script, ni un binario que alguien suba y ejecute, y quien ya tiene shell puede quitarlo con `unset PROMPT_COMMAND`.

Esto mira el nivel de abajo: la llamada al sistema `execve`. Ahí no hay forma de esconderse, porque **para ejecutar algo hay que pasar por ella**.

```bash
sudo apt install -y auditd audispd-plugins && sudo systemctl enable --now auditd && sudo auditctl -v
```

Y lo primero, la configuración de disco, **porque el riesgo real no es el tamaño**:

```bash
sudo sed -i -e 's/^max_log_file *=.*/max_log_file = 8/' -e 's/^num_logs *=.*/num_logs = 2/' -e 's/^max_log_file_action *=.*/max_log_file_action = ROTATE/' -e 's/^space_left_action *=.*/space_left_action = SYSLOG/' -e 's/^admin_space_left_action *=.*/admin_space_left_action = SYSLOG/' -e 's/^disk_full_action *=.*/disk_full_action = ROTATE/' -e 's/^disk_error_action *=.*/disk_error_action = SYSLOG/' /etc/audit/auditd.conf && sudo grep -E '^(max_log_file|num_logs|max_log_file_action|space_left_action|admin_space_left_action|disk_full_action|disk_error_action)' /etc/audit/auditd.conf
```

> [!WARNING]
> <b>Algunas configuraciones de `auditd` traen `disk_full_action = HALT`, que APAGA la máquina.</b> En un honeypot eso es una denegación de servicio servida en bandeja: alguien que provoque suficientes eventos tira el servidor. Con lo de arriba quedan 16 MB como techo (2 ficheros de 8), rotando, y **sin ninguna acción que pare nada**.
>
> Y el tamaño no importa porque **el log es un buffer de paso**: lo que interesa sale hacia Telegram, y lo que se rote se puede perder sin más.

Las reglas van en un fichero y no con `auditctl` a mano, porque así **no sobreviven a un reinicio**, y el vigilante seguiría corriendo sobre un log que ya no recibe nada, sin dar ningún error:

```bash
sudo install -o root -g root -m 0640 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/AUDITD/dirtyland.rules" /etc/audit/rules.d/dirtyland.rules
```

Y se cargan:

```bash
sudo augenrules --load && sudo auditctl -l
```

Tienen que salir las dos, la de 64 y la de 32 bits. Sin la segunda, a alguien le basta con ejecutar un binario de 32 para saltarse la auditoría entera.

<b>La clave de todo esto es el `auid`</b>: es lo que hace la regla utilizable.

El `auid` es el usuario que **se autenticó**. Se fija al hacer login y **no se puede cambiar después**: ni con `sudo`, ni con `su`, ni entrando en otro intérprete. Se hereda por todos los procesos hijos. Con `auid>=1000` la regla hace dos cosas a la vez:

- **Captura todo lo que hace una persona**, incluido lo que haga tras un `sudo su` (que era justo el punto ciego del registro del shell).
- **Y deja fuera lo que no es una persona**: cron, systemd, y (esto importa mucho) **todo lo que pasa dentro de los contenedores**, porque esos procesos no vienen de un login y no tienen `auid`. Sin ese filtro llegaría por duplicado cada orden de cada atacante de Cowrie y el aviso sería inservible.

Y el vigilante que lo lee y lo manda:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-auditwatch.service" /etc/systemd/system/dirtyland-auditwatch.service
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now dirtyland-auditwatch.service && sudo systemctl is-active dirtyland-auditwatch.service
```

Para verlo sin esperar, con las últimas líneas del log. **Con `--seco` sale por pantalla y no se envía nada** (medir el volumen no debería costar una notificación):

```bash
sudo /opt/dirtyland/monitor/auditd-watch.py --test 200 --seco
```

Y sin `--seco`, lo mismo pero al móvil, que es la forma de comprobar que la cadena entera funciona:

```bash
sudo /opt/dirtyland/monitor/auditd-watch.py --test 200
```

Un aviso tiene esta pinta:

<pre>
<b>[dirtyland-auditwatch] Maquina VPS principal</b>
<b>🚨 Esto NO son los senuelos 🚨</b>
<b>3 ordenes  ---  user desde pts1, pts0</b>
<i><b>$</b> tu usuario   <b>#</b> como root   ---   <b>(+n)</b> = esa orden lanzo n programas mas por dentro</i>

<b>#</b> wc -l
<b>$</b> python3 -c import os; os.system('whoami')  <i>(+2)</i>
<b>$</b> sudo tail -60 /var/log/audit/audit.log  <i>(+1)</i>
</pre>

La primera línea dice qué servicio avisa y de qué máquina, y la segunda que esto no es un señuelo: por este mismo chat llegan los avisos de Cowrie y de Dionaea, y un aviso de "órdenes ejecutadas" se lee muy distinto según de dónde venga. Las marcas `$` y `#` van fuera del bloque de código, porque ese bloque está para copiar la orden. Y el aviso se manda cuando la cosa se calma, o pasados 2 minutos aunque no se calme, porque con solo la ventana de silencio el caso que importa, alguien trabajando dentro de la máquina, es justo el que no para.

<b>Un vigilante que pierde lo que vigila cuando se le reinicia es peor que no tenerlo, porque uno cree que lo tiene.</b> Y los dos lo hacían: `comandos-watch.sh` seguía el journal con `-n 0`, o sea desde ahora mismo, y `auditd-watch.py` saltaba al final del fichero al arrancar, así que lo anotado mientras el servicio estuvo parado se perdía sin rastro. Ahora retoman donde lo dejaron, con `--cursor-file` y apuntando el inodo y el byte en `auditwatch.pos`.

<b>Las tripas de una orden se pliegan, y el `(+n)` dice cuántas.</b> auditd enseña cada `execve`, incluido lo que un programa lanza por dentro: un solo `augenrules --load` son trece, y sin plegar seis órdenes tecleadas salían como 32 líneas. El árbol de `pid`/`ppid` solo no basta, porque plegar todo descendiente haría que un `sudo su` se llevara por delante lo que se teclee después dentro del shell de root, que es lo que más interesa ver. Así que se mira también el tiempo: un hijo que aparece dentro de 2 segundos es parte de aquella orden. Es una heurística, pero no esconde nada en silencio, porque cada orden lleva escrito cuántos programas se plegaron dentro.

> [!CAUTION]
> <b>Un registro de ejecuciones acaba conteniendo secretos.</b> Pasó el mismo día que se montó: `send-alert.sh` pasaba el token del bot como argumento de `curl`, auditd registra los argumentos de cada programa, y el token apareció publicado en el propio aviso de Telegram. Hubo que revocarlo. Ahora el token va por la entrada estándar de `curl` con `--config`, y hay dos defensas más:
>
> - <b>Lo nuestro no se avisa a sí mismo.</b> Se descarta todo lo que mencione `send-alert.sh`, `api.telegram.org` o `dirtyland-cmd`. Además de los secretos eso corta un bucle, porque el aviso se manda con `send-alert.sh`, que ejecuta `curl` con el texto entero como argumento.
> - <b>Censura por si acaso</b>: tokens de bot, `api_key=`, `Authorization:` y la contraseña pegada a un `-p`, esto último solo en los clientes de base de datos, que es donde ese patrón significa eso.
>
> Censurar de más oculta justo lo que se venía a ver, así que se prefiere quedarse corto, y no cubre todo lo imaginable: si tecleas una clave en una orden, dala por comprometida y rótala.

**Los dos registros se quedan, y no es redundancia**: cada uno ve lo que el otro no puede.

| | `dirtyland-cmdwatch` | `dirtyland-auditwatch` |
|---|---|---|
| **De dónde lee** | `PROMPT_COMMAND` del shell, vía journal | La llamada al sistema `execve`, vía `auditd` |
| **Qué enseña** | La **línea tal como se escribió** | **Cada programa** que se ejecuta |
| Un alias (`ls`) | `ls` | `ls --color=auto` |
| Una tubería | Una sola línea | Un programa por tramo |
| Los *builtins* (`cd`, `exit`, `export`) | **Sí** | **No**: no ejecutan nada, así que no hay `execve` |
| `sh`, `python -c`, un binario suelto | **No** | **Sí** |
| Lo que lanza un script por dentro | **No** | **Sí**, plegado con `(+n)` |
| Si alguien hace `unset PROMPT_COMMAND` | **Deja de ver** | Sigue viendo |

Por eso **`exit` solo aparece en uno y `clear_console` solo en el otro**, y no es un fallo de ninguno: es la diferencia entre *lo que escribiste* y *lo que ocurrió*. Se agrupan <b>20 segundos</b> antes de enviar y se recortan a <b>40 líneas</b> por mensaje, porque un solo `apt install` son cientos y un aviso de cientos de líneas no se lee. Los umbrales se mueven con `AUDIT_VENTANA` y `AUDIT_MAX_LINEAS`.

<b>Se anota en dos momentos, y hacen falta los dos.</b> El normal es antes de cada *prompt*; el otro, al salir del shell, porque sin él se perdía la última orden de cada sesión, que es justo lo que alguien hace antes de irse. Y el primer disparo no anota nada, solo toma nota de por dónde iba el historial: al abrir un shell bash carga `~/.bash_history`, y sin esa guarda la última línea de una sesión anterior se anotaba como recién ejecutada.

Está comprobado en un Debian 13 real que <b>no toca el `$?` del operador</b>: con el registro puesto y sin él, `false; echo $?` devuelve lo mismo. Si lo cambiara, cualquiera que mirase su propio código de salida vería el nuestro.

La segunda es el servicio que agrupa lo anotado y lo manda:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-cmdwatch.service" /etc/systemd/system/dirtyland-cmdwatch.service
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dirtyland-cmdwatch.service
sudo systemctl status dirtyland-cmdwatch.service --no-pager
```

<b>Por qué agrupa en vez de mandar un aviso por orden.</b> Un aviso por línea es inservible: en cuanto alguien entra y trabaja diez minutos el móvil se colapsa y se deja de leer. Se junta lo que llega y se manda de una pieza en cuanto hay una pausa de 20 s, o antes si se acumulan 25 órdenes, y se agrupa por sesión (usuario, origen y terminal), porque mezclar las órdenes de dos personas en un mismo mensaje sería justo el error que hace inútil el aviso. El directorio solo se enseña cuando cambia y el código de salida solo si no es `0`.

Para probarlo sin esperar a nadie, basta con abrir otra sesión y teclear algo:

```bash
logger -t dirtyland-cmd -p authpriv.notice -- "user=prueba tty=pts/9 from=127.0.0.1 pwd=/tmp rc=0 cmd=echo prueba del vigilante"
```

En menos de medio minuto debe llegar un aviso `[Host] 1 orden en la maquina principal`.

<b>El apartado "¿Me han baneado?"</b> abre el resumen, porque es lo primero que uno quiere saber. Lo genera `estado-cuentas.py`, y antes de fiarse del "No" hay que saber qué comprueba:

Hace <b>una petición autenticada</b> a cada plataforma y mira si la credencial sigue siendo aceptada: un `401` o un `403` son lo que ocurre cuando cierran una cuenta, y eso se detecta el mismo día. Lo que no puede ver es una cuenta que sigue leyendo pero tiene la publicación restringida, así que da <b>dos señales</b> y no una: la segunda es nuestro propio cortacircuitos, que si ha saltado significa que abuse.ch nos estaba rechazando envíos, y suele avisar antes que el `401`.

<pre>
🛐 Todo en orden
✅ AbuseIPDB: No me han baneado  (HTTP 200)
✅ VirusTotal: No me han baneado  (HTTP 200)
✅ abusech: No me han baneado  (query_status=hash_not_found)

Mis perfiles
MalwareBazaar · ThreatFox · AbuseIPDB · VirusTotal
</pre>

**`hash_not_found` es la respuesta buena**, aunque suene a fallo. Se pregunta por el hash de EICAR, que no está en MalwareBazaar a propósito: lo que se quiere saber no es si conoce ese fichero, es si <b>acepta nuestra credencial</b>. Una cuenta sancionada contesta `unauthorized` o `illegal_auth_key`, y entonces el aviso dice que sí nos han baneado.

Pone `abusech` y no `abuse.ch` a propósito: Telegram convierte en enlace cualquier cosa con forma de dominio, y en un mensaje cuyo asunto es si nos han baneado, una etiqueta azul y subrayada confunde. Ni el `<code>` ni un carácter de ancho cero lo evitan; quitarle el punto es lo único que funciona.

Las tres consultas son de lectura y gastan una llamada al día de cada cuota, 1 de 1000 en AbuseIPDB y 1 de 500 en VirusTotal: un precio razonable por enterarse el mismo día en vez de tres semanas después. Los enlaces salen de la sección `[perfiles]` del `config.ini`, que se rellena en el apartado <b>3.5.5.1</b>; los que sigan con su marcador no se muestran.

Se puede lanzar suelto para probarlo:

```bash
sudo python3 /opt/dirtyland/monitor/estado-cuentas.py
```

El resumen diario se programa con cron a las 06:00 UTC que eso a hora española equivale a 08:00 AM en verano y 7 en invierno. 

<p>Si el host no trae cron, se instala:</p>

```bash
sudo apt install -y cron && sudo systemctl enable --now cron
```

Y las tareas se ponen con esto, que **no abre ningún editor**:

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/cron-dirtyland.sh" /opt/dirtyland/ && sudo /opt/dirtyland/cron-dirtyland.sh --apply
```

Y se comprueba mirando el crontab de root, que es donde las deja:

```bash
sudo crontab -l
```

Tienen que estar estas cinco, y **nada más** de lo que ya hubiera cambiado:

<pre>
0 6 * * * /opt/dirtyland/monitor/daily-digest.sh
0 6 * * * /opt/dirtyland/monitor/baneadas-diario.sh
*/5 * * * * /opt/dirtyland/monitor/dionaea-watch.sh
*/30 * * * * /opt/dirtyland/monitor/proxy-watch.sh
0 4 1,16 * * /opt/dirtyland/geoip/generar-tabla-paises.py --avisar >/dev/null
</pre>

Se puede lanzar dos veces: si están las cinco, lo dice y se va. **Solo añade, nunca borra**, porque el crontab de root puede tener cosas que no son de este proyecto, y guarda copia del anterior. Reconoce cada tarea <b>por el script, no por la línea entera</b>, así que si le cambias la hora a mano no la da por ausente ni la duplica. Sin `--apply` solo dice cuáles faltan.

<b>`baneadas-diario.sh`</b> manda las IPs que hay bloqueadas en el cortafuegos. Sale a la misma hora que el resumen pero en un mensaje aparte, y es a propósito: el resumen dice cómo está el sistema, esto dice a quién se le ha cerrado la puerta, y mezclarlas hace que ninguna se lea.

<pre>
<b>[nftables] Maquina VPS principal</b>
<b>🚫 IP's baneadas: 4</b>

<b>Automaticas</b>
  72.255.37.107  🇺🇸 Estados Unidos
  103.83.101.171  🇻🇳 Vietnam

<b>A mano, desde Telegram</b>
  43.230.94.188  🇮🇳 India

<b>De origen desconocido</b> <i>(anteriores al 29/08)</i>
  153.117.9.239  🇵🇰 Pakistan
</pre>

<b>Sale de la tabla de `nftables`, no de un registro nuestro.</b> Es la única fuente que dice lo que de verdad está bloqueando la máquina: un fichero de anotaciones se queda desfasado en cuanto alguien desbanea a mano con `nft delete element`.

<b>Un aviso sobre una IP que se está baneando en ese momento no lleva botón.</b> El filtro ya excluía lo baneado, pero el aviso se encolaba antes de pedir el baneo, así que al pintar el teclado la IP todavía no constaba: ahora se apunta antes de avisar. Y banear una IP ya baneada tampoco es un error, que pasa a menudo porque el aviso sigue en el chat con su botón debajo. No se reescribe la etiqueta del que ya estaba: si una IP se baneó sola y luego alguien pulsa el botón, sigue constando como automática, porque lo que cuenta es de dónde salió.

<b>Automático o manual</b> sale del comentario que dejó el baneador al ponerla. Hay un tercer grupo porque durante un tiempo los dos caminos escribían el mismo texto, así que de aquellos baneos no consta de dónde vinieron, y meterlos en "a mano" sería afirmar algo que no se sabe. La etiqueta de "a mano" cambió de texto, así que lo que lleve la vieja se reconoce como lo que es y ese grupo se vacía solo según se desbanean o caducan.

Y <b>"ninguna" también se envía</b>. Un canal que solo habla cuando hay algo no se distingue de un canal averiado: si un día no llega nada, no se sabe si es que no hubo baneos o es que el aviso dejó de funcionar.

<b>`dionaea-watch.sh`</b>, cada cinco minutos, es la que avisa de la actividad de Dionaea, y hace falta porque Cowrie y Dionaea no se notifican igual: Cowrie tiene su plugin de salida dentro del contenedor y reacciona en el momento, mientras que Dionaea no tiene nada equivalente y hay que ir a leer su base de datos. Sin esa línea, los ataques por SMB, RPC y MSSQL <b>no llegarían nunca al móvil</b>.

<b>Esa segunda línea vigila además que Dionaea siga vivo</b>, que es el cuelgue en bucle del que habla el principio de este apartado. Lo único que distingue "no le ataca nadie" de "está bloqueado" es cuándo anotó la última conexión, y este script ya tiene esa base abierta cada cinco minutos. Si pasan más de <b>2 horas</b> sin una sola, avisa por Telegram con las dos órdenes escritas dentro: `docker top dirtyland_dionaea` para confirmarlo, y `docker restart dirtyland_dionaea` para levantarlo.

<b>Y no repite el mismo aviso cada cinco minutos.</b> Este script reporta lo nuevo desde la última vez, y con un atacante insistente eso es un grifo abierto: un mismo escáner de SMB dejaba una línea en cada pasada, o sea 288 avisos al día por una sola IP. La regla es la del plugin de Cowrie: cada combinación de <b>IP + servicio + puerto</b> avisa sus primeras `DIONAEA_AVISOS_POR_IP` veces (2) y luego calla. Callar no es olvidar, porque lo silenciado se cuenta, sale resumido al final del mensaje y a las `DIONAEA_REAVISO_HORAS` (6) vuelve a avisar con el total. <b>Lo que no se calla nunca son las descargas</b>.

<b>`generar-tabla-paises.py`</b> regenera la tabla de las banderas los días <b>1 y 16</b> de cada mes. Va en el crontab y no en `/etc/cron.d/dirtyland-reporter`, que es del reporter y se reinstala entero al actualizarlo. Descarga los ficheros públicos de los cinco RIR, así que no gasta cuota de ninguna API, y `--avisar` es lo que la hace fiable: si una descarga falla o llega a medias no toca la tabla que ya hay y lo cuenta por el bot. Una tabla de hace un mes sigue acertando en casi todo; media tabla, no.

Más a menudo no serviría de nada: los RIR publican a diario, pero un rango cambia de país muy de tarde en tarde. Y si algún día hace falta a mano (después de una reinstalación, por ejemplo) es la misma orden sin `--avisar`:

```bash
sudo /opt/dirtyland/geoip/generar-tabla-paises.py
```

Para ver cuántos días tiene la que hay puesta, sin descargar nada:

```
/opt/dirtyland/geoip/generar-tabla-paises.py --comprobar
```

Probamos las dos manualmente sin esperar al cron:

```bash
sudo /opt/dirtyland/monitor/daily-digest.sh
```

```bash
sudo /opt/dirtyland/monitor/dionaea-watch.sh --test
```

El `--test` reporta los últimos eventos <b>sin</b> marcar el estado como leído, así que se puede lanzar las veces que haga falta para comprobar que el envío funciona sin perderse nada del primer aviso real.

Los tokens los saca del `telegram.cfg` del apartado 3.4.2.7, el mismo bot que usa Cowrie, y no del `telegram.env` del monitor, que es otra conversación. Si responde `no pude leer bot_token/chat_id`, es que ese fichero no está o le faltan las claves.

## 3.5 Reporte a las plataformas.

Todo este esfuerzo tiene que dar algún producto o servicio y es el de contribuir a las plataformas de inteligencia de amenazas.

El honeypot no solo sirve para analizar que te ataquen, sino coger esa información y utilizarla.

El reporter es <b>un solo programa</b> que sirve a los dos honeypots.

La estructura es la siguiente:

| Carpeta | Qué hace | Qué NO sabe |
|---|---|---|
| `collectors/` | Leen Cowrie y Dionaea y traducen sus logs a un modelo común | Que existen las plataformas |
| `reporters/` | Uno por plataforma. Aplican sus reglas y publican | De qué honeypot viene lo que publican |
| `common/` | Modelo, estado, límites de ritmo, transporte HTTP y la barrera de IPs | - |
| `orchestrator.py` | Encadena todo en el orden correcto | - |

Por eso un mismo módulo de AbuseIPDB sirve para Cowrie y para Dionaea sin un solo condicional por honeypot, lo que le llega es el mismo objeto en ambos casos.

Sin embargo, en este apartado se monta en "modo simulación", es decir, sin llegar a publicar nada. Es en el apartado 3.8 donde se ponen las API keys de cada plataforma, se expone la máquina a internet y realmente empieza a reportar y funcionar.

### 3.5.1 Qué va a cada plataforma.

Cada plataforma acepta o no cierto hallazgo:

| Artefacto capturado | Plataforma | Qué se envía |
|---|---|---|
| IPs atacantes | AbuseIPDB | La IP a secas, con categorías. El puerto va en el comentario. No se sube la del servidor, ni Mullvad, ni proxy, ni la de casa. |
| Binario capturado | VirusTotal | El fichero; y si es malware (3.5.3, paso 4), comentario firmado y voto "malicious" |
| Binario capturado | MalwareBazaar | El fichero, **solo tras el veredicto de VirusTotal**. Hemos puesto un tope de 5 subidas al día y 20 a la semana. |
| URL que sirvió el binario | URLhaus | La URL, con `threat = malware_download` |
| Infraestructura confirmada | ThreatFox | El IOC como `ip:port` o dominio, con nombre de familia de Malpedia |

### 3.5.2 ¿Cómo lo hacemos?

La pregunta más importante de todas. Me llevé un baneo por parte de una de las plataformas por pensar que daba igual lo que publicaba mientras fuera un binario malicioso, en qué cantidad y qué binario exactamente estaba publicando.

Se decidió automatizar todo el proceso, aunque lo idóneo sería analizar manualmente cada muestra y luego publicar.

Considero que he encontrado **el método para no ser baneado de nuevo**.

Empecemos por lo fácil. Cada plataforma es más o menos exquisita:

- **VirusTotal**: No es casi nada exigente, por no decir nada.
- **AbuseIPDB**: No es apenas exigente.

Sin embargo, las tres plataformas que nos quedan y son de abuse.ch, sí son muy exigentes y rigurosas: simplemente hay que cumplir con lo que nos piden:

- **MalwareBazaar**: El propio fundador de abuse.ch me pidió que dejara de publicar WannaCry. No está en sus políticas, simplemente me lo pidió. Por desgracia, sus intenciones no siempre se reflejan de manera exacta y precisa en las políticas de su página.
- **ThreatFox y URLhaus**: Son estrictas, basta con seguir las políticas. Nada novedoso ni que sorprenda.

Entonces:

- Como AbuseIPDB solo busca publicar IPs y ya, no hay ningún problema a resolver ni método especial. Simplemente publica las IPs que no sean tuyas de tu servidor, no sean de Mullvad, los proxies o la tuya de tu casa y respeta el tope diario que establece AbuseIPDB; es posible que lo superes.
- VirusTotal realmente no publicas nada, no atribuyes tu mérito de la misma forma que lo haces con las plataformas de abuse.ch, VirusTotal aunque sí puedes subir archivos, normalmente la única forma en la que atribuyes que fuiste tú el primero en subir algo, es básicamente siendo el primero en comentar en el apartado de comentarios del binario y votar, nada más. De nuevo, no hay nada especial a tener en cuenta.

#### 3.5.2.1 El problema.

Las plataformas que nos quedan son las de abuse.ch y son las más estrictas. Sin embargo, aspirar al 100% de automatización y cumplimiento es difícil.

El hallazgo difícil es el binario, no la IP ni URL ni IOC.

A menudo los atacantes sueltan o generan 3 tipos de archivos:
- De relleno, literalmente archivos vacíos (comúnmente los verás como Andromeda).
	- Aunque cumplen una función, no tiene ningún sentido lo que hacen en nuestro caso, porque somos un servidor y no un dispositivo IoT. 
- Droppers, archivos "_inocuos_" ya que solo hacen curls y descargas: si lo analizas con VirusTotal, casi nadie lo detecta como algo malo, porque realmente no lo es. Un script que contiene curls y wgets no tiene por qué ser considerado un malware. Sin embargo, lo hemos llamado por su nombre exacto, dropper, porque su función no es para nada benigna, sino descargar de servidores C2 el malware real.

Vamos a parar un momento para mencionar que **para esos dos casos** comparten algo en común: son archivos de pocas o ninguna línea, es decir: **un tamaño de pocos bytes o 1 KB como mucho.**

Y el tercer caso:
- El binario en sí es malicioso y ya.

### 3.5.3 El método.

Entonces.

Necesitamos hacer un filtro:

1. Lo primero es determinar el peso del archivo. Si pesa 0 bytes como son los Andromeda, se descarta.
2. Los droppers no son malware en sí y tampoco pesan como un malware. Pero hay que hacer una criba de lo que es un dropper y lo que es un script con curls y wgets. Si es texto plano de 512 bytes o menos sin `#!`, se descarta, porque no se puede ejecutar. Si tiene `#!`, pasa a VirusTotal.
   - El `#!` es la primera línea de un archivo, que indica un script.
   - O también si es un ELF o PE en Windows.
   - O un comprimido `.zip`, `.gzip`.
3. Entonces, cada binario/script se sube a VirusTotal. Si ya estaba registrado, bien, y si no, se sube a analizar. Se recoge del análisis:
   - La familia y nombre.
   - La puntuación que los motores le han puesto (a veces subjetiva y variable).
4. Lo que nos confirma que es un binario malicioso es:
   - La puntuación: si 12 o más motores dicen que lo es, es porque lo es.
   - Si 3 o más motores lo catalogan como de X familia, es porque lo es.
   - Que no sea adware ni PUP.
5. Entonces, si es malware, continuamos; si no, aquí se termina el proceso.
6. Si es malware, en VirusTotal votaremos que lo es (Community down vote) y ponemos un comentario.
   - Esto lo hacemos porque hay bots en VirusTotal que están literalmente esperando a que alguien suba algo en MalwareBazaar, para robártelo, subirlo a VT, y decir que han sido los primeros en hacerlo y esto es real y verídico, roban el crédito y esfuerzo ajeno. Es más, roban hasta tu comentario que hayas puesto en MalwareBazaar, por lo que el comentario que pongas en MB se recomienda que pongas tu nombre de usuario, para "envenenar" ese robo, y aunque te lo roben, se sabe de quién se lo ha robado, porque no dan ni crédito de quién se lo han robado, y al ser algo automatizado, pues nadie lo suele mirar.
7. Ya que sabemos que es un malware, necesitamos revisar la familia que no sea WannaCry (basta con que un motor lo llame así). Si no es así, continuamos.
8. Finalmente es aquí donde revisamos si existe ese malware en MalwareBazaar: si está publicado, descartamos. Si no lo está y tiene una antigüedad en VirusTotal de 10 días o menos, nosotros publicamos; si no, descartamos.


### 3.5.4 Flujo completo.

- **El eje central es un archivo llamado:** `orchestrator.py`.
- Cada 15 minutos, el cron ejecuta un script: `malware-watch.sh`.
- Este script `malware-watch.sh` es quien lanza `orchestrator.py`.
	- **¿Por qué un script para invocar a otro, en vez de invocar directamente el `orchestrator.py`?**
	- Porque `malware-watch.sh` contiene `flock` (que como por poder lo podría directamente tener el orquestador).
		- `flock` es un comando de Linux, no de Python.
		- Busca solucionar un problema muy concreto. VirusTotal solo permite 500 peticiones al día y 4 peticiones por minuto. <br>`flock` es un comando que bloquea archivos, la intención es que no permita la segunda ejecución de `orchestrator.py` (_explicaremos más adelante lo que hace exactamente_ `orchestrator.py` _pero básicamente es el encargado de recopilar, analizar, subir_). <br>
		- Todo eso es un proceso largo y el cron se ejecuta cada 15 minutos de manera imperativa. <br><br> Queriendo decir que de nada sirve volver a ejecutar ese archivo `orchestrator.py` si en esos 15 minutos no le ha dado tiempo físico de hacer todo.
		- El problema no es solo que se solapen, sino que suban dos veces lo mismo a la plataforma.
		- Para ello, `flock` bloquea cuando se ejecuta `orchestrator.py` y se abre cuando termina, permitiendo que en el próximo cron de 15 minutos pueda volver a ser ejecutado con normalidad. Sin que se ejecute dos veces a la vez.
	- Para que quede rastro de los fallos que `orchestrator.py` no puede apuntar en su propio log: configuración rota o Python sin arrancar. 
- Entonces, cuando se pueda ejecutar `orchestrator.py` su misión es:
	- Cerrar lo que quedó a medias en la ejecución anterior: comprobar si llegó lo que se estaba enviando cuando se cortó.
	- Leer los logs de Cowrie y Dionaea: IPs atacantes, binarios y URLs de descarga.
	- Denunciar las IPs atacantes en AbuseIPDB. Siempre porque no depende de VT.
	- Con los binarios nuevos: aplicar el filtro del 3.5.3 y subir a VirusTotal los que no conozca.
	- Con los binarios que ya toca juzgar: mirar el veredicto de VirusTotal y, si es malware, comentar y votar en VirusTotal, y después subir a MalwareBazaar, URLhaus y ThreatFox, y denunciar en AbuseIPDB al servidor que sirvió el binario.
	- Dejar el resumen de la pasada en su log.
	- El manejo de error que explicamos en el apartado `3.5.4.1`.

Las IPs y los IOC no suponen ningún reto especial. Lo difícil son los binarios, y ya vimos en el 3.5.3 cómo se tratan.

#### 3.5.4.1 Si VirusTotal no funciona.

VirusTotal juega un papel importante en el flujo: hay que anticiparse a dos posibles escenarios:

**Caso 1: Caída de la plataforma VirusTotal.** <br>
**Caso 2: Superar la cuota de peticiones a VirusTotal.**

<p>
En ambos casos se paraliza la subida a MalwareBazaar, ThreatFox y URLhaus. Las muestras quedan en el estado "pendiente_de_veredicto".<br>
¿Por qué?<br>
<b>Sin VirusTotal no se puede acreditar que un binario sea malware</b>, y por tanto tampoco que la URL o el servidor que lo repartió sirvieran malware. Así que, sin veredicto, no se sube nada a esas tres plataformas.

<b>Con AbuseIPDB se sigue como si nada</b>, salvo la denuncia del servidor que sirvió el binario, que también espera.
</p>
<p>
<b>Lo único que difiere es que en el caso 2</b>, necesitamos saber cuándo se restablece la cuota. Pues si mandamos peticiones con tal de ver si podemos, nos devuelve respuestas `HTTP: 429` y eso puede acabar en baneo.

Por suerte, es muy simple: cuando son las 00:00 UTC, el contador de VT llega a cero y podemos volver a mandar peticiones hasta 500. No es un contador de tiempo que haya que esperar, ni hay que preguntar cuánto nos falta: llevamos la cuenta nosotros y frenamos antes de llegar a 500.
</p>

### 3.5.5 Instalación del reporter.

Necesitamos `python3-requests`:

```bash
sudo apt install -y python3-requests
```

Primero se vacía el destino, conservando el `config.ini` si ya existiera (así el mismo comando sirve para instalar y para actualizar, sin dejar ficheros viejos sueltos):

```bash
sudo find /opt/dirtyland/platform-reporter -mindepth 1 -maxdepth 1 ! -name config.ini -exec rm -rf {} + && sudo cp -a "/tmp/dirtyland-repo/REPORTING PLATFORM SCRIPTS/." /opt/dirtyland/platform-reporter/ && sudo chown -R root:root /opt/dirtyland/platform-reporter && sudo find /opt/dirtyland/platform-reporter -type f -name '*.py' -exec chmod 640 {} + && sudo chmod 750 /opt/dirtyland/platform-reporter/orchestrator.py /opt/dirtyland/platform-reporter/malware-watch.sh && echo "reporter instalado"
```

Tiene que terminar imprimiendo `reporter instalado`.

Los directorios de estado y registro:

```bash
sudo install -d -m 750 -o root -g root /var/lib/dirtyland-reporter /var/log/dirtyland-reporter
```

#### 3.5.5.1 Configuración y lista de bloqueo.

Se instala el config con los permisos adecuados:

```bash
sudo install -m 600 -o root -g root /opt/dirtyland/platform-reporter/config.ini.example /opt/dirtyland/platform-reporter/config.ini
```

Aquí se rellenan <b>cinco cosas</b>:

| Clave | Sección | Obligatoria | Qué poner |
|---|---|---|---|
| `ips` | `[blocklist]` | **Sí.** El programa se niega a arrancar con la lista vacía | Las IPs de los proxies y del propio servidor VPN que uses, es decir, 3 proxies + 1 servidor. Las dos de la VPS ya vienen puestas |
| `cowrie_log_tz` | `[paths]` | Sí, si el contenedor de Cowrie no va en UTC | La zona horaria del contenedor de Cowrie (aquí `Europe/Kyiv`), la que ven los atacantes y con la que Cowrie escribe sus logs. El reporter la usa para pasar esas horas a UTC antes de publicar a las plataformas |
| `attribution_tag` | `[general]` | No. Sin ella no se firma lo publicado | Tu handle |
| `usuario` | `[threatfox]` | No. Sin ella el resumen no distingue un IOC nuevo de un refresco | Tu nombre tal como lo enseña ThreatFox |
| Los seis enlaces | `[perfiles]` | No. Sin ellos el resumen diario no enseña tus perfiles | Tu ID en cada enlace, en lugar de `TU-ID` |
| `virustotal`, `abusech`, `abuseipdb` | `[api_keys]` | No. Se ponen en el 3.8.1 | - |

Cada cosa está lejos una de otra y con bloques largos de comentarios en medio.<br>
<b>Para solucionarlo no busques nada a ojo:</b>

```bash
sudo awk '/^\[/ {sec=$0} sec=="[perfiles]" || /^(ips|cowrie_log_tz|attribution_tag|usuario)[ \t]*=/ {if ($0 !~ /^[ \t]*(;|#|$)/) printf "%4d  %s\n", NR, $0}' /opt/dirtyland/platform-reporter/config.ini
```

Te dice en qué líneas aparece cada cosa. Ahora que ya sabemos las líneas abrimos el nano pero mostrando las líneas:

```
sudo nano -l /opt/dirtyland/platform-reporter/config.ini
```
Al terminar de editar, vamos a listar **todo marcador que siga sin sustituir**:

```bash
sudo grep -nE '^[^;]*<[^>]+>' /opt/dirtyland/platform-reporter/config.ini
```

Las tres `api_key` del principio salen a propósito: se rellenan en el 3.8.1, y el `usuario` de `[threatfox]` puede quedarse con su marcador si prefieres no ponerlo.

- **Si cambias de nodo del VPN, añádelo a `ips` antes de usarlo.** Una IP de más en la lista no hace daño; una que falta sí, porque el reporter acabaría denunciándote.
- **Lo que se publica va en inglés, por OPSEC.** Los comentarios de VirusTotal y AbuseIPDB son públicos y permanentes: el castellano estrecharía el perfil de quien hay detrás, y el inglés es además lo que allí se espera.
- **`anonymous`:** las tres plataformas de abuse.ch lo aceptan en cada envío, con `1` publicando sin nombre y `0` atribuyendo a tu cuenta. Los reporters mandan `0`.
    - No es lo mismo que `attribution_tag`: `anonymous` decide si la plataforma te reconoce como quien lo envió, y `attribution_tag` escribe tu handle **dentro del texto**, que es lo único que sobrevive si alguien republica la muestra en otro sitio.
- **Tu handle no puede aparecer jamás dentro del honeyfs.** Sería el hilo que conecta el señuelo con quien lo opera.
- **Para confirmar la zona horaria del contenedor de Cowrie:**

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "import time; print(time.tzname)"
```

#### 3.5.5.2 Comprobaciones.

Todos los comandos del reporter llevan `sudo`: el `config.ini` es `600` y de `root`, y sin él el reporter no puede leerlo.

<b>1. ¿El código está bien?</b> Dos baterías de pruebas que no necesitan claves, ni red, ni honeypot: trabajan con datos falsos.

```bash
sudo python3 /opt/dirtyland/platform-reporter/tests/test_gates.py
```

Comprueba las puertas una a una: que con 4 motores no se publica, que una muestra de 30 días se rechaza, que el mismo hash no sale dos veces, que sin handshake no se reporta a AbuseIPDB y que una IP propia aborta el envío.

```bash
sudo python3 /opt/dirtyland/platform-reporter/tests/test_end_to_end.py
```

Ejecuta el orquestador completo con un `cowrie.json` y una `dionaea.sqlite` falsos, y comprueba que VirusTotal va antes que MalwareBazaar, que una segunda pasada no repite nada y que ninguna IP propia ni ninguna clave aparece en lo que se habría enviado.

Las dos terminan con <b>código 0</b> si todo pasa. Hay que volver a lanzarlas después de tocar cualquier umbral o política.

<b>2. ¿Mi configuración está bien?</b>

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

Comprueba la configuración, los permisos y la barrera de IPs: que las propias se rechazan y una ajena pasa. Si todavía no has puesto las `api_key`, saldrá con código 3, y es lo correcto: se queja de ellas.

<b>3. ¿Funciona en mi máquina?</b> Una pasada en vacío: sin `--live` no publica nada.

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini
```

Si no hay `api_key`, cada plataforma se salta entera, así que solo demuestra que el reporter arranca y lee los logs. Con las `api_key` puestas, durante los días de simulación, esto dice por qué no se envió cada cosa:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --show-rejections 30
```

<pre>
abuseipdb    handshake     45.9.148.99   sin handshake TCP confirmado: la politica prohibe...
malwarebazaar antiguedad   7794cb2e...   vista por primera vez hace 30 dias, el maximo son 10
</pre>

| Código de salida | Significado |
|---|---|
| 0 | Todo bien |
| 1 | Error inesperado |
| 2 | Problema de configuración |
| 3 | Falló el self-test |
| 4 | Terminó con errores de red o rechazos de plataforma |
| 5 | Cuota agotada (no es un fallo) |

#### 3.5.5.3 Automatizarlo con crontab.

Tal y como documentamos en el apartado `3.5.4`, se utiliza "crontab" para automatizarlo; el script que ejecuta dijimos que es `malware-watch.sh`:

```bash
MODO=$(grep -qE '^[[:space:]]*\*/15 .*malware-watch\.sh --live' /etc/cron.d/dirtyland-reporter 2>/dev/null && echo live || echo sim) && sudo install -m 644 -o root -g root /opt/dirtyland/platform-reporter/cron.d/dirtyland-reporter /etc/cron.d/dirtyland-reporter && { [ "$MODO" = live ] && sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' /etc/cron.d/dirtyland-reporter; true; } && grep -vE '^\s*(#|$)' /etc/cron.d/dirtyland-reporter | grep malware-watch
```
El fichero de cron tiene dos líneas casi iguales, y solo una está activa: la otra lleva # delante, que la desactiva.

**El comando previo nos muestra la línea que ha quedado activa.**

Ha tenido que haber quedado así:

<pre>
*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh
#*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live
</pre>

Si nos preguntamos por qué 15 minutos, ejecutarlo más a menudo no adelanta nada:
- Los binarios se juzgan horas después. Una muestra se sube a VirusTotal y su veredicto se mira 12 horas más tarde, cuando los motores ya la han analizado. Mirar cada 3 minutos no lo acelera.
- Cada pasada gasta cuota. Hace consultas a VirusTotal, que solo admite 500 al día. Más pasadas serían más consultas para nada.
- 15 minutos es un punto medio: lo bastante frecuente para denunciar pronto las IPs atacantes y recoger los binarios nuevos, sin gastar cuota de más. No es un número exacto que haga falta; es el que se eligió.

Si por casualidad queremos ver el fichero de cron donde se alberga lo anterior:

```bash
cat /etc/cron.d/dirtyland-reporter
```

Dentro veríamos:

<pre>
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh
#*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live

17 6 * * * root /usr/bin/python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test

*/5 * * * * root /opt/dirtyland/monitor/breaker-watch.sh

5,20,35,50 * * * * root /opt/dirtyland/monitor/cuota-watch.sh
</pre>

#### 3.5.5.4 Vigilancia, pausa y qué hacer si te banean.

<b>Ver qué está pasando.</b> Qué se envió y qué se rechazó:

```bash
sudo tail -n 40 /var/log/dirtyland-reporter/reporter.log
```

Con `-f` en lugar de `-n 40` se sigue en directo, hasta cortarlo con `Ctrl+C`. Si algo no cuadra, `-v` enseña los descartes uno a uno, y `--only` recoge de un solo señuelo para ver cuál de los dos está en silencio:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini -v
```

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --only dionaea
```

<b>Envíos cortados a medias.</b> Si una publicación se corta por un `timeout`, un `500` o la red, no se sabe si llegó: el servidor pudo procesarla y caerse al contestar. Por eso no se reenvía a ciegas, porque eso es lo que genera duplicados. Queda como <b>sin confirmar</b>, y en la pasada siguiente se pregunta a la plataforma si llegó, cuando la plataforma lo permite. Lo que no se resuelve se da por perdido a las 24 horas.

<b>El cortacircuitos de abuse.ch.</b> MalwareBazaar, ThreatFox y URLhaus son la misma cuenta: un baneo en una se lleva las tres. Por eso, tres rechazos de abuse.ch en 24 horas apagan las tres hasta que se rearman a mano, después de entender qué pasó:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --reset-breaker
```

VirusTotal y AbuseIPDB son cuentas aparte y siguen funcionando.

<b>Pausar.</b> Para dejar de enviar a abuse.ch y seguir con AbuseIPDB y VirusTotal, se desactivan sus secciones del `config.ini`:

```ini
[malwarebazaar]
enabled = false

[threatfox]
enabled = false

[urlhaus]
enabled = false
```

Y para detenerlo todo:

```bash
sudo rm /etc/cron.d/dirtyland-reporter
```

<b>Si llega el baneo.</b> abuse.ch admite apelación. Lo que funciona es explicar sin adornos qué es la máquina, qué causó la infracción y qué se ha cambiado para que no se repita.

## 3.6 Para facilitarnos la vida.

Hay acciones que es posible que acabemos haciendo muchas veces:
- Entrar al señuelo para ver cómo se comporta.
- Pararlo todo cuando algo se tuerce.
- Etc.

Como no queremos obligar a nadie a aprenderse comandos ni abrir esta documentación.<br>
He decidido crear estos scripts que reunen todas las posibles acciones que he podido hacer en el servidor:

| Script | Para qué |
|---|---|
| `acceder_ssh_para_vagos.sh` | Entrar al señuelo desde dentro de la propia VPS |
| `boton_del_panico.sh` | Parar los dos contenedores en seco, y reanudarlos |
| `cortar_el_grifo.py` | Apagar la publicación hacia una plataforma concreta, y el modo del cron |
| `estoy_dentro.py` | Callar los avisos del anfitrión mientras estás trabajando en la máquina |
| `que_pasa_con_las_plataformas.py` | Plataforma por plataforma: qué se publicó, qué se descartó y **por qué** |
| `voy_al_dia.py` | Qué versión tiene puesta la VPS y si coincide con la copia del repositorio |
| `que_le_falta_al_senuelo.py` | Qué binarios **dice tener** el señuelo y no sabe ejecutar, ordenados por lo que los bots han tecleado de verdad |
| `banco_shell_real.py` | Pasa líneas por el **shell de verdad**, el protocolo de Cowrie sobre su `fs.pickle`, y compara con lo que contesta `bash`. Sin red y sin tocar la VPS. Cubre lo que las pruebas de comandos no pueden ver: el troceo, la redirección, los paréntesis y el directorio actual. **403 casos en verde**, y los abiertos van en una lista aparte |

Estos ficheros están en la carpeta `3.6 Para facilitarnos la vida/` del repositorio.<br>
Los copiamos:

```bash
install -m 700 -t ~/ "/tmp/dirtyland-repo/3.6 Para facilitarnos la vida/"*.sh "/tmp/dirtyland-repo/3.6 Para facilitarnos la vida/"*.py
```

Un comodín y no la lista de nombres, para que añadir un script a esa carpeta no obligue a tocar este paso. Los `tests/` no entran, porque el comodín no baja a los subdirectorios. Y es `700` porque uno de estos scripts apaga el señuelo entero y otro toca el `config.ini`.

```bash
ls -l ~/*.sh ~/*.py
```

Deben salir los nueve como `-rwx------`: los ocho de la tabla y `que_hizo_esta_ip.py`, que se usa en el 3.9.

### 3.6.1 Explicación breve del funcionamiento de cada comando.

#### Entrar al señuelo.

Sin argumentos entra como `alyosha`; se le puede pasar otro usuario del `userdb`:

```bash
~/acceder_ssh_para_vagos.sh
```

```bash
~/acceder_ssh_para_vagos.sh admin
```

No pide la contraseña, la pone él. Para probar un login <b>fallido</b>, por ejemplo para ver si salta la alerta, se le pide que pregunte:

```bash
~/acceder_ssh_para_vagos.sh admin --pedir
```

Conecta al contenedor <b>desde dentro de la VPS</b>, así que la sesión no se confunde con un ataque. Necesita OpenSSH 8.4 o posterior.

#### El botón del pánico.

Para los dos contenedores, y con ellos toda la actividad entrante. Necesita `sudo` y pide confirmación escribiendo `PARAR`:

```bash
sudo ~/boton_del_panico.sh
```

```bash
sudo ~/boton_del_panico.sh --estado
```

```bash
sudo ~/boton_del_panico.sh --reanudar
```

No toca el cortafuegos, no borra nada y el reporter sigue procesando lo ya recogido.

#### Cortar el grifo de una plataforma.

Deja de publicar en una plataforma concreta mientras resuelves una duda con ella. Necesita `sudo`, porque edita el `config.ini`:

```bash
sudo ~/cortar_el_grifo.py
```

<pre>
Current status:
  0)  cron mode  (/etc/cron.d/dirtyland-reporter)      🔴 SIMULATION  (nothing is published)

  1)  abuse.ch  (MalwareBazaar + ThreatFox + URLhaus)  🔴 stopped
  2)  VirusTotal                                       🔴 on, but muted by cron
  3)  AbuseIPDB                                        🔴 on, but muted by cron

  [REASON: cron is in SIMULATION mode: nothing is published]
</pre>

Se conmuta por número y se pueden dar varios (`0 1`). Antes de confirmar enseña qué va a pasar y deja una copia fechada del `config.ini`. La <b>opción 0 es el modo del cron</b> y manda sobre todo lo demás: con él en simulación no se publica nada. Solo se apaga la <b>publicación</b>: el señuelo sigue capturando y el reporter recogiendo.

Un estado 🟡 `PARTIAL` se resuelve <b>apagando</b>, no encendiendo:

| Estado actual | Al elegirla |
|---|---|
| 🟢 las tres encendidas | se apagan las tres |
| 🟡 alguna encendida | se apagan las tres |
| 🔴 ninguna encendida | se encienden las tres |

Para solo mirar, sin cambiar nada:

```bash
sudo ~/cortar_el_grifo.py --estado
```

#### Callar los avisos mientras estás dentro.

Cuando entras tú a la máquina, todo lo que haces dispara avisos. Esto los calla. Necesita `sudo`, porque escribe en `/opt/dirtyland/monitor/`:

```bash
sudo ~/estoy_dentro.py
```

```bash
sudo ~/estoy_dentro.py --estado
```

| Qué calla | Qué **no** calla |
|---|---|
| Todo lo que pasa por `send-alert.sh`: el vigilante de SSH, el de órdenes, el del cortafuegos y el de Dionaea. O sea, la vigilancia del anfitrión | El **resumen diario**, que se manda con `--siempre` a propósito |
| | El chat del **señuelo**: son dos bots y dos conversaciones distintas (apartado 3.4.2.7) |
| | El señuelo en sí. Cowrie y Dionaea siguen capturando, y el reporter sigue publicando. Para pararlos está `~/boton_del_panico.sh` |

Por defecto calla <b>4 horas</b> y se enciende sola. Se puede pedir silencio sin plazo escribiendo `forever`. Los avisos callados no se pierden: quedan anotados y el resumen diario los cuenta.

```
Vigilancia del anfitrion
🔴 SILENCIADA --- vuelve sola en 143 min
  🟡 6 aviso(s) retenidos en /opt/dirtyland/monitor/silenciadas.log
```

#### Saber si lo que hay puesto es lo que hay en el repositorio.

Necesita `sudo`, porque casi todo lo desplegado pertenece a `root`:

```bash
sudo ~/voy_al_dia.py
```

<b>Hay que lanzarlo antes de exponer.</b> Compara la versión puesta en la VPS con la de la copia que el `git archive` dejó en `/tmp/dirtyland-repo`:

<pre>
en la maquina : 7f0e389  2026-08-28T06:50
en la copia   : 7f0e389  2026-08-28T06:50
AL DIA
</pre>

Si no coinciden dice `ATRASADO`, y la primera vez, con la máquina sin marcar, `SIN MARCAR`. No cambia nada. Devuelve `0` si coinciden, `1` si está atrasada o sin marcar y `2` si no ha podido comparar, por ejemplo porque la carpeta se subió a mano en vez de con `git archive`.

#### Qué dice tener el señuelo y no sabe ejecutar.

Necesita `sudo`, porque lee el `fs.pickle`, los logs de Cowrie y le pregunta al contenedor:

```bash
sudo ~/que_le_falta_al_senuelo.py
```

El sistema de ficheros del señuelo anuncia cientos de binarios que no sabe ejecutar, y eso es una contradicción que no pasa en ningún Linux:

<pre>
$ ls -la /usr/bin/sed   ->  -rwxr-xr-x 1 root root 126424 Jan  5 2023 /usr/bin/sed
$ file /usr/bin/sed     ->  ELF 64-bit LSB pie executable, x86-64
$ which sed             ->  /usr/bin/sed
$ sed --version         ->  -bash: /usr/bin/sed: No such file or directory
</pre>

El script ordena lo que falta por lo que los bots han tecleado de verdad contra este señuelo, así que dice qué conviene emular primero:

<pre>
  SABE EJECUTAR        : 196 nombres
  DICE TENER           : 453 binarios
  DICE TENER Y NO SABE : 353   (78% de lo que anuncia)

QUE EMULAR PRIMERO --- lo que falta y ADEMAS se ha tecleado aqui
      12  sed                      /usr/bin/sed
       7  ln                       /usr/bin/ln
       5  sysctl                   /usr/sbin/sysctl

Y 350 que tampoco sabe ejecutar pero NADIE ha tecleado.
</pre>

```bash
sudo ~/que_le_falta_al_senuelo.py --tecleado
```

```bash
sudo ~/que_le_falta_al_senuelo.py --todos
```

- El primero enseña solo el ranking de lo más tecleado, con una marca en lo que no se sabe ejecutar.
- El segundo lista además los que nadie ha tecleado nunca.

#### Saber si vas al día.

Es lo que hace que la próxima vez `voy_al_dia.py` sepa qué versión hay puesta:

```bash
sudo ~/voy_al_dia.py --marcar
```

> [!IMPORTANT]
> <b>Este es el último paso de cualquier despliegue, y el único que hay que recordar.</b> Qué no detecta: si copias unas piezas y otras no, dirá que vas al día igualmente, porque solo mira el sello.

#### Otros scripts.

Sí, no he puesto todos, porque los tres que faltan están en el 3.9.

## 3.7 Últimas comprobaciones antes de exponer.

Como somos tan paranoicos y rigurosos con nuestro trabajo, necesitamos confirmar:

### 3.7.1 Los dos canales de alerta funcionan.

Si exponemos el señuelo y las alertas no funcionan, nos estaremos perdiendo justo aquello para lo que montamos todo esto.

Esto es la comprobación rápida (que los dos bots hablan). El ensayo completo, aviso por aviso, va en los dos apartados siguientes.

El bot del <b>host</b>:

```bash
sudo /opt/dirtyland/monitor/send-alert.sh "Comprobacion previa a la exposicion"
```

Y el bot del <b>señuelo</b>, provocando un evento real desde dentro (el honeypot sigue sellado, así que nos conectamos directamente al contenedor por su IP interna):

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alyosha@172.20.0.10
```

Una vez dentro, cualquier comando debería dispararnos una alerta al Telegram de Cowrie:

```bash
whoami
exit
```

### 3.7.1.1 El ensayo completo: los veinticinco avisos.

Que los dos bots hablen no quiere decir que **todos** los avisos lleguen. Cada uno lo compone un vigilante distinto, con su propio HTML, sus banderas y su troceado, así que un fallo de formato en uno no dice nada de los demás.

`probar-avisos.sh` los dispara todos, uno detrás de otro. **Veintidós son del anfitrión** y los monta él con entradas falsas; los **tres últimos son del señuelo** y necesitan una sesión de verdad, así que van al final y se explican un poco más abajo:

```bash
sudo /opt/dirtyland/monitor/probar-avisos.sh
```

Tarda alrededor de un minuto (espera tres segundos entre mensaje y mensaje para no chocar con el límite de Telegram) y recorre estos veinticinco, en este orden:

<pre>
 1  [Host] Login SSH exitoso
 2  [Host] INTENTO DE ACCESO A ROOT
 3  [Host] Intento de login SSH FALLIDO
 4  [Dirtyland] Ordenes tecleadas (comandos-watch)
 5  [Dirtyland] Ordenes vistas por auditd
 6  [Dirtyland] Cortacircuitos SALTADO
 7  [Dirtyland] Cortacircuitos rearmado
 8  [Dirtyland] Cuota superada
 9  [Dirtyland] Cuota restablecida
10  [Dirtyland] IP's baneadas (parte diario)
11  [Dirtyland] Resumen diario (datos reales de la maquina)
12  [Dirtyland] Tabla de paises: no se pudo regenerar
13  [Dirtyland] Tabla de paises: los datos llegaron incompletos
14  [Proxy] Inactivo al arrancar (primera pasada)
15  [Proxy] Un relay se cae
16  [Proxy] Y vuelve
17  [Proxy] Un relay desaparece de la lista de Mullvad
18  [Proxy] Queda uno solo: acceso sin respaldo
19  [Proxy] SIN ACCESO: se caen todos
20  [Dionaea] Nuevas conexiones de ataque + malware capturado
21  [Dionaea] Vivo pero mudo (sin anotar nada)
22  [Dionaea] Vuelve a anotar conexiones

23  [Cowrie via SSH] Login correcto + ACTOR NUEVO con sus ordenes
24  [Cowrie] MUESTRA NUEVA (fichero vacio, e3b0c442...b855)
25  [Cowrie via Telnet] Login correcto
</pre>

Los tres últimos son **del señuelo**, y no los compone ningún vigilante del anfitrión: los compone el plugin que vive dentro de Cowrie, y ese solo habla cuando hay una sesión. Así que a esos no se les falsea la entrada (se entra de verdad, se teclea y se sube un fichero), y al móvil llegan así:

<pre>
[Cowrie vía SSH]     Event: cowrie.login.success
[Cowrie vía SSH]     ACTOR NUEVO / GUION NUEVO   (con los comandos, a los 30 s)
[Cowrie]             MUESTRA NUEVA  SHA256: e3b0c442...b855
[Cowrie vía Telnet]  Event: cowrie.login.success
</pre>

Al móvil llegan <b>algo más de veinticinco mensajes</b>, porque hay pasos que disparan varios y es lo que pasaría de verdad: el 19 manda un "caído" por cada relay y el "SIN ACCESO" que los resume, y el 4 manda una tanda por cada usuario que estuviera tecleando.

Si alguno no aparece, el que falla es su vigilante y hay que mirarlo **antes** de exponer. La terminal va diciendo por cuál va, así que el que falta se identifica solo.

Un `send-alert.sh hola` solo probaría el token. Aquí cada aviso lo compone el código de verdad, con datos de mentira, así que lo que llega al móvil es exactamente lo que llegará el día que pase.

Y no toca nada de producción. Todos los vigilantes admiten por variable de entorno dónde está su estado y de dónde leen, y el ensayo los apunta a un directorio temporal que se borra al salir: ningún contador avanza, ninguna IP queda marcada como avisada. El único que corre con datos reales es el resumen diario.

Los relays tampoco van escritos: los seis avisos del proxy salen de leer `proxys.conf`, que es de donde los lee el vigilante, y la bandera se deduce de las dos primeras letras del nombre del relay.

Y si solo se quiere repetir uno (porque ha fallado, o porque se acaba de tocar ese vigilante), se pide por su número:

```bash
sudo /opt/dirtyland/monitor/probar-avisos.sh --solo 14
```

> [!WARNING]
> <b>Esto sí deja rastro, a diferencia de los veintidós anteriores.</b> Aquellos se montan en un directorio temporal y no tocan nada; estos son sesiones de verdad contra el señuelo, así que quedan en la base de Cowrie, en el registro de órdenes y en `downloads/`, y saldrán luego en el informe de análisis. Por eso van detrás de su propia opción.

Tres detalles de esta tanda. El fichero que se sube es el <b>fichero vacío</b>, cuyo SHA-256 es `e3b0c442...b855`: un hash real, inofensivo y que existe en VirusTotal, así que el enlace del aviso se puede seguir hasta el final. Van dos descargas a propósito, porque Dionaea solo apunta el MD5 en su base y hace falta ver las dos formas del mensaje. Y el ensayo escribe en la base de Dionaea, así que deja filas de mentira que el resumen del día siguiente contaría.

El botón "Block IP" se prueba aparte, en el momento: llega dentro del resumen diario, se pulsa desde el móvil y debe contestar `🚫 BLOCKED` en el mismo mensaje. Eso recorre el camino entero, el plugin, la cola, el `sudo` del anfitrión y `nft`, y esa pulsación viene de tu dedo, así que no hay script que la ensaye.

Dos avisos de Cowrie no salen en este ensayo, y no es cuestión de esperar más: el baneo automático y el resumen de lo silenciado no pueden salir de aquí, porque los compone el plugin dentro del contenedor y dependen de tráfico real acumulado. Se ven en el 3.8.2, cuando ya hay quien los provoque.

Los dos llegan solos en cuanto el señuelo lleve un rato expuesto. Si no quieres esperar a las doscientas repeticiones del baneo ni a la media hora del resumen, los umbrales se leen del entorno y se pueden bajar los primeros días en el `docker-compose.yml`:

```
    environment:
      - TZ=Europe/Kyiv
      - AUTOBAN_REPETICIONES=20
      - DIGEST_INTERVAL=300
```

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d cowrie
```

Cuando los hayas visto se quitan las dos líneas y se vuelve a levantar igual. En producción los valores buenos son los de fábrica.

### 3.7.2 Los servicios de vigilancia están activos.

```bash
sudo systemctl status dirtyland-sshwatch.service --no-pager
sudo systemctl status dirtyland-cmdwatch.service --no-pager
sudo systemctl status cron --no-pager
sudo crontab -l | grep -v -e '^#' -e '^$'
```
<i>He puesto un `grep -v` para quitar los comentarios: si el crontab de root se abrió alguna vez con `crontab -e`, trae una cabecera de 23 líneas.</i>

Los tres deben mostrar: 
- `active (running)` y `enabled; preset: enabled`.
- Y que el registro de órdenes está puesto: `/etc/profile.d/dirtyland-registro.sh` debe existir con modo `644`, **y `grep -c dirtyland-registro /etc/bash.bashrc` debe dar `1`**. Sin el primero, `dirtyland-cmdwatch` corre vigilando un canal vacío. Sin el segundo, se pierde todo lo que se teclee en un shell de root abierto con `sudo su`.
- `sudo crontab -l` debe mostrar <b>cinco</b> líneas. Van con `sudo` porque ahí se instalaron en el 3.4.4: el crontab de tu usuario está vacío y `crontab -l` a secas responde "no crontab for user", que parece que falta todo y no falta nada.

| Tarea | Línea | Si falta |
|---|---|---|
| Resumen diario | `0 6 * * * /opt/dirtyland/monitor/daily-digest.sh` | |
| Vigilancia de Dionaea | `*/5 * * * * /opt/dirtyland/monitor/dionaea-watch.sh` | Los ataques por SMB, RPC y MSSQL no se notifican: Dionaea no tiene plugin de alertas como Cowrie |
| IPs baneadas | `0 6 * * * /opt/dirtyland/monitor/baneadas-diario.sh` | |
| Proxys de acceso | `*/30 * * * * /opt/dirtyland/monitor/proxy-watch.sh` | El día que Mullvad tire un relay te enteras cuando no puedas entrar |
| Tabla de países | `0 4 1,16 * * /opt/dirtyland/geoip/generar-tabla-paises.py --avisar` | Las banderas de las alertas se van quedando desfasadas sin que nada lo diga |

### 3.7.3 Los contenedores están arriba y sanos.

```bash
sudo docker ps
```

Deben aparecer los dos (`dirtyland_cowrie` y `dirtyland_dionaea`) en estado `Up`, y ninguno en `Restarting` (que indicaría que algo falla en bucle).

Comprobamos también que Cowrie cargó sus dos motores de salida y que no hay errores de carga del sistema de ficheros:

```bash
sudo docker logs dirtyland_cowrie --tail 20
```

### 3.7.4 Saber exactamente qué estamos exponiendo.

Esta es la comprobación más importante de todas: <b>qué escucha, en qué puerto y en qué IP</b>.

```bash
sudo ss -tulnp
```

Lo que debe salir, y nada más:

| IP | Puerto | Servicio | Quién es |
|---|---|---|---|
| `[IP VPS]` | 22 | SSH | Cowrie (señuelo Linux) |
| `[IP VPS]` | 23 | Telnet | Cowrie (señuelo Linux) |
| `[IP VPS 2]` | 135 | RPC | Dionaea (señuelo Windows) |
| `[IP VPS 2]` | 445 | SMB | Dionaea (señuelo Windows) |
| `[IP VPS 2]` | 1433 | MSSQL | Dionaea (señuelo Windows) |
| `0.0.0.0` | 56769 | SSH | <b>Nuestra administración real</b> |

> [!WARNING]
> Si aparece <b>cualquier otro puerto</b> escuchando que no esté en esa lista, hay que averiguar qué es antes de exponer nada.

Al estar sobre una VPS aparece un puerto extra: el <b>5355</b>, TCP y UDP, que es LLMNR de `systemd-resolved`. Escucha en todas las interfaces, pero el cortafuegos no lo deja entrar desde fuera y es tráfico de descubrimiento de la red local, no un servicio nuestro.

El listado de `ss` muestra lo que escucha en el <b>host</b>. Los puertos de los señuelos (22 y 23 en Cowrie; 135, 445 y 1433 en Dionaea) no aparecen ahí, porque con `"userland-proxy": false` no hay proceso que los ocupe: se resuelven con DNAT, y se comprueban en la tabla `nat` del apartado siguiente.

### 3.7.5 El docker-compose definitivo.

Aquí no se vuelve a escribir el fichero: se **comprueba**. Salió de la parte 1 del repositorio y su bloque `volumes` lo generó el guion del 3.4.2.9, así que lo que toca es confirmar que lo que hay montado es lo que debería.

Lo primero, que la sintaxis sea válida:

```bash
cd /opt/dirtyland && sudo docker compose config >/dev/null && echo "compose OK"
```

Lo que hay que mirar son las tres cosas que se pueden haber quedado atrás. **Qué puertos publica**:

```bash
cd /opt/dirtyland && sudo docker compose config --format json | python3 -c "import json,sys; [print(f\"{s}: {[p['published'] for p in v.get('ports',[])]}\") for s,v in json.load(sys.stdin)['services'].items()]"
```

<pre>
cowrie: ['22', '23']
dionaea: ['445', '135', '1433']
</pre>

Si en `cowrie` no aparece el `23`, el señuelo ofrece telnet de puertas adentro pero nadie puede llegar, y ningún log lo dice (ver el punto 4 del apartado 3.4.2.10).

**Cuántos módulos de comandos monta**, que tienen que ser los mismos que hay en `cmdpatch`:

```bash
echo "en cmdpatch: $(ls /opt/dirtyland/cowrie/cmdpatch/*.py | wc -l)   montados: $(sudo grep -c 'cmdpatch/.*\.py:' /opt/dirtyland/docker-compose.yml)"
```

Los dos números tienen que ser iguales. Si el segundo es menor, hay un comando que existe en el host y que el contenedor no está usando: se corrige volviendo a lanzar el generador del 3.4.2.9 con `--apply`, no editando el fichero a mano.

**Y que la zona horaria va por duplicado**, la variable y el montaje:

```bash
sudo grep -E 'TZ=|/etc/localtime' /opt/dirtyland/docker-compose.yml
```

<pre>
      - TZ=Europe/Kyiv
      - /etc/localtime:/etc/localtime:ro
</pre>

### 3.7.6 Las reglas de cortafuegos siguen intactas.

```bash
sudo nft list ruleset
```

Los contadores de `packets` y `bytes` cambian en cada consulta; lo que importa es la <b>estructura</b>. Salen más tablas de las que escribimos nosotros, porque Docker crea las suyas al arrancar, y eso es normal.

- <b>`table ip nat`, cadena `DOCKER`.</b> El DNAT, con cada señuelo atado a su IP: `[IP VPS]` a `172.20.0.10` y `[IP VPS 2]` a `172.20.0.20`. Ya funciona.
- <b>`table ip filter`, cadena `DOCKER`.</b> Docker ya acepta el tráfico entrante a los cinco puertos. Por su lado, los señuelos serían alcanzables.
- <b>`table inet filter`, cadena `forward`.</b> La nuestra, en `policy drop` y sin reglas de entrada. Las dos tablas se evalúan, así que basta con que una descarte el paquete: Docker dice que sí, nosotros que no, y gana el no.
- <b>`table ip raw`.</b> Descarta el tráfico dirigido a `172.20.0.10` y `172.20.0.20` que no venga por el puente, para que nadie esquive el DNAT.

Esa es la pieza que cambia el apartado <b>3.8.2</b>: la parte 4 añade las reglas de entrada que faltan. Hasta entonces el señuelo sigue sellado.

Tienen que salir las cuatro tablas de arriba, con la `forward` de `inet filter` en `policy drop` y sin reglas de entrada.

Y lo más importante, que el cortafuegos sobreviva a un reinicio. Para comprobarlo:

```bash
sudo systemctl is-enabled nftables
```

### 3.7.7 Confirmación final: seguimos sellados.

La prueba definitiva: intentar entrar <b>desde fuera</b>, desde una máquina que no sea la VPS.

```bash
IP1=[IP VPS]; IP2=[IP VPS 2]; for par in "$IP1 22" "$IP1 23" "$IP2 135" "$IP2 445" "$IP2 1433"; do nc -vz -w 3 $par; done
```

Y lo mismo desde PowerShell, el comando del 3.4.1:

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

Los cinco tienen que dar `timed out` (o `cerrado o filtrado`, si lo has hecho desde PowerShell). Si alguno conectara, es que ya estaríamos expuestos sin saberlo.

> [!IMPORTANT]
> Esta prueba hay que hacerla <b>dos veces</b>: una <b>con la VPN de administración conectada</b> (nuestra IP de Mullvad, la única que el firewall permite en el puerto 56769) y otra <b>con la VPN apagada</b> (simulando a un atacante cualquiera de Internet). En ambos casos los cinco puertos de los señuelos deben dar `timed out`. La única excepción legítima es el puerto de administración 56769, que <b>solo</b> debe responder con la VPN conectada y desde nuestra IP.

Durante las pruebas puede que un `tcpdump` enseñe paquetes entrantes reales de escáneres automáticos tocando nuestras IPs. Es ruido de fondo de Internet y no significa que el señuelo esté expuesto: el cortafuegos los está descartando, que es justo lo que se está comprobando.

### 3.7.8 Los reportes automáticos están listos (pero en espera).

Confirmamos que el reporter está montado y que su escudo funciona, aunque todavía sin API keys (se ponen justo antes de exponer):

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

Debe salir con código 3 y quejarse solo de las `api_key`, que se ponen en el 3.8.1 (la lista de bloqueo cubre nuestras IPs, la barrera bloquea lo que debe y deja pasar lo que debe). Y que el cron lo tiene programado:

```bash
grep -r reporter /etc/cron.d/
```

Las API keys son lo <b>último</b> antes de exponer: mientras el señuelo siga sellado, no hay nada que reportar. Se añaden al `config.ini` en el 3.8.1.

### 3.7.9 Última recomendación antes del paso final.

Antes de exponer, conviene hacer un <b>snapshot</b> de la VPS desde el panel del proveedor, si es que acaso nos lo ofrece. Si algo saliera mal tras la exposición, podríamos volver a este estado exacto (verificado y sellado) sin rehacer el trabajo.

> [!CAUTION]
> Superadas todas estas comprobaciones, el siguiente apartado es la <b>exposición real a Internet</b>. A partir de ese momento cualquier atacante del planeta puede alcanzar nuestros señuelos, y la reputación de ambas IPs empieza a consumirse. Es un paso deliberado e irreversible en ese sentido.

### 3.7.10 Las treinta y cuatro suites, de una vez.

A lo largo de la guía cada apartado ejecuta las suyas: las de Telegram en el 3.4.2.7 y las del reporter en el 3.5.5.2. Esto es el repaso completo, **antes de exponer**, y sirve además para cuando se ha tocado algo y no se recuerda a qué apartado pertenecía.

No necesitan claves, ni red, ni que el señuelo esté levantado: sustituyen las llamadas HTTP por un doble y trabajan sobre directorios temporales. Se ejecutan desde el árbol del repositorio, porque algunas leen el fichero que prueban por ruta relativa:

```bash
cd /tmp/dirtyland-repo && find . -path ./.git -prune -o \( -name 'test_*.py' -o -name 'test*.sh' \) -print0 | sort -z | while IFS= read -r -d '' t; do printf '%-30s ' "$(basename "$t")"; case "$t" in *.py) python3 "$t" 2>/dev/null | tail -1 ;; *) bash "$t" 2>&1 | tail -1 ;; esac; done
```

<pre>
test-acceder-ssh.sh            ok: 11   fallos: 0
test_comandos.py               ok: 970  fallos: 0
test_que_hizo_esta_ip.py       ok: 148  fallos: 0
test_gates.py                  test_gates: 382 correctas, 0 fallidas
...                            (34 en total)
</pre>

Y si solo se quiere el veredicto, sin recorrer las treinta y cuatro:

```bash
cd /tmp/dirtyland-repo && fallos=0; total=0; while IFS= read -r -d '' t; do total=$((total+1)); case "$t" in *.py) python3 "$t" >/dev/null 2>&1 ;; *) bash "$t" >/dev/null 2>&1 ;; esac || fallos=$((fallos+1)); done < <(find . -path ./.git -prune -o \( -name 'test_*.py' -o -name 'test*.sh' \) -print0); echo "suites: $total   con fallos: $fallos"
```

<pre>
suites: 34   con fallos: 0
</pre>

Qué protege cada una, para saber qué se ha roto cuando una falle:

| Suite | Vigila |
|---|---|
| `test-acceder-ssh.sh` | Que el ayudante de acceso entre **sin teclear nada**: el `ssh` de la prueba es de mentira y ejecuta el `SSH_ASKPASS` de verdad, así que se comprueba la contraseña que recibe, que el `userdb` real manda sobre la copia del guion, que el ayudante no lleva el secreto dentro y que no queda en el disco |
| `test_parche_protocol.py` | El modo contraseña del terminal. Pulsa una a una las once teclas de edición dentro de un `[sudo] password for ...` y comprueba que **no le llega nada** al terminal (el borrado se comía el prompt, las flechas pintaban el historial y `Ctrl-L` repintaba la contraseña en claro) y que fuera del modo contraseña todas siguen haciendo lo de siempre |
| `test_sanitize_pickle.py` | El saneador del sistema de ficheros: la leyenda, los `/etc` de serie, la coherencia de telnet en sus dos mitades, la zona horaria, los destinos de los enlaces, el `/etc/mtab` que apuntaba al PID del contenedor de construcción y ese mismo PID dentro de `/proc` |
| `test-vigilancia-host.sh` | El registro de órdenes del anfitrión y el silenciador: que una orden con `pwd=` escrito dentro no pueda elegir qué directorio aparece en la alerta, que el silenciador calle cuando debe y deje pasar el resumen diario, y que un aviso sin cuerpo se envíe igual |
| `test_comandos.py` | Los módulos de comandos y <b>la coherencia de la leyenda entre ficheros distintos</b>: que `lsblk`, `df`, `/proc/mounts`, `/etc/fstab` y el `dmesg` enlatado describan el mismo disco, que el `dmesg` use el kernel del `/proc/version` y la MAC del `ifconfig`, y que los enlatados caigan en `usr/bin/` y no en `bin/`, que es donde no se disparan |
| `test_gates.py` | Las puertas del reporter, una a una, los **dos vetos de política** de MalwareBazaar, y que las denuncias de AbuseIPDB digan la verdad: el puerto público y no el interno, y ninguna categoría que la evidencia no sostenga |
| `test_end_to_end.py` | Que en simulación no sale ni una publicación a la red, y que una configuración correcta pasa el `--self-test` |
| `test_botones_cowrie.py` | Los botones de baneo del bot y las etiquetas de transporte (`vía SSH` / `vía Telnet`) y que la cabecera no vuelva a llevar el `sensor` |
| `test_memoria_cowrie.py` | Lo que el plugin recuerda y lo que cuenta. **La memoria por IP**, que decide cuándo callar: que un guion repetido avise una vez y no una por sesión, y que al recortar la memoria deje de afirmar que no hay nada nuevo, porque sobre una memoria incompleta no se distingue "nunca lo hizo" de "se me olvidó" |
| `test_repetidas_dionaea.py` | **La memoria que impide que Dionaea repita el mismo aviso cada cinco minutos.** Las dos funciones se extraen del script que se despliega y se ejecutan con `bash` de verdad, no reescritas en Python, que entonces la prueba comprobaría otra cosa |
| `test_telnet_opciones.py` | La negociación de telnet, la que tumbaba todas las sesiones |
| `test_que_hizo_esta_ip.py` | La ficha de una IP, sobre un señuelo sintético con dos IPs en el mismo log. Sobre todo que <b>no se cuele nadie más</b>, porque una ficha que mezcla dos atacantes no es un error de formato, es una denuncia mal hecha: caza los tres sitios por donde se colaría, incluida una clave parecida que el `LIKE` de SQL casa. Y las dos cosas de las que depende el cifrado: que el tar no se abra sin la clave y que no quede un `.tar.gz` en claro |
| `test_que_le_falta.py` | El censo de lo que el señuelo dice tener y no sabe ejecutar. Sobre todo que <b>un comando emulado nunca salga como que falta</b>, que es lo que pasaba leyendo el catálogo del `cmdpatch` en vez de preguntárselo al contenedor |
| `test_paises.py` | La banderita de cada IP. Sobre todo que <b>no pueda tumbar un aviso</b>: que una tabla que falta, que está a medias o que no se entiende devuelva vacío en vez de reventar, o peor, en vez de devolver dos caracteres cualesquiera con pinta de país. Además los bordes de cada tramo, y que la tabla esté ordenada, que de eso vive la búsqueda binaria |
| `test_cortar_el_grifo.py` | Que conmutar el cron deja **siempre una sola línea activa**, en los dos sentidos |
| `test_que_pasa_con_las_plataformas.py` | Los dos contadores del día del informe por plataforma, que son los que se miran para saber si algo va mal: que cuenten lo de hoy y no lo de siempre, que una simulación no cuente como publicada, y que el motivo que escriben sea el de verdad y no uno genérico |
| `test_voy_al_dia.py` | Que el comparador de despliegues diga la verdad en los tres estados y que se niegue a dar por buena una copia traída a mano, cuyo sello llega sin sustituir. Y las tres que vigilan que el README no se quede viejo: que la lista de suites esté completa, que <b>todo fichero que el README manda copiar exista de verdad</b> y que siga mandando cargar el registro de órdenes desde `/etc/bash.bashrc` |
| `test-digest-modo.sh` | El apartado de reporters del resumen diario, entero: que el cron manda sobre el color, las cuatro líneas de `[MOTIVO: ...]`, y que las cuentas sean de 24 horas y no de la última pasada de quince minutos |
| `test-lib-telegram.sh` | El envío, el troceado de mensajes y el escapado de HTML |
| `test-ssh-watch.sh` | El vigilante de accesos al anfitrión |
| `test-breaker-watch.sh` | El cortacircuitos de la cuenta de abuse.ch |
| `test-cuota-watch.sh` | El vigilante de la cuota diaria: que avise al agotarse el cupo y solo entonces, que no repita mientras siga agotado, que al cambiar el día cuente como transición nueva, y que mire `api_calls` y no `quota`, porque la primera cuenta llamadas, que es contra lo que compara el limitador |
| `test-proxy-watch.sh` | El vigilante de los proxys SOCKS, con la API de Mullvad simulada: que avise al caer un relay y al volver, que calle mientras nada cambie, y que una respuesta rara de la API no lo deje mudo para siempre |
| `test-probar-avisos.sh` | El ensayo de los veintidós avisos del anfitrión del 3.7.1.1, en seco: que <b>todos</b> siguen saliendo y con la cabecera que escribe cada vigilante, de modo que si alguien renombra un aviso y no toca la guía esto se pone rojo; que en seco no se manda nada a Telegram y ningún estado de producción se toca; y que con una ventana de silencio abierta el ensayo no arranca |
| `test_analisis.py` | El informe de inteligencia de `ANALISIS/analisis.py` sobre un respaldo <b>sintético</b>, porque no se pueden subir capturas reales al repositorio: que los guiones se agrupen (doce IPs con el mismo guion son un actor, no doce), que la hora de Cowrie se corrija igual que en el recolector, que lo ilegible se diga en vez de salir como un cero, y que el informe no pueda acabar en un commit |
| `test-enlaces-malware.sh` | Los enlaces a VirusTotal y MalwareBazaar de las alertas |
| `test_parche_mssql.py` | El bucle de Dionaea que colgaba el señuelo. No comprueba que un texto se sustituya por otro: **ejecuta el bucle**, antes y después del parche, con el fragmento copiado letra por letra del `mssql.py` de la imagen fijada por digest, y comprueba que uno no termina nunca y el otro sí. Y que el parche **se niegue a aplicarse** si ese fichero cambia |
| `test-montajes-dionaea.sh` | Que añadir un montaje al `docker-compose` no tuerza el YAML, porque un compose torcido sigue siendo YAML válido y sin ese montaje Dionaea vuelve a colgarse con el primer paquete MSSQL malformado. Hay dos `docker` de mentira, uno que valida y otro que rechaza siempre, porque una vuelta atrás que nunca se ha probado es una que no se sabe si existe |
| `test-dionaea-mudo.sh` | El vigilante de "Dionaea vivo pero mudo", el control que ya falló dos veces en una semana: cinco días sin anotar una sola conexión mientras `docker ps` decía `Up`, el proceso existía y el DNAT contaba paquetes. Comprueba que el aviso salga **a las 2 h**, no al día siguiente. Necesita el binario `sqlite3` |
| `test-registro-comandos.sh` | Que se registre lo que teclea una persona en el anfitrión, y sobre todo la **cobertura**: un shell de root abierto con `sudo su` no anotaba nada (`/etc/profile.d` solo lo leen los shells de *login*, y con `sudo -i` sí funcionaba, así que el fallo dependía de cómo te hicieras root). Arranca un `bash` de verdad de cada tipo y le teclea órdenes |
| `test_auditd_watch.py` | La lectura del log de `auditd`, contra una **muestra real** de la VPS y no escrita a mano: los campos interpretados que se pegan al anterior sin espacio, los argumentos en hexadecimal y un evento repartido en varias líneas unidas por su número de serie |
| `test-cron-dirtyland.sh` | Que las tareas periódicas se pongan **sin `nano` y sin duplicar**. Este paso era el único del despliegue que no era copiar y pegar |
| `test-baneadas-diario.sh` | El listado de IPs bloqueadas y de dónde vino cada baneo, contra la forma **real** de un `nft list set`: elementos separados por comas, repartidos en varias líneas y con su comentario detrás |
| `test-banear-dos-veces.sh` | Pulsar el botón de baneo de un aviso cuya IP ya está baneada. `nftables` se queja al añadir un elemento que ya existe y con `set -e` tumbaba el guion, así que el botón daba error en un caso que no lo es: el resultado que se buscaba ya está |

Dos necesitan el binario `sqlite3` (`test-dionaea-mudo.sh` y `test-digest-modo.sh`). En la VPS está; en otra máquina hay que instalarlo o esas dos se saltan solas diciéndolo.

Que las treinta y cuatro estén en verde **no dice que el señuelo esté bien**: dicen que la lógica que se puede probar sin Internet se comporta como se espera. Lo que el señuelo parece desde fuera se mide en el 3.8.2.

### 3.7.11 Antes de formatear o mudar la máquina: qué hay que salvar.

Casi todo lo de esta guía se **regenera**: el pickle, el honeyfs, los módulos, el `docker-compose`, las reglas del cortafuegos. Todo eso sale del repositorio y de un `docker build`. Pero hay cosas que **no se regeneran** porque son el resultado de haber estado escuchando, y esas se pierden con el disco.

> [!CAUTION]
> <b>La base de estado sola no sirve de nada.</b> La tabla `samples` guarda la **ruta** al binario, no el binario. Si salvas `state.sqlite3` y no los volúmenes de Docker, la cola de muestras pendientes apunta a ficheros que ya no existen. Hay que salvar las dos cosas.

Qué hay, y qué se pierde con cada cosa:

| Qué | Dónde | Qué te llevas si se pierde |
|---|---|---|
| Estado del reporter | `/var/lib/dirtyland-reporter/state.sqlite3` | qué se denunció y se subió ya, la **cola de muestras esperando veredicto**, las cuotas del día, el cortacircuitos y los rechazos |
| **Malware de Cowrie** | volumen `dirtyland_cowrie-var` -> `_data/lib/cowrie/downloads` | los binarios capturados |
| Log de sesiones | mismo volumen -> `_data/log/cowrie/cowrie.json*` | la evidencia de todo lo que ha pasado |
| **Malware de Dionaea** | volumen `dirtyland_dionaea-var` -> `_data/lib/dionaea/binaries` | los binarios de SMB |
| Eventos de Dionaea | mismo volumen -> `dionaea.sqlite` | su registro |
| Memoria del bot | `/opt/dirtyland/Telegram Reports/state/` | los guiones ya vistos y la lista de baneados |
| Claves de host SSH | `/opt/dirtyland/cowrie/keys/` | la **huella** del señuelo, que cambiaría |
| Secretos | `config.ini`, `telegram.cfg`, `telegram.env` | las claves de API y los tokens |
| Reglas del cortafuegos | volcado de `nft list ruleset` | **quién ordenó cada baneo**: automático o a mano |

<b>1. Parar la pila.</b> Con las bases de datos escribiendo, una copia en caliente puede salir a medias:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml down
```

> [!WARNING]
> `down` a secas. **Nunca `down -v`**: esa opción borra los volúmenes con nombre, o sea justo el malware y los logs que estás intentando salvar.

<b>2. Volcar las reglas del cortafuegos.</b> Las de nftables viven en el kernel, no en un fichero, así que si no se vuelcan se pierden al formatear.

```bash
sudo sh -c 'nft list ruleset > /opt/dirtyland/monitor/nftables-ruleset.txt' && sudo chmod 600 /opt/dirtyland/monitor/nftables-ruleset.txt && sudo grep -c BANEADA /opt/dirtyland/monitor/nftables-ruleset.txt
```

Ese recuento es el número de IPs baneadas con comentario; si sale `0` es que el volcado salió vacío y no tiene sentido seguir.

> [!NOTE]
> **`sudo nft list ruleset > fichero` no vale**: la redirección la hace **tu** shell, que no es root, así que el fichero se intenta crear sin permisos y en un directorio de root falla. Por eso va todo dentro de `sudo sh -c '...'`.

<b>3. Empaquetarlo, comprimirlo y cifrarlo de una tirada, con barra de progreso.</b> Los volúmenes y las rutas de `/opt` van en el mismo archivo, para que la copia sea una sola cosa y no tres que hay que casar después.

El respaldo son varios GB y `gzip` va a un solo núcleo, así que esto tarda. Este script mide el total, enseña la barra con su porcentaje y su tiempo restante, usa `pigz` (gzip en paralelo) si está, y **no deja ningún `.tar.gz` sin cifrar en el disco**. Se pega tal cual para crearlo:

```bash
cat > ~/respaldo.sh <<'EOF'
#!/bin/bash
# Empaqueta + comprime + CIFRA el respaldo en una sola tuberia, con barra.
# La pila tiene que estar ya parada (pasos 1 y 2 de arriba).
set -e
FECHA=$(date +%F)
OUT=~/dirtyland-respaldo-$FECHA.tar.gz.enc
RUTAS=(
  var/lib/dirtyland-reporter
  var/lib/docker/volumes/dirtyland_cowrie-var
  var/lib/docker/volumes/dirtyland_dionaea-var
  "opt/dirtyland/Telegram Reports/state"
  "opt/dirtyland/Telegram Reports/telegram.cfg"
  opt/dirtyland/cowrie/keys
  opt/dirtyland/platform-reporter/config.ini
  opt/dirtyland/monitor/telegram.env
  opt/dirtyland/monitor/nftables-ruleset.txt
)
command -v pv   >/dev/null || sudo apt-get install -y pv
command -v pigz >/dev/null && GZ=pigz || GZ=gzip
# tamano total, para que la barra tenga porcentaje. Se prefija "/" con un
# bucle: el atajo ${RUTAS[@]/#//} deja las rutas SIN barra y du no las
# encuentra, asi que la barra sale sin total.
ABS=(); for r in "${RUTAS[@]}"; do ABS+=("/$r"); done
TOTAL=$(sudo du -sbc "${ABS[@]}" 2>/dev/null | tail -1 | cut -f1)
sudo tar -cf - -C / "${RUTAS[@]}" \
  | pv -s "$TOTAL" \
  | $GZ \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -k 1234 -out "$OUT"
chmod 600 "$OUT"
ls -lh "$OUT"
EOF
```

Y se ejecuta:

```bash
bash ~/respaldo.sh
```

Se comprueba que dentro está lo que tiene que estar (descifrando y listando, que un archivo a medias se nota aquí):

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in ~/dirtyland-respaldo-*.tar.gz.enc -k 1234 | tar -tzf - | grep -cE 'downloads/|binaries/|state.sqlite3'
```

> [!CAUTION]
> El cifrado con contraseña "1234" no busca confidencialidad, sino que el Windows Defender no lo detecte (y si usas Linux, da igual). Cualquier otro comprimido lo revisa, ya que busca y lee firmas/hashes.

`tar` va a avisar de que un fichero cambió mientras lo leía, y es normal: el señuelo estuvo escuchando hasta hace un momento y `cowrie.json` pudo crecer entre que `tar` lo abrió y lo terminó. Sale con código 1, que es "aviso", no "error": el archivo está completo y se puede restaurar.

<b>4. Levantar la pila otra vez y sacar el cifrado</b>, desde tu equipo y con la VPN levantada.

Ya está el respaldo hecho, así que **se vuelve a levantar el señuelo** para que no pierda más tiempo caído (esto solo si NO vas a formatear ahora mismo; si vas a formatear a continuación, sáltatelo):

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```

El script dejó el `.enc` en tu propio `home` y ya es tuyo, así que se baja directo. <b>Desde tu equipo</b> (vale igual en PowerShell y en Linux; `scp` usa el mismo `~/.ssh/config` del 3.2.6, así que si un relay del proxy está caído se cambia al alias de uno de los respaldos):

```bash
scp dirtyland:~/dirtyland-respaldo-*.tar.gz.enc .
```

Cuando lo tengas bajado, se borra la copia del `home` para no dejar el malware (aunque cifrado) al alcance del usuario normal. <b>En la VPS</b>:

```bash
shred -u ~/dirtyland-respaldo-*.tar.gz.enc && echo "copia borrada de la VPS"
```

<b>5. Al restaurar</b>, sobre la máquina nueva: se sigue la guía hasta tener la pila levantada una vez (para que Docker cree los volúmenes con su nombre) y **entonces** se para, se restaura encima y se vuelve a levantar:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml down
```

Se descifra y se extrae en una sola tubería (el fichero cifrado se sube antes a la máquina nueva, p. ej. a `~`):

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in ~/dirtyland-respaldo-FECHA.tar.gz.enc -k 1234 | sudo tar -xzf - -C /
```

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```

Y lo primero que hay que mirar después, porque es lo que dice si la cola sobrevivió:

```bash
sudo python3 -c "import sqlite3
for r in sqlite3.connect('/var/lib/dirtyland-reporter/state.sqlite3').execute('SELECT state, COUNT(*) FROM samples GROUP BY state'): print(r[0], r[1])"
```

Si decides **no restaurar** y empezar de cero, no pasa nada grave, pero implica esto: las IPs ya denunciadas se volverían a denunciar, y las muestras ya subidas se reintentarían para que las plataformas las rechacen por duplicadas. No es un baneo, pero es ruido evitable.

## 3.8 Exposición.

Hasta aquí todo el trabajo se ha hecho con el señuelo sellado. Este apartado es el que lo abre a Internet, y son solo dos pasos: poner las API keys y aplicar la parte 4 del cortafuegos. En ese orden, porque las claves no tienen ningún riesgo con la máquina cerrada y el cortafuegos sí es el punto de no retorno.

> [!CAUTION]
> A partir del 3.8.2 cualquiera puede alcanzar los dos señuelos. La reputación de ambas IPs empieza a consumirse y el reporte automático empieza a tener material del que hablar. Si algo no ha quedado verificado en el 3.7, hay que volver ahora.

### 3.8.1 API keys de los reportes.

Es el último cambio en la configuración del reporter, y el que estaba pendiente desde el 3.5.5.1:

```bash
sudo nano /opt/dirtyland/platform-reporter/config.ini
```

Están todas juntas en `[api_keys]`, al principio del fichero, y es lo <b>único</b> que queda por rellenar. Se sustituyen los tres marcadores por las claves reales:

```ini
[api_keys]
virustotal = <CLAVE-API-VIRUSTOTAL>
abusech    = <CLAVE-API-ABUSECH>
abuseipdb  = <CLAVE-API-ABUSEIPDB>
```

Tres claves y no cinco: <b>MalwareBazaar, ThreatFox y URLhaus son la misma cuenta de abuse.ch</b> y comparten Auth-Key. Es la misma razón por la que el cortacircuitos del 3.5.5.4 cuenta los rechazos por cuenta y no por plataforma. Que estén juntas y al principio tiene una ventaja: para saber qué secretos contiene este fichero basta con mirar esa sección. Y si alguna plataforma necesitara algún día una cuenta propia, se le pone su `api_key` en su sección y esa manda sobre la de aquí.

El fichero tiene que seguir siendo ilegible para todo el que no sea `root`, porque a partir de ahora contiene secretos:

```bash
sudo stat -c '%a %U:%G %n' /opt/dirtyland/platform-reporter/config.ini
```

Debe responder exactamente `600 root:root`. Si no, el reporter se negará a arrancar, que es justo lo que queremos que haga.

Ahora el self-test tiene que salir limpio por primera vez:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

Debe terminar en `self-test: todo correcto` y con código 0. Si sigue quejándose de alguna `api_key`, es que ese marcador no se sustituyó bien.

Y una pasada en simulación, que ahora sí ejercita las claves:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini
```

Este es el primer momento en que el reporter habla con las plataformas. Con las claves puestas, la simulación **sí** hace las consultas de lectura; lo que no hace, y no hará hasta el 3.8.3, es publicar. Si alguna clave estuviera mal, aparecería aquí como un `401` en el log, y es mejor descubrirlo ahora que con tráfico real encima.

### 3.8.2 Cortafuegos final: exponer.

Este es el paso irreversible. Antes de nada, la copia de seguridad de lo que hay:

```bash
sudo cp /etc/nftables.conf /etc/nftables_3.8.2.pre.exposicion___$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```

> [!WARNING]
> Abre **una segunda sesión SSH** ahora y déjala conectada mientras haces esto. Si algo saliera mal con la cadena `input`, esa sesión abierta es lo que te permite arreglarlo; con una sola sesión y el `policy drop`, un error te deja fuera de la máquina.

La regla de la parte 4 está en la carpeta `CORTAFUEGOS` del repositorio, igual que las tres anteriores:

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

Se pega dentro el contenido de **[CORTAFUEGOS/nftables-PART-4.txt](CORTAFUEGOS/nftables-PART-4.txt)** y se revisa:

```bash
cat /etc/nftables.conf
```

Lo que cambia respecto a la parte 3 son cuatro cosas:

| Cambio | Por qué |
|---|---|
| Bloque de <b>ingress</b> en `forward` | Es lo único que expone. Hasta ahora el `policy drop` de esa cadena mataba el tráfico que llegaba por DNAT |
| Prohibido <b>contenedor a contenedor</b> | Si Cowrie cae, no debe poder tocar el 445 de Dionaea. Sin esta línea, las propias reglas de ingress se lo permitirían |
| La <b>segunda IP pública</b> en el anti pivoteo | La parte 3 solo protegía `[IP VPS]`. Un contenedor comprometido podía alcanzar `[IP VPS 2]` |
| Fuera el `tcp dport 22 accept` de `input` | Nunca hizo nada, como ya explicaba el 3.4.1, y leerlo inducía a error |

Los puertos del bloque de ingress son los del <b>contenedor</b> (2222 y 2223 de Cowrie, 135/445/1433 de Dionaea), no los publicados. Cuando el paquete llega a `forward`, el DNAT ya ha reescrito el destino: por eso ahí no se ven el 22 ni el 23.

Se comprueba la sintaxis **antes** de aplicar nada:

```bash
sudo nft -c -f /etc/nftables.conf
```

Ese comando no debe imprimir absolutamente nada. Si imprime algo, es un error de sintaxis y todavía no se ha tocado el cortafuegos vivo. Solo entonces se aplica:

```bash
sudo nft -f /etc/nftables.conf
```

Y se verifica lo que ha quedado cargado:

```bash
sudo nft list chain inet filter forward
```

Ahora, **desde tu equipo, no desde la VPS** y **con la VPN de administración conectada**, los cinco puertos deben responder. Son los mismos comandos del 3.7.7, pero con el resultado contrario: allí tenían que dar timeout, aquí tienen que conectar.

| Comando | Lo que tiene que salir |
|---|---|
| `nc -vz -w 3 [IP VPS] 22` | `Connection to [IP VPS] 22 port [tcp/ssh] succeeded!` |
| `nc -vz -w 3 [IP VPS] 23` | `Connection to [IP VPS] 23 port [tcp/telnet] succeeded!` |
| `nc -vz -w 3 [IP VPS 2] 135` | `Connection to [IP VPS 2] 135 port [tcp/epmap] succeeded!` |
| `nc -vz -w 3 [IP VPS 2] 445` | `nc: connect to [IP VPS 2] port 445 (tcp) timed out: Operation now in progress` |
| `nc -vz -w 3 [IP VPS 2] 1433` | `Connection to [IP VPS 2] 1433 port [tcp/ms-sql-s] succeeded!` |

Y en Windows, los cinco de una vez. Tienen que salir todos `ABIERTO` menos el 445, por lo que se explica justo debajo:

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

<b>Que el 445 falle desde tu equipo es lo esperado, y no es culpa de la VPS.</b> El TCP/445 saliente lo bloquean casi todas las VPN y casi todos los ISP domésticos desde los gusanos de SMB, así que el paquete muere antes de salir de tu red. Que diga `timed out` y no `connection refused` es justo la señal: un rechazo lo manda el destino, un silencio se lo come alguien por el camino.

Queda descartar la otra causa, que sí sería grave: que lo bloquee el proveedor de la VPS <b>a la entrada</b>, porque el 445 es de donde Dionaea saca más muestras. Se le pregunta a Dionaea quién ha llegado, y esto no depende de tu red:

```bash
sudo python3 -c "import sqlite3; d=sqlite3.connect('/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite'); [print(f'  puerto {p:<6} {c:>6} conexiones   {i:>5} IPs distintas') for p,c,i in d.execute(\"SELECT local_port, COUNT(*), COUNT(DISTINCT remote_host) FROM connections WHERE connection_type='accept' GROUP BY local_port ORDER BY local_port\")]"
```

<pre>
  puerto 135         7 conexiones       2 IPs distintas
  puerto 445         7 conexiones       1 IPs distintas
  puerto 1433        8 conexiones       3 IPs distintas
</pre>

Si el 445 suma conexiones, está abierto a Internet y el bloqueo es solo tuyo. Si se queda a cero mientras los otros dos suben, lo bloquea el proveedor y hay que escribirles. Dale unas horas: recién arrancado la muestra es muy corta.

Y queda una última comprobación, y de ella depende todo el reporte. Tras esas conexiones desde fuera, la IP registrada tiene que ser la tuya, no la puerta de enlace de Docker:

```bash
sudo grep -o '"src_ip": *"[^"]*"' /var/lib/docker/volumes/dirtyland_cowrie-var/_data/log/cowrie/cowrie.json | sort | uniq -c | sort -rn | head
```

Debe aparecer el nodo de salida de tu VPN. Si todo sigue saliendo como `172.20.0.1`, Docker está enmascarando el origen y **no se reportará jamás a nadie**: la barrera descartaría a todos los atacantes por no ser direcciones globales, sin dar un solo error. El reporter avisa de ello en el log, pero es mejor verlo aquí.

### 3.8.3 Pasar el reporte a modo real.

> [!IMPORTANT]
> **AQUÍ SE REPORTA YA DE VERDAD.** Todo lo anterior era simulación: el reporter leía, decidía y escribía en el log lo que *habría* enviado, <b>sin publicar nada</b>. Lo único que salía a la red eran consultas de lectura, porque sin ellas no se podrían validar las puertas de decisión, que es justo lo que se quiere mirar estos días. Aquí se le quita el freno, y a partir de la primera pasada del cron <b>se publica</b> en las cinco plataformas.
>
> **LO PUBLICADO ES PÚBLICO Y PERMANENTE, Y NO SE PUEDE RETIRAR.** Un comentario en VirusTotal o una denuncia en AbuseIPDB los va a leer gente, y acusan a una IP que pertenece a alguien. Por eso el orden importa: primero se leen unos días de simulación, y solo cuando convenza se cambia la línea del cron.

El cron sigue en simulación, y así debe seguir unos días. El sitio donde mirar es el log:

```bash
sudo tail -n 60 /var/log/dirtyland-reporter/reporter.log
```

O `tail -f` si prefieres verlo en vivo, recordando que ese se queda abierto hasta que pulses `Ctrl+C`.

Lo que se busca ahí es que lo que *se habría* enviado sea razonable: IPs de atacantes de verdad, ninguna propia, y las muestras esperando veredicto en vez de publicarse en caliente. Y los rechazos, con su motivo:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --show-rejections 30
```

Cuando el resultado convenza, y no antes, se cambia la línea del cron. Se hace con esta orden y no con un editor porque a mano uno se deja las **dos** líneas activas o **ninguna**.

```bash
sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' /etc/cron.d/dirtyland-reporter
```

Y se confirma que quedó **una sola** línea activa, con `--live`:

```bash
grep -vE '^\s*(#|$)' /etc/cron.d/dirtyland-reporter | grep malware-watch
```

<pre>
*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live
</pre>

> [!CAUTION]
> Este es el paso que empieza a publicar.

## 3.9 Fin.

Cuando hemos desplegado el honeypot y esperado el tiempo que queríamos esperar y tenemos ya una buena cosecha de hallazgos, sean binarios, IPs y demás, es turno de documentar lo obtenido.

Por suerte son 3 scripts los que nos van a ayudar.

### 3.9.1 Analisis.py

Este script:
- Saca todos los hallazgos de todas las IPs.
- Genera un informe `.html` de gran detalle y cuidado, que nos ayudará a analizar lo sucedido en el honeypot.

Para usarlo:

```bash
mkdir -p ~/datos-analisis && ln -sfn /var/lib/docker/volumes/dirtyland_cowrie-var /var/lib/docker/volumes/dirtyland_dionaea-var /var/lib/dirtyland-reporter "/opt/dirtyland/Telegram Reports/state" /opt/dirtyland/monitor ~/datos-analisis/ && sudo python3 /tmp/dirtyland-repo/ANALISIS/analisis.py --respaldo ~/datos-analisis --salida ~/analisis-senuelo-$(date +%F).html --ip-vps $(hostname -I) && sudo chown $USER: ~/analisis-senuelo-*.html
```

Para sacar los hallazgos encriptados de la máquina VPS. La contraseña es 1234 y recordemos que lo ciframos para que el Windows Defender no pite.

```bash
scp "dirtyland:~/dirtyland-respaldo-*.tar.gz.enc" .
```

Para sacar el informe generado, que se encuentra en la máquina VPS.

```bash
scp "dirtyland:~/analisis-senuelo-*.html" .
```

### 3.9.2 Solo de una IP

Este script fue diseñado con la idea de:
- Coger los hallazgos de una sola IP.
- Tener el mejor detalle posible con una sola IP sobre lo que ha hecho o no.
- El análisis que genera es un .txt, en el que incluye todos los comandos que ha ejecutado, entonces puedes coger todo eso, pegarselo al Claude y si hay algún comando que este honeypot no hace pasárselo y que Claude trabaje.

Se utiliza así para ejecutarlo:

```bash
sudo ~/que_hizo_esta_ip.py <IP>
```

No vamos a explicar como funciona porque ya viene muy bien detallado el script de como usarlo.

Para sacar el hallazgo de la máquina.<br>
<b>En Linux:</b>

```bash
scp 'dirtyland:~/ficha-*' "$(xdg-user-dir DESKTOP)"
```

<b>En Windows:</b>

```powershell
scp "dirtyland:~/ficha-*" ([Environment]::GetFolderPath('Desktop'))
```

Y ya lo tendremos en el escritorio.

### 3.9.3 el de sacar las cosas.

Este script simplemente saca los hallazgos y ya.<br>
Para usarlo:

```bash
bash ~/respaldo.sh
```

Para sacar el hallazgo de la máquina.<br>
<b>En Linux:</b>

```bash
scp 'dirtyland:~/dirtyland-respaldo-*.tar.gz.enc' "$(xdg-user-dir DESKTOP)"
```

<b>En Windows:</b>

```powershell
scp "dirtyland:~/dirtyland-respaldo-*.tar.gz.enc" ([Environment]::GetFolderPath('Desktop'))
```
