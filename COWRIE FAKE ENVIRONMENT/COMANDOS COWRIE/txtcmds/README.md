# txtcmds

Salidas enlatadas que **sustituyen** a las que Cowrie trae de fabrica. Cowrie
las busca primero aqui: es la clave `[honeypot] txtcmds_path` del `cowrie.cfg`,
y si un comando no esta, cae en la suya. La ruta dentro de esta carpeta es la
ruta del binario en el senuelo.

No son modulos de Python, asi que **no** van a `cmdpatch/` ni los recoge el
`find` de los `*.py` del apartado 3.4.2.8: se copian aparte y se montan como
directorio.

## Por que todo cuelga de `usr/bin/` y no de `bin/`

Cowrie coloca sus enlatados en `txtcmds/bin/` (ahi tiene `df`, `dmesg`,
`mount`, `sync` y `stty`). En un Debian moderno **esos cinco no se disparan
nunca**, y la consecuencia no es que mientan: es que el comando se rompe.

El motivo esta en `getCommand()` de `shell/protocol.py`. Recorre el `PATH` y se
queda con la **primera** ruta donde el fichero existe, sin resolver enlaces:

```
PATH = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

`/usr/bin` va antes que `/bin`, asi que `df` resuelve a `/usr/bin/df` y Cowrie
busca el enlatado en `txtcmds/usr/bin/df`, que no existe. Y en nuestro pickle
`/bin` es un **enlace** a `usr/bin`, asi que `/bin/df` ni siquiera es una ruta.
Al no encontrar enlatado, el shell cae al ultimo recurso y contesta:

```
$ df -h
-bash: /usr/bin/df: cannot execute binary file: Exec format error
```

Comprobado en vivo contra el pickle de produccion. Por eso lo que hay aqui
cuelga de `usr/bin/`.

## Que hay aqui y por que

| Fichero | Motivo |
|---|---|
| `usr/bin/dmesg` | El de Cowrie es el arranque de un **Debian Lenny de 2009**: kernel `2.6.26-2-686`, de 32 bits. Contradice el `uname`, el `/proc/version` y el `/proc/cpuinfo` de la leyenda a la vez. El de aqui es el arranque de la maquina que decimos ser, y cuadra con `dmidecode` (placa MSI MS-7D25, BIOS 1.80 del 09/14/2022), con `lsblk` (NVMe, dispositivo 259:2), con `/proc/meminfo` (16 GB) y con la MAC de `ifconfig`. |
| `usr/bin/stty` | El de Cowrie esta **vacio**, y ademas en `bin/`, asi que lo que salia era el `Exec format error`. |
| `usr/bin/sync` | Igual: vacio y en `bin/`. Aqui sigue vacio a proposito ---`sync` no imprime nada--- pero el fichero **tiene que existir** o el comando se rompe. |

`df`, `mount`, `getconf` y `top` tambien estaban rotos o mintiendo, pero no se
arreglan aqui: son **modulos** en `commands/`, porque un fichero enlatado no ve
los argumentos y `df` y `df -h` no dan la misma salida.

## Lo que ya no esta

`usr/bin/nano` y `usr/bin/pico` eran enlatados con un mensaje de error. Ahora
hay un `nano` emulado de verdad en `commands/nano.py`, que ademas **guarda** lo
que el atacante escribe. Un enlatado no puede hacer eso.
