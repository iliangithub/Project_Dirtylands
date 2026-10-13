# SPDX-FileCopyrightText: 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# SPDX-FileCopyrightText: 2015, 2016 GoSecure Inc.
# SPDX-FileCopyrightText: 2021-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import annotations

import struct

from twisted.conch.telnet import (
    ECHO,
    LINEMODE,
    NAWS,
    SGA,
    AuthenticatingTelnetProtocol,
    ITelnetProtocol,
)
from twisted.internet.protocol import connectionDone
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.core.credentials import UsernamePasswordIP

# NEW-ENVIRON telnet option (RFC 1572)
# Used for environment variable exchange and targeted by CVE-2026-24061
NEW_ENVIRON = bytes([39])  # 0x27

# Options negotiated (in this order) to mimic Debian netkit telnetd's opening
# IAC stream, so nmap fingerprints the service as "Linux telnetd" instead of
# matching its Cowrie softmatch (which keys on an initial lone IAC DO NAWS).
TTYPE = bytes([24])  # 0x18
TSPEED = bytes([32])  # 0x20
XDISPLOC = bytes([35])  # 0x23

# Las opciones que PEDIMOS al cliente nada mas conectar. UNA sola definicion,
# usada por los dos sitios que tienen que estar de acuerdo: el bucle de
# connectionMade que las solicita, y enableRemote, que decide si se aceptan
# cuando el cliente dice que si.
#
# Estaban escritas dos veces y habian dejado de coincidir. Eso tumbaba telnet
# entero, y conviene entender por que porque no es evidente:
#
#   connectionMade hacia doChain(TTYPE, TSPEED, XDISPLOC, NEW_ENVIRON), o sea
#   "DO TERMINAL-TYPE" y compania. El cliente contestaba "WILL TERMINAL-TYPE".
#   Twisted, para una opcion que hemos pedido NOSOTROS, entra por
#   will_no_true(), y ahi dentro hay esto:
#
#       assert self.enableRemote(option), \
#           "enableRemote must return True in this context"
#
#   Nuestro enableRemote solo decia que si a NAWS, SGA y NEW-ENVIRON; TTYPE,
#   TSPEED y XDISPLOC caian en el "else: return False". O sea que pediamos una
#   opcion y, cuando nos la concedian, la rechazabamos. Twisted tiene razon en
#   protestar: es incoherente. Y no es un fallo cosmetico --- la excepcion
#   rompe la conexion, asi que NINGUNA sesion de telnet llegaba al login.
#
# Pedir y aceptar tienen que ser la misma lista por construccion, no por que
# alguien se acuerde de tocar las dos.
OPCIONES_SOLICITADAS = (TTYPE, TSPEED, XDISPLOC, NEW_ENVIRON)

# NEW-ENVIRON subnegotiation command bytes
NEW_ENVIRON_IS = 0  # Sender is supplying value
NEW_ENVIRON_SEND = 1  # Sender requests receiver send value
NEW_ENVIRON_INFO = 2  # Sender is supplying updated value

# NEW-ENVIRON variable type bytes
NEW_ENVIRON_VAR = 0  # Well-known variable name follows
NEW_ENVIRON_VALUE = 1  # Variable value follows
NEW_ENVIRON_ESC = 2  # Escape byte for literal VAR/VALUE/USERVAR bytes in data
NEW_ENVIRON_USERVAR = 3  # User-defined variable name follows


class HoneyPotTelnetAuthProtocol(AuthenticatingTelnetProtocol):
    """
    TelnetAuthProtocol that takes care of Authentication. Once authenticated this
    protocol is replaced with HoneyPotTelnetSession.
    """

    loginPrompt = b"login: "
    passwordPrompt = b"Password: "
    windowSize: list[int]
    cve_2026_24061_user: str | None = None

    def connectionMade(self):
        self.transport.negotiationMap[NAWS] = self.telnet_NAWS
        # Initial option negotiation. Mirror Debian netkit telnetd's opening
        # sequence (DO TTYPE, TSPEED, XDISPLOC, NEW-ENVIRON) so the service
        # fingerprints as "Linux telnetd", not Cowrie. NAWS is still handled if
        # the client volunteers it (window size then defaults to 80x40).
        for opt in OPCIONES_SOLICITADAS:
            self.transport.doChain(opt).addErrback(log.err)

        # Register NEW-ENVIRON subnegotiation handler for CVE-2026-24061 detection
        self.transport.negotiationMap[NEW_ENVIRON] = self.telnet_NEW_ENVIRON

        # Store received environment variables
        self.environ_received: dict[str, str] = {}

        # I need to doubly escape here since my underlying
        # CowrieTelnetTransport hack would remove it and leave just \n
        self.windowSize = [40, 80]
        self.transport.write(self.factory.banner.replace(b"\n", b"\r\r\n"))
        self.transport.write(self.loginPrompt)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        Fires on pre-authentication disconnects
        """
        AuthenticatingTelnetProtocol.connectionLost(self, reason)

    def telnet_User(self, line):
        """
        Overridden to conditionally kill 'WILL ECHO' which confuses clients
        that don't implement a proper Telnet protocol (most malware)
        """
        self.username = line  # .decode()
        # only send ECHO option if we are chatting with a real Telnet client
        self.transport.willChain(ECHO)
        # FIXME: this should be configurable or provided via filesystem
        self.transport.write(self.passwordPrompt)
        return "Password"

    def telnet_Password(self, line):
        username, password = self.username, line  # .decode()
        del self.username

        # CVE-2026-24061 exploit bypass: use the extracted username if set
        if self.cve_2026_24061_user is not None:
            exploit_user = self.cve_2026_24061_user
            log.msg(
                eventid="cowrie.telnet.exploit_success",
                format="CVE-2026-24061 exploit successful: logging in as %(username)s",
                cve="CVE-2026-24061",
                username=exploit_user,
                original_username=username.decode("utf-8", errors="replace")
                if isinstance(username, bytes)
                else username,
                attempted_command=password.decode("utf-8", errors="replace")
                if isinstance(password, bytes)
                else password,
            )
            username = exploit_user.encode() if isinstance(exploit_user, str) else exploit_user
            password = b""  # Exploit bypasses password
            self.cve_2026_24061_user = None  # Clear the flag

        def login(ignored):
            self.src_ip = self.transport.getPeer().host
            creds = UsernamePasswordIP(username, password, self.src_ip)
            d = self.portal.login(creds, self.src_ip, ITelnetProtocol)
            d.addCallback(self._cbLogin)
            d.addErrback(self._ebLogin)

        # are we dealing with a real Telnet client?
        if self.transport.options:
            # stop ECHO
            # even if ECHO negotiation fails we still want to attempt a login
            # this allows us to support dumb clients which is common in malware
            # thus the addBoth: on success and on exception (AlreadyNegotiating)
            self.transport.wontChain(ECHO).addBoth(login)
        else:
            # process login
            login("")

        return "Discard"

    def telnet_Command(self, command):
        self.transport.protocol.dataReceived(command + b"\r")
        return "Command"

    def _cbLogin(self, ial):
        """
        Fired on a successful login
        """
        _interface, protocol, logout = ial
        protocol.windowSize = self.windowSize
        self.protocol = protocol
        self.logout = logout
        self.state = "Command"

        self.transport.write(b"\n")

        # Remove the short timeout of the login prompt.
        self.transport.setTimeout(
            CowrieConfig.getint("honeypot", "idle_timeout", fallback=300)
        )

        # replace myself with avatar protocol
        protocol.makeConnection(self.transport)
        self.transport.protocol = protocol

    def _ebLogin(self, failure):
        # TODO: provide a way to have user configurable strings for wrong password
        self.transport.wontChain(ECHO)
        self.transport.write(b"\nLogin incorrect\n")
        self.transport.write(self.loginPrompt)
        self.state = "User"

    def telnet_NAWS(self, data):
        """
        From TelnetBootstrapProtocol in twisted/conch/telnet.py
        """
        if len(data) == 4:
            width, height = struct.unpack("!HH", b"".join(data))
            self.windowSize = [height, width]
        else:
            log.msg("Wrong number of NAWS bytes")

    def telnet_NEW_ENVIRON(self, data: list[bytes]) -> None:
        """
        Handle NEW-ENVIRON (RFC 1572) subnegotiation.

        Parses environment variables sent by the client and logs them.
        Also detects CVE-2026-24061 exploit attempts where USER=-f root
        is used to bypass authentication in vulnerable telnetd implementations.

        Subnegotiation format:
            IS/SEND/INFO [VAR name VALUE value]* [USERVAR name VALUE value]*
        """
        if not data:
            return

        # Join the data bytes
        raw_data = b"".join(data)
        if len(raw_data) < 1:
            return

        command = raw_data[0]

        # We only care about IS (0) and INFO (2) - client sending values
        if command not in (NEW_ENVIRON_IS, NEW_ENVIRON_INFO):
            return

        # Parse the environment variables
        env_vars = self._parse_new_environ_data(raw_data[1:])

        # Log each environment variable
        for name, value in env_vars.items():
            # Store for potential later use
            self.environ_received[name] = value

            # Log the environment variable (matches SSH cowrie.client.var pattern)
            log.msg(
                eventid="cowrie.client.var",
                format="Telnet NEW-ENVIRON: %(name)s=%(value)s",
                name=name,
                value=value,
            )

            # CVE-2026-24061 detection: USER environment variable with -f flag
            # This exploit bypasses authentication in GNU inetutils telnetd <= 2.7
            if name.upper() == "USER" and value.startswith("-f"):
                log.msg(
                    eventid="cowrie.telnet.exploit_attempt",
                    format="CVE-2026-24061 exploit attempt detected: USER=%(value)s",
                    cve="CVE-2026-24061",
                    name=name,
                    value=value,
                )
                # If vulnerability emulation is enabled, set up auth bypass
                if CowrieConfig.getboolean(
                    "telnet", "cve_2026_24061_vulnerable", fallback=False
                ):
                    extracted_user = self._extract_cve_2026_24061_user(value)
                    if extracted_user:
                        self.cve_2026_24061_user = extracted_user

    def _extract_cve_2026_24061_user(self, value: str) -> str | None:
        """
        Extract username from CVE-2026-24061 exploit payload.

        The exploit uses USER=-f<user> or USER=-f <user> to bypass authentication.
        Returns the target username if the value matches the exploit pattern, None otherwise.
        """
        if not value.startswith("-f"):
            return None

        # Handle both "-f root" and "-froot" formats
        remainder = value[2:]
        if remainder.startswith(" "):
            return remainder[1:] if len(remainder) > 1 else None
        return remainder if remainder else None

    def _parse_new_environ_data(self, data: bytes) -> dict[str, str]:
        """
        Parse NEW-ENVIRON subnegotiation data into a dictionary.

        Format: [VAR|USERVAR name VALUE value]* with ESC for escaping.
        """
        env_vars: dict[str, str] = {}
        if not data:
            return env_vars

        i = 0
        current_name: list[int] = []
        current_value: list[int] = []
        in_value = False
        escape_next = False

        while i < len(data):
            byte = data[i]

            if escape_next:
                # Previous byte was ESC, treat this byte as literal
                if in_value:
                    current_value.append(byte)
                else:
                    current_name.append(byte)
                escape_next = False
            elif byte == NEW_ENVIRON_ESC:
                # Next byte is escaped
                escape_next = True
            elif byte == NEW_ENVIRON_VAR or byte == NEW_ENVIRON_USERVAR:
                # Save previous variable if any
                if current_name:
                    name = bytes(current_name).decode("utf-8", errors="replace")
                    value = bytes(current_value).decode("utf-8", errors="replace")
                    env_vars[name] = value
                # Start new variable
                current_name = []
                current_value = []
                in_value = False
            elif byte == NEW_ENVIRON_VALUE:
                # Switch from name to value
                in_value = True
            else:
                # Regular data byte
                if in_value:
                    current_value.append(byte)
                else:
                    current_name.append(byte)

            i += 1

        # Don't forget the last variable
        if current_name:
            name = bytes(current_name).decode("utf-8", errors="replace")
            value = bytes(current_value).decode("utf-8", errors="replace")
            env_vars[name] = value

        return env_vars

    def enableLocal(self, option: bytes) -> bool:
        if option == ECHO:
            return True
        # TODO: check if twisted now supports SGA (see git commit c58056b0)
        elif option == SGA:
            return False
        else:
            return False

    def enableRemote(self, option: bytes) -> bool:
        # Todo lo que hemos PEDIDO se acepta, sin excepcion. Twisted lo exige
        # con un assert (ver OPCIONES_SOLICITADAS arriba) y ademas es de
        # sentido comun: no se pide una opcion para luego rechazarla.
        #
        # NEW-ENVIRON entra por aqui: sirve para capturar las variables de
        # entorno y detectar los intentos de CVE-2026-24061.
        if option in OPCIONES_SOLICITADAS:
            return True
        # NAWS y SGA no se piden, pero se aceptan si el cliente los ofrece.
        if option in (NAWS, SGA):
            return True
        # TODO: check if twisted now supports LINEMODE (see git commit c58056b0)
        return False
