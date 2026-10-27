# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

FULL = """# dmidecode 3.6
Getting SMBIOS data from sysfs.
SMBIOS 3.5.0 present.
Table at 0x7A8C1000.

Handle 0x0000, DMI type 0, 26 bytes
BIOS Information
\tVendor: American Megatrends International, LLC.
\tVersion: 1.80
\tRelease Date: 09/14/2022
\tAddress: 0xF0000
\tRuntime Size: 64 kB
\tROM Size: 32 MB
\tCharacteristics:
\t\tPCI is supported
\t\tBIOS is upgradeable
\t\tBIOS shadowing is allowed
\t\tBoot from CD is supported
\t\tSelectable boot is supported
\t\tACPI is supported
\t\tUEFI is supported
\tBIOS Revision: 5.27

Handle 0x0001, DMI type 1, 27 bytes
System Information
\tManufacturer: Micro-Star International Co., Ltd.
\tProduct Name: MS-7D25
\tVersion: 1.0
\tSerial Number: To be filled by O.E.M.
\tUUID: 03000200-0400-0500-0006-000700080009
\tWake-up Type: Power Switch
\tSKU Number: To be filled by O.E.M.
\tFamily: To be filled by O.E.M.

Handle 0x0002, DMI type 2, 15 bytes
Base Board Information
\tManufacturer: Micro-Star International Co., Ltd.
\tProduct Name: PRO B660M-A WIFI (MS-7D25)
\tVersion: 1.0
\tSerial Number: To be filled by O.E.M.
\tAsset Tag: To be filled by O.E.M.
\tFeatures:
\t\tBoard is a hosting board
\t\tBoard is replaceable
\tLocation In Chassis: To be filled by O.E.M.
\tChassis Handle: 0x0003
\tType: Motherboard
\tContained Object Handles: 0

Handle 0x0004, DMI type 4, 48 bytes
Processor Information
\tSocket Designation: LGA1700
\tType: Central Processor
\tFamily: Core i5
\tManufacturer: Intel(R) Corporation
\tID: 51 06 0A 00 FF FB EB BF
\tSignature: Type 0, Family 6, Model 151, Stepping 5
\tVersion: 12th Gen Intel(R) Core(TM) i5-12400
\tVoltage: 1.1 V
\tExternal Clock: 100 MHz
\tMax Speed: 4400 MHz
\tCurrent Speed: 2500 MHz
\tStatus: Populated, Enabled
\tUpgrade: Other
\tCore Count: 6
\tCore Enabled: 6
\tThread Count: 12
\tCharacteristics:
\t\t64-bit capable
\t\tMulti-Core
\t\tHardware Thread
\t\tExecute Protection
\t\tEnhanced Virtualization

Handle 0x0007, DMI type 16, 23 bytes
Physical Memory Array
\tLocation: System Board Or Motherboard
\tUse: System Memory
\tError Correction Type: None
\tMaximum Capacity: 128 GB
\tNumber Of Devices: 4

Handle 0x0008, DMI type 17, 92 bytes
Memory Device
\tArray Handle: 0x0007
\tTotal Width: 64 bits
\tData Width: 64 bits
\tSize: 8 GB
\tForm Factor: DIMM
\tLocator: DIMM 0
\tBank Locator: P0 CHANNEL A
\tType: DDR4
\tSpeed: 3200 MT/s
\tManufacturer: Kingston
\tPart Number: KF3200C16D4/8GX

Handle 0x0009, DMI type 17, 92 bytes
Memory Device
\tArray Handle: 0x0007
\tTotal Width: 64 bits
\tData Width: 64 bits
\tSize: 8 GB
\tForm Factor: DIMM
\tLocator: DIMM 1
\tBank Locator: P0 CHANNEL B
\tType: DDR4
\tSpeed: 3200 MT/s
\tManufacturer: Kingston
\tPart Number: KF3200C16D4/8GX
"""


class Command_dmidecode(HoneyPotCommand):
    def call(self) -> None:
        if self.protocol.user.username != "root":
            self.errorWrite("/dev/mem: Permission denied\n")
            return
        self.write(FULL)


commands["dmidecode"] = Command_dmidecode
commands["/usr/sbin/dmidecode"] = Command_dmidecode
commands["/usr/bin/dmidecode"] = Command_dmidecode
