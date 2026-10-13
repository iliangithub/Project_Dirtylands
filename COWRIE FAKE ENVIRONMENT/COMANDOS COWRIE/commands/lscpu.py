# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 "
    "clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm "
    "constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc "
    "cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx est "
    "tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt "
    "tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch "
    "cpuid_fault epb ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority "
    "ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed "
    "adx smap clflushopt clwb intel_pt sha_ni xsaveopt xsavec xgetbv1 xsaves"
)

OUTPUT = f"""Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          46 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   12
  On-line CPU(s) list:    0-11
Vendor ID:                GenuineIntel
  Model name:             12th Gen Intel(R) Core(TM) i5-12400
    CPU family:           6
    Model:                151
    Thread(s) per core:   2
    Core(s) per socket:   6
    Socket(s):            1
    Stepping:             5
    CPU(s) scaling MHz:   38%
    CPU max MHz:          4400.0000
    CPU min MHz:          800.0000
    BogoMIPS:             4992.00
    Flags:                {FLAGS}
Virtualization features:
  Virtualization:         VT-x
Caches (sum of all):
  L1d:                    288 KiB (6 instances)
  L1i:                    192 KiB (6 instances)
  L2:                     7.5 MiB (6 instances)
  L3:                     18 MiB (1 instance)
NUMA:
  NUMA node(s):           1
  NUMA node0 CPU(s):      0-11
Vulnerabilities:
  Gather data sampling:   Not affected
  Itlb multihit:          Not affected
  L1tf:                   Not affected
  Mds:                    Not affected
  Meltdown:               Not affected
  Mmio stale data:        Not affected
  Retbleed:               Not affected
  Spec store bypass:      Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:             Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:             Mitigation; Enhanced / Automatic IBRS; IBPB conditional; RSB filling; PBRSB-eIBRS SW sequence; BHI SW loop, KVM SW loop
  Srbds:                  Not affected
  Tsx async abort:        Not affected
"""


class Command_lscpu(HoneyPotCommand):
    def call(self) -> None:
        self.write(OUTPUT)


commands["lscpu"] = Command_lscpu
commands["/usr/bin/lscpu"] = Command_lscpu
