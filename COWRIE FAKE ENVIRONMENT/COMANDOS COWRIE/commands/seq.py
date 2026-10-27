# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_seq(HoneyPotCommand):
    def call(self) -> None:
        sep = "\n"
        nums_args = []
        i = 0
        args = self.args
        while i < len(args):
            a = args[i]
            if a == "-s" and i + 1 < len(args):
                sep = args[i + 1]
                i += 2
                continue
            if a.startswith("-s"):
                sep = a[2:]
                i += 1
                continue
            if a in ("-w", "--equal-width"):
                i += 1
                continue
            nums_args.append(a)
            i += 1

        try:
            nums = [float(x) for x in nums_args]
        except ValueError:
            self.errorWrite(f"seq: invalid floating point argument: {nums_args[-1] if nums_args else ''}\n")
            return
        if len(nums) == 1:
            first, step, last = 1.0, 1.0, nums[0]
        elif len(nums) == 2:
            first, last = nums
            step = 1.0
        elif len(nums) == 3:
            first, step, last = nums
        else:
            self.errorWrite("seq: missing operand\nTry 'seq --help' for more information.\n")
            return
        if step == 0:
            self.errorWrite("seq: invalid Zero increment value: '0'\n")
            return
        intmode = all(n.is_integer() for n in nums)
        out = []
        x = first
        while (step > 0 and x <= last + 1e-9) or (step < 0 and x >= last - 1e-9):
            out.append(str(int(x)) if intmode else f"{x:g}")
            x += step
            if len(out) > 1000000:
                break
        if out:
            self.write(sep.join(out) + "\n")


commands["seq"] = Command_seq
commands["/usr/bin/seq"] = Command_seq
