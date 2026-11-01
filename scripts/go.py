#!/usr/bin/env python3
"""Run pinned Go without installing or consulting a system compiler."""
import os
import sys
import toolchain

if sys.argv[1:] == ['--fetch-only']:
    go, env = toolchain.ensure(offline=False)
    print(go)
elif sys.argv[1:] == ['--path']:
    print(toolchain.ensure()[0])
else:
    go, env = toolchain.ensure()
    os.execve(go, [str(go), *sys.argv[1:]], env)
