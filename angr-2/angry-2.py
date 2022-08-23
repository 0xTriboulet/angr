#!/usr/bin/env python3

import angr
import monkeyhex
import claripy

__author__ = "0xTriboulet"

proj = angr.Project('./impossible_password.bin' , auto_load_libs=False)
state = proj.factory.entry_state()

simgr = proj.factory.simulation_manager(state)

print("Checking simulation manager\n\n\n")

result = simgr.explore(find=lambda s: b"}" in s.posix.dumps(1))

if "found" in str(result):
    s = simgr.found[0]
    print("Success!")
    print(s.posix.dumps(1))

