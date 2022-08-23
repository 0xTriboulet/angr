#!/usr/bin/env python3

import angr
import monkeyhex
import claripy

__author__ = "0xTriboulet"

proj = angr.Project('./impossible_password.bin' , auto_load_libs=False)#,  force_load_libs='/home/kali/throw_it_in_reverse/angr-2/rand.h')
state = proj.factory.entry_state()

#idfer = proj.analyses.Identifier()
## RUNNING THIS BELOW GOT US THIS ADDRESS FOR MAIN: 0x401171
#print("\n\nPrinting functions...\n\n")
#for func in idfer.func_info:
#        print(hex(func.addr),func.name)

simgr = proj.factory.simulation_manager(state)

print("Checking simulation manager\n\n\n")

result = simgr.explore(find=lambda s: b"}" in s.posix.dumps(1))

if "found" in str(result):
    s = simgr.found[0]
    print("Success!")
    print(s.posix.dumps(1))

