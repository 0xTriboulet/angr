#!/usr/bin/env python3

import angr
import monkeyhex
import claripy

__author__ = "0xTriboulet"

proj = angr.Project('./test.o' ,load_options={'auto_load_libs': False})
state = proj.factory.entry_state()

#idfer = proj.analyses.Identifier()
## RUNNING THIS BELOW GOT US THIS ADDRESS FOR MAIN: 0x401171
#print("\n\nPrinting functions...\n\n")
#for func in idfer.func_info:
#        print(hex(func.addr),func.name)

simgr = proj.factory.simulation_manager(state)

#print("Checking simulation manager")
#print(simgr.active)

## PRINT ENTRY ADDRESS
print(hex(state.solver.eval(simgr.active[0].regs.rip))) 

#entry_addr = hex(state.solver.eval(simgr.active[0].regs.rip)) 

result = simgr.explore(find=lambda s: b"SUCCESS" in s.posix.dumps(1))

if "found" in str(result):
    s = simgr.found[0]
    print(s.posix.dumps(0),s.posix.dumps(1))

