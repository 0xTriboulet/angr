import angr
import monkeyhex
import claripy

__author__ = "0xTriboulet"


proj = angr.Project('./headache' , auto_load_libs=False)
state = proj.factory.entry_state()


simgr = proj.factory.simulation_manager(state)


## PRINT ENTRY ADDRESS
print(hex(state.solver.eval(simgr.active[0].regs.rip))) 

#entry_addr = hex(state.solver.eval(simgr.active[0].regs.rip)) 
good = find=lambda s: b"Login success!" in s.posix.dumps(1)
bad = find=lambda s: b"HTB{w0w_th4ts_c000l}" in s.posix.dumps(0)

result = simgr.explore(find=good, avoid=bad)

if "found" in str(result):
    s = simgr.found[0]
    print(s.posix.dumps(0)[0:4]+b"ACTUAL FLAG OMITTED}",s.posix.dumps(1))
