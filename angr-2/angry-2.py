#/usr/bin/env python3

import angr
import monkeyhex
import claripy

__author__ = "0xTriboulet"

proj = angr.Project('./impossible_password.bin' , auto_load_libs=False, force_load_libs=['./rand.o'])
state = proj.factory.entry_state()

simgr = proj.factory.simulation_manager(state)

result = simgr.explore(find=lambda s: b"}" in s.posix.dumps(1))

if "found" in str(result):
    s = simgr.found[0]
    print("\n\n\nSuccess!\n")
    print("secret password:", str(s.posix.dumps(0)[-20:], 'ASCII'))
    print("flag:", str(s.posix.dumps(1)[-20:-10],'ASCII')+'-----'+str(s.posix.dumps(1)[-5:],'ASCII'))

