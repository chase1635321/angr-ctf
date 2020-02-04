#!/usr/bin/python3

import angr

project = angr.Project("06_angr_symbolic_dynamic_memory")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

simgr.explore(find=0x804875b, avoid=0x8048749)

if simgr.found:
    print(simgr.found[0].posix.dumps(0).decode())
else:
    print("No solutino found")
