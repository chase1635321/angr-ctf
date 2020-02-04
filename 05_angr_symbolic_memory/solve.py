#!/usr/bin/python3

import angr

project = angr.Project("05_angr_symbolic_memory")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

simgr.explore(find=0x804865d, avoid=0x804866f)

if simgr.found:
    print(simgr.found[0].posix.dumps(0).decode())
else:
    print("No solution found")
