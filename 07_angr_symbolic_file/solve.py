#!/usr/bin/python3

import angr

project = angr.Project("07_angr_symbolic_file")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

simgr.explore(find=0x80489b2, avoid=0x8048998)

if simgr.found:
    print(simgr.found[0].posix.dumps(0).decode())
else:
    print("No solution found")
