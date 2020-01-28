#!/usr/bin/python3

import angr

project = angr.Project("00_angr_find")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

simgr.explore(find=0x08048687)

if simgr.found:
    solution = simgr.found[0]
    print("Solution found:")
    print(solution.posix.dumps(0))
else:
    print("No solution found")
