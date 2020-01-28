#!/usr/bin/python3

import angr

proj = angr.Project("01_angr_avoid")

state = proj.factory.entry_state()

simgr = proj.factory.simgr(state)

simgr.explore(find=0x80485e5,avoid=0x80485a8)

if simgr.found:
    solution = simgr.found[0]
    print("Found solution:")
    print(solution.posix.dumps(0))
else:
    pritn("Solution not found")
