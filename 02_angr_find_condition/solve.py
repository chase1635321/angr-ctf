#!/usr/bin/python3

import angr

project = angr.Project("02_angr_find_condition")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

def is_good(state):
    return "Good Job" in state.posix.dumps(1).decode()

def is_bad(state):
    return "Try again" in state.posix.dumps(1).decode()

simgr.explore(find=is_good, avoid=is_bad)

if simgr.found:
    solution = simgr.found[0]
    print("Found solution:")
    print(solution.posix.dumps(0))
else:
    print("No solution found :(")
