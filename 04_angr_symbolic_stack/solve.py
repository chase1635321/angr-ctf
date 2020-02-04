#!/usr/bin/python3

import angr

def main():
    project = angr.Project("04_angr_symbolic_stack")
    state = project.factory.entry_state()
    simgr = project.factory.simgr(state)

    simgr.explore(find=0x80486e1, avoid=0x80486cf)
    
    if simgr.found:
        solution_state = simgr.found[0]
        print(solution_state.posix.dumps(0))
    else:
        print("No solution found")





main()
