#!/usr/bin/python3

import angr
import claripy

project = angr.Project("08_angr_constraints")
state = project.factory.blank_state(addr=0x804862a)
simgr = project.factory.simgr(state)

password = claripy.BVS("password", 8*16)

state.memory.store(0x0804a050, password)

simgr.explore(find=0x08048678)

if simgr.found:
    solution = simgr.found[0]
    solution_BVS = solution.memory.load(0x804a050, 16)
    solution.add_constraints(solution_BVS == "BWYRUBQCMVSBRGFU")
    s = solution.solver.eval(password, cast_to=bytes).decode()
    print(s)
else:
    print("No solution found")

