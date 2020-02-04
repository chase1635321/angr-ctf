#!/usr/bin/python3

import angr
import claripy

project = angr.Project("10_angr_simprocedures")

class CheckEquals(angr.SimProcedure):
    def run(self, to_check, length):
        user_input = state.memory.load(to_check, length)
        return claripy.If(user_input == "WQNDNKKWAWOLXBAC", claripy.BVV(1, 32), claripy.BVV(0, 32))


project.hook_symbol("check_equals_WQNDNKKWAWOLXBAC", CheckEquals())

state = project.factory.entry_state()
simgr = project.factory.simgr(state)

def good(state):
    return "Good" in state.posix.dumps(1).decode()

def bad(state):
    return "Try" in state.posix.dumps(1).decode()

simgr.explore(find=good, avoid=bad)

if simgr.found:
    print(simgr.found[0].posix.dumps(0).decode())
else:
    print("No solution found")
