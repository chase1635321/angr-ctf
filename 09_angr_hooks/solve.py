#!/usr/bin/python3

import angr
import claripy

project = angr.Project("09_angr_hooks")
state = project.factory.entry_state()

@project.hook(0x080486b8, length=5)
def check_equals_hook(state):
    s = state.memory.load(0x804a054, 16)
    state.regs.eax = claripy.If(s == "XKSPZSJKJYQCQXZV", claripy.BVV(1, 32), claripy.BVV(0, 32))

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
