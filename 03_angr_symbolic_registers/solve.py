#!/usr/bin/python3

import angr
import claripy
import sys

def main():
  path_to_binary = "03_angr_symbolic_registers"
  project = angr.Project(path_to_binary)

  start_address = 0x80488d1  # :integer (probably hexadecimal)
  initial_state = project.factory.entry_state()

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.' in stdout_output.decode()

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.' in stdout_output.decode()

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(0))

  else:
    raise Exception('Could not find the solution')

main()
