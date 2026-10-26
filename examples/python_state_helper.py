"""Small stateful module used by python_state.gak."""

calls = 0


def bump():
    global calls
    calls += 1
    return calls
