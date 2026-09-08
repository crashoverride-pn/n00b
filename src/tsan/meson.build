# The detector is its own static_library so it can be compiled WITHOUT
# -fsanitize=thread while the rest of the tree is compiled with it.  Instrumented
# detector code would call itself on every shadow update and never terminate.
n00b_tsan_src = files(
    'abi.c',
    'clock.c',
    'report.c',
    'shadow.c',
)
