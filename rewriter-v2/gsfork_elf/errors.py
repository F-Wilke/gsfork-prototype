class RewriteError(Exception):
    """An unsupported input or an unsuccessful correctness check."""


def fail(file, section, address, rule):
    raise RewriteError(f"{file}:{section}:0x{address:x}: {rule}")
