"""Explicit failures that survive optimized Python; never print raw evidence."""
import re

class SecurityError(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)

def require(condition, code, message):
    if not condition:
        raise SecurityError(code, message)

def valid_digest(value):
    return type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None
