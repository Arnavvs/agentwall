from enum import StrEnum


class Action(StrEnum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    ESCALATE = "ESCALATE"
