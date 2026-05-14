from contextvars import ContextVar
from uuid import uuid4

correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


def set_correlation_id(cid: str | None = None) -> str:
    cid = cid or uuid4().hex
    correlation_id_var.set(cid)
    return cid


def get_correlation_id() -> str:
    cid = correlation_id_var.get()
    if not cid:
        return set_correlation_id()
    return cid
