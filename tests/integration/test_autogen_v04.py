from agentwall.integrations.autogen_v04 import (
    _extract_text_from_autogen_msg,
    _is_autogen_v02,
    _is_autogen_v04,
    _is_sk_kernel,
)


def test_is_autogen_v04_false_without_package():
    class FakeAgent:
        pass

    assert _is_autogen_v04(FakeAgent()) is False


def test_is_autogen_v02_false_without_package():
    class FakeAgent:
        pass

    assert _is_autogen_v02(FakeAgent()) is False


def test_is_sk_kernel_false_without_package():
    class FakeKernel:
        pass

    assert _is_sk_kernel(FakeKernel()) is False


def test_extract_text_string():
    assert _extract_text_from_autogen_msg("hello") == "hello"


def test_extract_text_dict():
    msg = {"content": "hello world", "role": "user"}
    assert _extract_text_from_autogen_msg(msg) == "hello world"


def test_extract_text_object_with_content():
    class Msg:
        content = "test content"

    assert _extract_text_from_autogen_msg(Msg()) == "test content"


def test_extract_text_none():
    assert _extract_text_from_autogen_msg(42) is None
