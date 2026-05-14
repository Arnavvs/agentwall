from agentwall.normalizer.unicode import normalize_unicode


def test_zero_width_strip():
    text = "Hello\u200bWorld\ufeff"
    result = normalize_unicode(text)
    assert "\u200b" not in result
    assert "\ufeff" not in result
    assert "HelloWorld" in result


def test_nfkc_normalization():
    text = "\ufb01le"
    result = normalize_unicode(text)
    assert result == "file"


def test_preserves_newlines():
    text = "line1\nline2\ttab"
    result = normalize_unicode(text)
    assert "\n" in result
    assert "\t" in result


def test_strips_control_chars():
    text = "Hello\x00World\x01"
    result = normalize_unicode(text)
    assert "\x00" not in result
    assert "\x01" not in result


def test_empty_string():
    assert normalize_unicode("") == ""
