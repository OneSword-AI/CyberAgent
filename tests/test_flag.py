from cyberagent.flag import dedupe_flags, extract_flags, merge_candidate_flags


def test_extract_flags_uses_default_pattern():
    text = "noise flag{hello_world} more CTF{abc123}"

    assert extract_flags(text) == ["flag{hello_world}", "CTF{abc123}"]


def test_extract_flags_uses_custom_format():
    text = "token FLAG-1234 and FLAG-abcd"

    assert extract_flags(text, r"FLAG-[A-Za-z0-9]+") == ["FLAG-1234", "FLAG-abcd"]


def test_extract_flags_handles_capture_groups():
    text = "flag is flag{secret}"

    assert extract_flags(text, r"flag\{([^}]+)\}") == ["secret"]


def test_dedupe_flags_preserves_order():
    assert dedupe_flags(["flag{a}", "flag{b}", "flag{a}"]) == ["flag{a}", "flag{b}"]


def test_merge_candidate_flags_preserves_existing_order():
    assert merge_candidate_flags(["flag{old}"], ["flag{new}", "flag{old}"]) == [
        "flag{old}",
        "flag{new}",
    ]
