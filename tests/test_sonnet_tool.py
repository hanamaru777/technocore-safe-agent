import inspect
import json

from flop_agent import sonnet_tool as tool


_PAYLOAD = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstu"
BROAD = [
    "did:key:z6Mk" + _PAYLOAD,
    "did:key:z6Mk" + _PAYLOAD[:-1] + "v",
    "did:key:z6Mk" + _PAYLOAD[:-1] + "w",
    "did:key:z6Mk" + _PAYLOAD[:-1] + "x",
]
LIMITED = "did:key:z6Mk" + "A" * 44


def lines(token="golden"):
    return [[token] * 5 for _ in range(14)]


def dictionary():
    return {"golden": 2, "river": 2}


def poem_text(token="golden"):
    return "\n".join(" ".join([token] * 5) for _ in range(14))


def test_build_report_is_deterministic_machine_readable_and_review_explicit():
    first = tool.build_report(BROAD, lines(), dictionary())
    second = tool.build_report(BROAD, lines(), dictionary())

    assert first == second
    assert first["ok"] is True
    assert first["metadata"]["contest_id"] == "sonnet-2"
    assert first["metadata"]["rules_version"] == "0.5"
    assert first["metadata"]["cmudict_sha256"]
    assert first["mechanical"]["status"] == "PASS"
    assert first["mechanical"]["line_syllables"] == [10] * 14
    assert first["literary"]["rhyme_review"] == "REVIEW_REQUIRED"
    assert first["literary"]["meter_review"] == "REVIEW_REQUIRED"
    assert first["publication"]["unresolved"]
    assert all(count > 0 for count in first["contributor_counts"].values())


def test_blocking_error_has_exact_token_and_missing_letter_diagnostics():
    roster = [
        LIMITED,
        "did:key:z6Mk" + "B" * 44,
        "did:key:z6Mk" + "C" * 44,
        "did:key:z6Mk" + "D" * 44,
    ]
    try:
        tool.build_report(roster, lines("river"), dictionary())
    except Exception as error:
        report = tool.error_report(error)
    else:
        raise AssertionError("expected blocking failure")

    assert report["ok"] is False
    assert report["error"] == "token_has_no_eligible_contributor"
    assert report["blocking"][0]["token"] == "river"
    assert report["blocking"][0]["line_index"] == 0
    assert report["blocking"][0]["word_index"] == 0
    assert report["blocking"][0]["missing_letters_by_did"]


def test_cli_success_emits_json_without_network(monkeypatch, tmp_path, capsys):
    roster = tmp_path / "roster.json"
    poem = tmp_path / "poem.txt"
    roster.write_text(json.dumps({"roster": BROAD}), encoding="utf-8")
    poem.write_text(poem_text(), encoding="utf-8")
    monkeypatch.setattr(tool, "load_dictionary", lambda _path: dictionary())

    code = tool.main([
        "--roster", str(roster),
        "--poem", str(poem),
        "--dictionary", str(tmp_path / "cmudict.dict"),
    ])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["ok"] is True
    assert payload["mechanical"]["poem_sha256"]


def test_malformed_input_fails_closed_as_json(monkeypatch, tmp_path, capsys):
    roster = tmp_path / "roster.json"
    poem = tmp_path / "poem.txt"
    roster.write_text("not-json", encoding="utf-8")
    poem.write_text(poem_text(), encoding="utf-8")
    monkeypatch.setattr(tool, "load_dictionary", lambda _path: dictionary())

    code = tool.main([
        "--roster", str(roster),
        "--poem", str(poem),
        "--dictionary", str(tmp_path / "cmudict.dict"),
    ])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert payload["ok"] is False
    assert payload["error"] == "roster_json_invalid"


def test_missing_required_argument_is_machine_readable(capsys):
    code = tool.main([])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 2
    assert captured.err == ""
    assert payload["ok"] is False
    assert payload["error"] == "arguments_invalid"


def test_poem_accepts_stanza_blank_lines_but_requires_14_content_lines(tmp_path):
    path = tmp_path / "poem.txt"
    content = poem_text().splitlines()
    path.write_text("\n".join(content[:4] + [""] + content[4:8] + [""] + content[8:12] + [""] + content[12:]), encoding="utf-8")
    assert len(tool.load_poem(path)) == 14

    path.write_text("one line only\n", encoding="utf-8")
    try:
        tool.load_poem(path)
    except tool.ToolInputError as error:
        assert str(error) == "poem_line_count_invalid:1"
    else:
        raise AssertionError("expected line-count failure")


def test_tool_has_no_network_shell_signer_or_secret_surface():
    source = inspect.getsource(tool)
    forbidden = (
        "httpx",
        "requests",
        "urllib",
        "socket",
        "subprocess",
        "os.system",
        "post_signed",
        "invoke_signer",
        "SIGN_SEED",
        "with_vault_seed",
    )
    assert all(token not in source for token in forbidden)
