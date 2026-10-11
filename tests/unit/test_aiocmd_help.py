"""Offline tests for the command help of the interactive shell."""
import pytest

from msldap.examples.msldapclient import MSLDAPClientConsole

pytestmark = pytest.mark.unit


@pytest.fixture
def console():
    return MSLDAPClientConsole()


def test_help_for_single_command(console, capsys):
    assert console.do_help("certtemplates") is True
    out = capsys.readouterr().out
    assert out.startswith("Usage: certtemplates [name]\n")
    assert "Lists certificate templates" in out


async def test_dash_h_shows_help(console, capsys):
    await console._run_single_command("certtemplates", ["-h"])
    assert capsys.readouterr().out.startswith("Usage: certtemplates [name]\n")


def test_hidden_args_not_in_usage(console):
    usage = console._get_command_usage("certtemplates", *console._get_command_args("certtemplates"))
    assert "to_print" not in usage


def test_annotations_not_in_usage(console):
    usage = console._get_command_usage("shadowcred", *console._get_command_args("shadowcred"))
    assert usage == "shadowcred <targetuser>"


def test_unknown_command(console, capsys):
    assert console.do_help("nope") is False
    assert "Unknown command" in capsys.readouterr().out


def test_help_listing(console, capsys):
    console.do_help()
    out = capsys.readouterr().out
    assert "certtemplates [name]" in out
    assert "help <command>" in out


def test_help_completes_commands(console):
    from prompt_toolkit.document import Document
    completer = console._completer_for_command("help")
    words = {c.text for c in completer.get_completions(Document("cert"), None)}
    assert {"certify", "certify2", "certtemplates"} <= words
    all_words = {c.text for c in completer.get_completions(Document(""), None)}
    assert "help" not in all_words and "?" not in all_words
    assert "whoami" in all_words
