import copy
import importlib
import os
import subprocess

import pytest

import renew
import utils


@pytest.fixture
def vhosts(monkeypatch):
    """
    Returns a function that sets the parsed vhosts.pl data, in place of
    reading /data/vhosts.pl.
    Example:

        vhosts({
            "www.example.org": {
                "servers": ["server1"],
                "aliases": ["example.org"],
            },
        })

    Until it's called, vhosts.pl is treated as empty.
    """
    data = {}

    def parse_vhosts_pl(self, vhosts_pl_path):
        # A fresh copy each time, as `Vhosts` modifies what it's given.
        return copy.deepcopy(data)

    monkeypatch.setattr(utils.Vhosts, "_parse_vhosts_pl", parse_vhosts_pl)

    def set_vhosts(new_data):
        data.clear()
        data.update(new_data)

    return set_vhosts


class AcmeShHelperCall:
    """A single recorded invocation of `acme-sh-helper`."""

    def __init__(self, command, kwargs):
        self.command = command
        self.args = command[1:]
        self.kwargs = kwargs

    def option_values(self, name):
        """All values passed for a repeatable option, e.g. `--domain`."""
        return [self.args[i + 1] for i, a in enumerate(self.args) if a == name]

    def has_flag(self, name):
        return name in self.args

    def __repr__(self):
        return f"AcmeShHelperCall({self.args!r})"


@pytest.fixture
def acme_sh_helper(monkeypatch):
    """
    Intercepts calls to `acme-sh-helper` made via `subprocess.run`,
    reporting success and recording the arguments for later inspection.
    """
    calls = []
    real_run = subprocess.run

    def fake_run(command, *args, **kwargs):
        if (
            isinstance(command, (list, tuple))
            and os.path.basename(command[0]) == "acme-sh-helper"
        ):
            calls.append(AcmeShHelperCall(list(command), kwargs))
            return subprocess.CompletedProcess(
                args=command, returncode=0, stdout="", stderr=None
            )
        # Continue as normal for non acme-sh-helper calls.
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


@pytest.fixture
def cert_data(monkeypatch):
    """
    Returns a function that adds an entry to the parsed cert data in
    place of reading /etc/ssl/mysociety/certs.
    Examples:

        cert_data(["www.example.org", "example.org"], expiry)
        cert_data(
            ["example.org", "*.example.org"],
            expiry,
            filename="wildcard.example.org.crt",
        )

    The CN is the first domain. `expiry` is a naive UTC datetime, and
    `filename` defaults to "<first domain>.crt".
    """
    certs = []
    monkeypatch.setattr(
        renew.CertRenewerCallable,
        "get_cert_data",
        staticmethod(lambda: iter(list(certs))),
    )

    def add(domains, expiry, filename=None):
        certs.append(
            {
                "filename": filename or f"{domains[0]}.crt",
                "domains": list(domains),
                "cn": domains[0],
                "expiry": expiry,
            }
        )

    return add


@pytest.fixture
def run_cli():
    """
    Returns a function to run one of the scripts as if from the command line.
    The function returns the exit code.
    """

    def run(script, *argv):
        module = importlib.import_module(script)
        try:
            module.main(list(argv))
        except SystemExit as e:
            return e.code or 0
        return 0

    return run
