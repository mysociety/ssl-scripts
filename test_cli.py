import datetime as dt


def test_issue_vhost_cert(vhosts, acme_sh_helper, run_cli):
    vhosts(
        {
            "www.example.org": {
                "servers": ["server1"],
                "aliases": ["example.org", "example.com"],
            },
        }
    )

    exit_code = run_cli(
        "letsencrypt",
        "--live-run",
        "--prod-ca",
        "www.example.org",
    )

    assert exit_code == 0
    assert len(acme_sh_helper) == 1
    call = acme_sh_helper[0]
    assert call.option_values("--cert-name") == ["www.example.org"]
    assert call.option_values("--domain") == [
        "www.example.org",
        "example.com",
        "example.org",
    ]
    assert not call.has_flag("--wildcard")
    assert not call.has_flag("--staging")
    assert not call.has_flag("--force")


def test_renew_vhost_cert(cert_data, vhosts, acme_sh_helper, run_cli):
    cert_data(
        ["www.example.org", "example.org", "example.com"],
        dt.datetime.now(),
    )
    vhosts(
        {
            "www.example.org": {
                "servers": ["server1"],
                "aliases": ["example.org", "example.com"],
            },
        }
    )

    exit_code = run_cli(
        "renew",
        "--renew",
    )

    assert exit_code == 0
    assert len(acme_sh_helper) == 1
    call = acme_sh_helper[0]
    assert call.option_values("--cert-name") == ["www.example.org"]
    assert call.option_values("--domain") == [
        "www.example.org",
        "example.com",
        "example.org",
    ]
    assert not call.has_flag("--wildcard")
    assert not call.has_flag("--staging")
    assert call.has_flag("--force")
