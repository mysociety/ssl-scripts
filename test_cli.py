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


def test_issue_vhost_cert_fails_when_standalone_set(vhosts, acme_sh_helper, run_cli):
    vhosts(
        {
            "www.standalone.org": {
                "standalone_certs": 1,
                "servers": ["server1"],
                "aliases": ["standalone.org", "standalone.com"],
            },
        }
    )

    exit_code = run_cli(
        "letsencrypt",
        "--live-run",
        "--prod-ca",
        "www.standalone.org",
    )
    assert exit_code == 1
    assert len(acme_sh_helper) == 0


def test_issue_standalone_domain_cert_fails_when_not_under_standalone(
    vhosts, acme_sh_helper, run_cli
):
    vhosts(
        {
            "www.vhost.org": {
                "standalone_certs": 0,
                "servers": ["server1"],
                "aliases": ["vhost.org", "vhost.com"],
            },
        }
    )
    exit_code = run_cli(
        "letsencrypt",
        "--live-run",
        "--prod-ca",
        "--standalone",
        "vhost.org",
    )
    assert exit_code == 1
    assert len(acme_sh_helper) == 0


def test_issue_standalone_domain_cert(vhosts, acme_sh_helper, run_cli):
    vhosts(
        {
            "www.standalone.org": {
                "standalone_certs": 1,
                "servers": ["server1"],
                "aliases": ["standalone.org", "standalone.com"],
            },
        }
    )

    exit_code = run_cli(
        "letsencrypt",
        "--live-run",
        "--prod-ca",
        "--standalone",
        "www.standalone.org",
        "standalone.org",
        "standalone.com",
    )
    assert exit_code == 0
    assert len(acme_sh_helper) == 3

    call = acme_sh_helper[0]
    assert call.option_values("--cert-name") == ["www.standalone.org"]
    assert call.option_values("--domain") == [
        "www.standalone.org",
    ]
    call = acme_sh_helper[1]
    assert call.option_values("--cert-name") == ["standalone.org"]
    assert call.option_values("--domain") == [
        "standalone.org",
    ]
    call = acme_sh_helper[2]
    assert call.option_values("--cert-name") == ["standalone.com"]
    assert call.option_values("--domain") == [
        "standalone.com",
    ]


def test_renew_vhost_cert_fails_when_standalone_set(
    cert_data, vhosts, acme_sh_helper, run_cli
):
    vhosts(
        {
            "www.standalone.org": {
                "standalone_certs": 1,
                "servers": ["server1"],
                "aliases": ["standalone.org", "standalone.com"],
            },
        }
    )

    cert_data(
        ["www.standalone.org", "standalone.org", "standalone.com"],
        dt.datetime.now(),
    )
    exit_code = run_cli(
        "renew",
        "--renew",
    )
    assert exit_code == 1
    assert len(acme_sh_helper) == 0


def test_renew_standalone_domain_certs(cert_data, vhosts, acme_sh_helper, run_cli):
    vhosts(
        {
            "www.standalone.org": {
                "standalone_certs": 1,
                "servers": ["server1"],
                "aliases": ["standalone.org", "standalone.com"],
            },
        }
    )

    cert_data(
        ["www.standalone.org"],
        dt.datetime.now(),
    )
    cert_data(
        ["standalone.org"],
        dt.datetime.now(),
    )
    cert_data(
        ["standalone.com"],
        dt.datetime.now(),
    )
    exit_code = run_cli(
        "renew",
        "--renew",
    )
    assert exit_code == 0
    assert len(acme_sh_helper) == 3

    call = acme_sh_helper[0]
    assert call.option_values("--cert-name") == ["www.standalone.org"]
    assert call.option_values("--domain") == [
        "www.standalone.org",
    ]
    call = acme_sh_helper[1]
    assert call.option_values("--cert-name") == ["standalone.org"]
    assert call.option_values("--domain") == [
        "standalone.org",
    ]
    call = acme_sh_helper[2]
    assert call.option_values("--cert-name") == ["standalone.com"]
    assert call.option_values("--domain") == [
        "standalone.com",
    ]
