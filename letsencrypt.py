#!/usr/bin/env python
from __future__ import print_function
import argparse
import json
import os
import subprocess
import sys
from utils import Vhosts
from loguru import logger


class CertGenerationError(Exception):
    pass


class CertManagerCallable(object):
    ACME_STAGING_ENDPOINT = "https://acme-staging-v02.api.letsencrypt.org/directory"
    ACME_PROD_ENDPOINT = "https://acme-v02.api.letsencrypt.org/directory"

    dry_run = None
    which_ca = None

    def __call__(self, args):

        self.dry_run = args.dry_run
        self.which_ca = args.which_ca
        self.force_issue = args.force_issue

        known_vhosts = Vhosts(args.vhosts_pl_path)

        if args.all_vhosts:
            pass  # Not yet implemented
        elif args.wildcard_cert:
            self._generate_wildcard_certificate(args.wildcard_cert)
        elif args.group:
            domains = []
            for vhost, data in known_vhosts.items():
                if 'ssl_group' in data and data['ssl_group'] == args.group:
                    domains += data['domains']
            self._generate_certificates(domains, cert_name="%s.group" % args.group)
        else:
            for v in args.vhost:
                domains = known_vhosts[v]['domains']
                self._generate_certificates(domains)

    def _call_acme_sh_helper(self, domains, wildcard, cert_name=None):
        # cater for a dry run.
        if self.dry_run:
            cmd_prefix = ['echo']
        else:
            cmd_prefix = []

        acme_args = []

        if not cert_name:
            cert_name=domains[0]

        acme_args += ["--cert-name", cert_name]

        for domain in domains:
            acme_args += ["--domain", domain]

        if wildcard:
            acme_args.append('--wildcard')

        # cater for optional arguments.
        if self.which_ca == "staging":
            acme_args.append("--staging")

        if self.force_issue:
            acme_args.append("--force")

        command = ['./acme-sh-helper'] + acme_args

        try:
            result = subprocess.run(
                command,
                cwd="/data/vhost/acme-challenge.mysociety.org/ssl-scripts/",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=True
            )
            logger.debug(f"{command} succeeded with output:\n {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"{command} failed with output:\n {e.stdout}")
            raise CertGenerationError()

    def _generate_wildcard_certificate(self, cn):
        self._call_acme_sh_helper([cn], True, cert_name=f"wildcard.{cn}")

    def _generate_certificates(self, domains, cert_name=None):
        if not domains:
            return
        if not cert_name:
            cert_name = domains[0]

        for i in range(0, len(domains), 100):
            if len(domains)>100:
                cn = '%s.%s' % (chr(i/100+65), cert_name)
            else:
                cn = cert_name
            self._generate_certificate(domains[i:i+100], cert_name=cn)

    def _generate_certificate(self, domains, cert_name=None):
        if not domains:
            return

        self._call_acme_sh_helper(domains, False, cert_name=cert_name)

if __name__ == '__main__':

    # Set-up argument parser.
    parser = argparse.ArgumentParser()

    # Run mode
    live_or_dry_group = parser.add_mutually_exclusive_group(required=True)
    live_or_dry_group.add_argument('--live-run', action='store_false', dest='dry_run', help='Run in live run mode')
    live_or_dry_group.add_argument('--dry-run', action='store_true', dest='dry_run', help='Run in dry run mode')

    # CA selection
    staging_or_prod_group = parser.add_mutually_exclusive_group(required=True)
    staging_or_prod_group.add_argument(
        '--staging-ca', action='store_const', dest='which_ca', const='staging', help='Use LetsEncrypt Staging CA')
    staging_or_prod_group.add_argument(
        '--prod-ca', action='store_const', dest='which_ca', const='prod', help='Use LetsEncrypt Production CA')

    # Force. Only really useful with `--wildcard`
    parser.add_argument('--force', action='store_true', dest='force_issue', default=False, help="Force issue even if no renewal appears necessary")

    # Vhost selection
    which_vhosts_group = parser.add_mutually_exclusive_group(required=True)
    which_vhosts_group.add_argument(
        '--all-vhosts', action='store_true', dest='all_vhosts', default=False, help="Apply to all eligible vhosts")
    which_vhosts_group.add_argument('--wildcard', action="store", dest='wildcard_cert', help="Issue a wildcard certificate.")
    which_vhosts_group.add_argument('--group', action='store', help="Specify a particular vhost group")
    which_vhosts_group.add_argument('vhost', nargs='*', default=[], help="Specify a particular vhost")

    # Misc options
    parser.add_argument(
        '--vhosts-pl-path', action='store', dest='vhosts_pl_path', default='/data/vhosts.pl',
        help="Override path to vhosts.pl (FOR TESTING USE)")

    # Get those arguments
    args = parser.parse_args()

    # Call our main class, passing in the `argparse.Namespace` object resulting.
    cmc = CertManagerCallable()
    cmc(args)
