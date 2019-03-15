#!/usr/bin/env python

import argparse
import json
import os
import subprocess
import sys
from utils import Vhosts


class CertManagerCallable(object):
    ACME_STAGING_ENDPOINT = "https://acme-staging.api.letsencrypt.org/directory"
    ACME_PROD_ENDPOINT = "https://acme-v01.api.letsencrypt.org/directory"

    dry_run = None
    which_ca = None

    def __call__(self):
        parser = self._arg_parser()
        args = parser.parse_args()

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

    def _generate_wildcard_certificate(self, cn):

        # cater for a dry run.
        if self.dry_run:
            cmd_prefix = ['echo']
        else:
            cmd_prefix = []

        # cater for optional arguments.
        acme_args = []
        if self.which_ca == "staging":
            acme_args.append("--staging")

        if self.force_issue:
            acme_args.append("--force")

        subprocess.check_call(cmd_prefix +
            ['sudo', './acme-sh-helper', '--domain', cn] +
            acme_args, cwd="/data/vhost/acme-challenge.mysociety.org/ssl-scripts/")

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
        if not cert_name:
            cert_name = domains[0]

        # Prepare arguments to simp_le
        all_vhosts_args = []
        for v in domains:
            all_vhosts_args.append("-d")
            all_vhosts_args.append(v)

        # Determine CA endpoint to use
        # and where should certificate target dir be?
        if self.which_ca == "prod":
            ca_url = self.ACME_PROD_ENDPOINT
            vhost_cwd = "/data/letsencrypt/certificates"
        elif self.which_ca == "staging":
            ca_url = self.ACME_STAGING_ENDPOINT
            vhost_cwd = "/data/letsencrypt/staging_certificates"

        # Make certificate target directory if not exists
        if not os.path.exists(vhost_cwd):
            if not self.dry_run:
                os.mkdir(vhost_cwd)

        # Actually run simp_le
        if self.dry_run:
            cmd_prefix = ['echo']
            actual_cwd = None
        else:
            cmd_prefix = []
            actual_cwd = vhost_cwd

        subprocess.check_call(cmd_prefix + [
            'simp_le', '--email', 'infrastructure@mysociety.org',
            '--default_root', '/data/letsencrypt/webroot/'] + all_vhosts_args + [
            '-f', 'key.pem', '-f', 'account_key.json', '-f', 'fullchain.pem',
            '--server', ca_url], cwd=actual_cwd)

        if self.dry_run:
            print "Rename key.pem to %s.key" % cert_name
            print "Rename fullchain.pem to %s.crt" % cert_name
            print("Run ./simp_le-git-helper %s %s" % (vhost_cwd, cert_name))
        else:
            os.rename(os.path.join(actual_cwd, 'key.pem'), os.path.join(actual_cwd, '%s.key' % cert_name))
            os.rename(os.path.join(actual_cwd, 'fullchain.pem'), os.path.join(actual_cwd, '%s.crt' % cert_name))
            if self.which_ca == "prod":
                self._add_to_puppet(cmd_prefix, actual_cwd, cert_name)
            else:
                print("Not adding to Puppet in staging.")

    def _add_to_puppet(self, cmd_prefix, cert_dir, cert_name):
        subprocess.check_call(['./simp_le-git-helper', cert_dir, cert_name ], cwd="/data/vhost/acme-challenge.mysociety.org/ssl-scripts/")

    def _arg_parser(self):
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

        return parser


if __name__ == '__main__':
    cmc = CertManagerCallable()
    cmc()
