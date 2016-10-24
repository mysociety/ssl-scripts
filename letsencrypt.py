#!/usr/bin/env python

import argparse
import json
import os
import subprocess
import sys


class CertManagerCallable(object):
    ACME_STAGING_ENDPOINT = "https://acme-staging.api.letsencrypt.org/directory"
    ACME_PROD_ENDPOINT = "https://acme-v01.api.letsencrypt.org/directory"

    dry_run = None
    known_vhosts = None
    vhosts = None
    which_ca = None

    def __call__(self):
        parser = self._arg_parser()
        args = parser.parse_args()

        self.dry_run = args.dry_run
        self.which_ca = args.which_ca

        self.known_vhosts = self._parse_vhosts_pl(args.vhosts_pl_path)

        if args.all_vhosts:
            pass  # Not yet implemented
        else:
            for v in args.vhost:
                domains = self._get_vhost_domains(v)
                self._generate_certificates(domains)

    def _get_vhost_domains(self, vhost_name):
        # Get vhosts.pl definition
        try:
            data = self.known_vhosts[vhost_name]
        except KeyError:
            sys.exit("Unknown vhost name '%s' given" % vhost_name)

        # Determine CN and SAN names
        aliases = data.get('aliases', [])
        redirects = data.get('redirects', [])

        dns_names = set()
        dns_names.add(vhost_name)
        dns_names.update(aliases)
        dns_names.update(redirects)

        if vhost_name in redirects:
            cn = aliases[0]
        else:
            cn = vhost_name
        dns_names.remove(cn)

        return [cn] + sorted(list(dns_names))

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
            vhost_cwd = "/data/letsencrypt/certificates/" + vhost_name
        elif self.which_ca == "staging":
            ca_url = self.ACME_STAGING_ENDPOINT
            vhost_cwd = "/data/letsencrypt/staging_certificates/" + vhost_name

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
            '--tos_sha256', '6373439b9f29d67a5cd4d18cbc7f264809342dbf21cb2ba2fc7588df987a6221',
            '--server', ca_url], cwd=actual_cwd)

        if self.dry_run:
            print "Rename key.pem to %s.key" % cert_name
            print "Rename fullchain.pem to %s.crt" % cert_name
        else:
            os.rename(os.path.join(actual_cwd, 'key.pem'), os.path.join(actual_cwd, '%s.key' % cert_name))
            os.rename(os.path.join(actual_cwd, 'fullchain.pem'), os.path.join(actual_cwd, '%s.crt' % cert_name))

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

        # Vhost selection
        which_vhosts_group = parser.add_mutually_exclusive_group(required=True)
        which_vhosts_group.add_argument(
            '--all-vhosts', action='store_true', dest='all_vhosts', default=False, help="Apply to all eligible vhosts")
        which_vhosts_group.add_argument('vhost', nargs='*', default=[], help="Specify a particular vhost")

        # Misc options
        parser.add_argument(
            '--vhosts-pl-path', action='store', dest='vhosts_pl_path', default='/data/vhosts.pl',
            help="Override path to vhosts.pl (FOR TESTING USE)")

        return parser

    def _parse_vhosts_pl_section(self, vhosts_pl_path, section):
        return json.loads(subprocess.check_output([
            'perl', '-e', 'use JSON; require "' + vhosts_pl_path + '"; print encode_json($' + section + ');'
        ]))

    def _parse_vhosts_pl(self, vhosts_pl_path):
        vhosts = self._parse_vhosts_pl_section(vhosts_pl_path, 'vhosts')
        return vhosts


if __name__ == '__main__':
    cmc = CertManagerCallable()
    cmc()
