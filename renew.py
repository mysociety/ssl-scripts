#!/usr/bin/python

import argparse
import collections
import datetime
import glob
import os
import OpenSSL
from utils import Vhosts


class CertRenewerCallable(object):
    def __call__(self):
        parser = self._arg_parser()
        args = parser.parse_args()

        self.future = datetime.datetime.now() + datetime.timedelta(weeks=args.weeks)
        self.vhosts = Vhosts()
        self.domain_lookup = {}
        self.server_lookup = collections.defaultdict(set)

        self.fill_lookups()

        if args.list:
            self.list()
        else:
            self.output()


    def step(self, s, col=4):
        print '[3%dm%d. %s[m' % (col, self.step_num, s)
        self.step_num += 1


    def fill_lookups(self):
        for vhost, data in self.vhosts.items():
            if 'ssl_group' in data:
                res = '--group ' + data['ssl_group']
            else:
                res = vhost
            self.server_lookup[res] |= set(data['servers'])
            for domain in data['domains']:
                self.domain_lookup[domain] = res

    def list(self):
        for data in sorted(self.get_cert_data(), key=lambda x: x['expiry']):
            if data['expiry'] >= self.future:
                continue

            # Just skip this for now.
            if data['filename'].startswith('wildcard'):
                continue

            # Let's see which vhosts.pl entries the domains of the certificate map to
            vhosts_to_renew = set(self.domain_lookup.get(dom, dom) for dom in data['domains'])
            for vhost in vhosts_to_renew.copy():
                if not vhost.startswith('--group') and vhost not in self.vhosts:
                    vhosts_to_renew.remove(vhost)
            if not vhosts_to_renew:
                print
                continue

            for vhost in vhosts_to_renew:
                if vhost.startswith('--group'):
                    cert_filename = vhost.split(' ')[1] + '.group'
                else:
                    cert_filename = self.vhosts[vhost]['domains'][0]

            print ' '.join(vhosts_to_renew) + ',' + cert_filename

    def output(self):
        for data in sorted(self.get_cert_data(), key=lambda x: x['expiry']):
            if data['expiry'] >= self.future:
                continue

            # We have a soon-to-be expiring certificate
            self.step_num = 1
            print '[36m%s expires at %s[m' % (data['filename'], data['expiry'])
            if data['filename'].startswith('wildcard'):
                self.step('Replace wildcard certificate with one for all needed domains\n')
                continue

            # Let's see which vhosts.pl entries the domains of the certificate map to
            vhosts_to_renew = set(self.domain_lookup.get(dom, dom) for dom in data['domains'])
            for vhost in vhosts_to_renew.copy():
                if not vhost.startswith('--group') and vhost not in self.vhosts:
                    print '[31mError dealing with %s[m' % vhost
                    vhosts_to_renew.remove(vhost)
            if not vhosts_to_renew:
                print
                continue

            # Okay, we have something we can renew
            self.step('Dry run')
            print 'sudo -u letsencrypt -i letsencrypt [33m' + ' '.join(vhosts_to_renew) + '[m --dry-run --staging-ca'
            self.step('Check the output looks sensible (e.g. contains the domains you expect)', 1)
            self.step('Live run, Staging CA')
            print 'sudo -u letsencrypt -i letsencrypt [33m' + ' '.join(vhosts_to_renew) + '[m --live-run --staging-ca'
            for vhost in vhosts_to_renew:
                if vhost.startswith('--group'):
                    cert_filename = vhost.split(' ')[1] + '.group'
                else:
                    cert_filename = self.vhosts[vhost]['domains'][0]
                print 'ls /data/letsencrypt/staging_certificates/%s*' % cert_filename
            self.step('Live run, Production CA')
            print 'sudo -u letsencrypt -i letsencrypt [33m' + ' '.join(vhosts_to_renew) + '[m --live-run --prod-ca'
            for vhost in vhosts_to_renew:
                if vhost.startswith('--group'):
                    cert_filename = vhost.split(' ')[1] + '.group'
                else:
                    cert_filename = self.vhosts[vhost]['domains'][0]
                self.step('Move new data into /data/servers')
                print 'sudo mv /data/letsencrypt/certificates/%s.crt /data/puppet/site/profiles/files/certificates/etc/ssl/mysociety/certs/' % cert_filename
                print 'sudo mv /data/letsencrypt/certificates/%s.key /data/puppet/site/profiles/files/certificates/etc/ssl/mysociety/keys/' % cert_filename
                self.step('Commit certificate and key in /data/puppet and push. Puppet will deploy the new files and restart Nginx.', 1)
                self.step('If you want to speed this process, either run sudo mysociety base "mysociety config" on leopard or to be more discriminating:')
                for server in self.server_lookup.get(vhost, []):
                    server = '[32m%s[m' % server
                    print 'sudo ssh %s mysociety config' % server
                self.step('Check expiry time')
                print 'openssl s_client -servername %s -connect %s:443 </dev/null 2>/dev/null | openssl x509 -noout -enddate' % (vhost, vhost)
                self.step('Unchanged expiry time probably means there is an old manual certificate with a different filename')
            print

    @staticmethod
    def get_cert_data():
        for crt in sorted(glob.glob('/etc/ssl/mysociety/certs/*.crt')):
            with open(crt) as f:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
            expiry = cert.get_notAfter()
            cn = cert.get_subject().CN
            san = []
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() != 'subjectAltName':
                    continue
                san = str(ext).lstrip('DNS:').split(', DNS:')
                assert cn in san
            yield {
                'filename': os.path.basename(crt),
                'domains': san,
                'expiry': datetime.datetime.strptime(expiry, '%Y%m%d%H%M%SZ'),
            }

    @staticmethod
    def _arg_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('--weeks', default=4, type=int, help='Number of weeks to look forward')
        # Whether to just list things
        parser.add_argument('--list', action='store_true', help='Just list the domains/groups for renewal with their filenames rather than full instructions for manual renewals')
        return parser


if __name__ == '__main__':
    cmc = CertRenewerCallable()
    cmc()
