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
        self.output()

    def fill_lookups(self):
        for vhost, data in self.vhosts.items():
            if 'ssl_group' in data:
                res = '--group ' + data['ssl_group']
            else:
                res = vhost
            self.server_lookup[res] |= set(data['servers'])
            for domain in data['domains']:
                self.domain_lookup[domain] = res

    def output(self):
        for data in sorted(self.get_cert_data(), key=lambda x: x['expiry']):
            if data['expiry'] >= self.future:
                continue

            # We have a soon-to-be expiring certificate
            print '[34m# %s expires at %s[m' % (data['filename'], data['expiry'])
            if data['filename'].startswith('wildcard'):
                continue

            # Let's see which vhosts.pl entries the domains of the certificate map to
            vhosts_to_renew = set(self.domain_lookup.get(dom, dom) for dom in data['domains'])
            for vhost in vhosts_to_renew.copy():
                if not vhost.startswith('--group') and vhost not in self.vhosts:
                    print '[31mError dealing with %s[m' % vhost
                    vhosts_to_renew.remove(vhost)
            if not vhosts_to_renew:
                continue

            # Okay, we have something we can renew
            print 'sudo -u letsencrypt -i letsencrypt [33m' + ' '.join(vhosts_to_renew) + '[m'
            for vhost in vhosts_to_renew:
                if vhost.startswith('--group'):
                    cert_filename = vhost.split(' ')[1] + '.group'
                else:
                    cert_filename = self.vhosts[vhost]['domains'][0]
                print 'cp /data/letsencrypt/certificates/%s.crt /data/letsencrypt/certificates/%s.key /data/servers/certificates/' % (cert_filename, cert_filename)
                for server in self.server_lookup.get(vhost, []):
                    server = '[32m%s[m' % server
                    print 'sudo scp /data/servers/certificates/%s.crt %s:/etc/nginx/ssl.crt/' % (cert_filename, server)
                    print 'sudo scp /data/servers/certificates/%s.key %s:/etc/nginx/ssl.key/' % (cert_filename, server)
                    print 'sudo ssh %s /etc/init.d/nginx reload' % server

    @staticmethod
    def get_cert_data():
        for crt in sorted(glob.glob('/data/servers/certificates/*.crt')):
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
        return parser


if __name__ == '__main__':
    cmc = CertRenewerCallable()
    cmc()

