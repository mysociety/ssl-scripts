#!/usr/bin/env python

import collections
import json
import os
import subprocess
import sys


class Vhosts(collections.Mapping):
    def __init__(self, vhosts_pl_path="/data/servers/vhosts.pl"):
        self.vhosts = self._parse_vhosts_pl(vhosts_pl_path)
        # Special additions
        self.vhosts['mx0.mysociety.org'] = {
            'ssl_group': 'Mail',
            'servers': ['bittern', 'starling'],
            'aliases': ['mx1.mysociety.org', 'mx0.ukcod.org.uk', 'mx1.ukcod.org.uk']
        }
        self.vhosts['git.mysociety.org'] = {
            'ssl_group': 'mySociety',
            'servers': ['leopard', 'panther', 'kingfisher', 'raven'],
            'aliases': ['debian.mysociety.org', 'nagios.mysociety.org', 'nagios-external.mysociety.org',
                'git.mysociety.org', 'icinga.mysociety.org', 'icinga-external.mysociety.org', 
                'grafana.mysociety.org', 'puppetboard.mysociety.org'
            ]
        }
        self.vhosts['mysocietyemergency.org'] = {
            'servers': ['emergency'],
            'aliases': ['www.mysocietyemergency.org']
        }

    def __getitem__(self, key):
        vhost = self.vhosts[key]
        vhost['domains'] = self._get_vhost_domains(key, vhost)
        return vhost

    def __len__(self):
        return len(self.vhosts)

    def __iter__(self):
        return iter(self.vhosts)

    def _get_vhost_domains(self, vhost_name, data):
        # Determine CN and SAN names
        aliases = data.get('aliases', [])
        redirects = data.get('redirects', [])
        ignore = data.get('https_ignore', [])
        if not isinstance(ignore, list):
            ignore = [ignore]

        dns_names = set()
        dns_names.add(vhost_name)
        dns_names.update(aliases)
        dns_names.update(redirects)

        if vhost_name in redirects:
            cn = aliases[0]
        else:
            cn = vhost_name
        dns_names.remove(cn)

        if cn in ignore:
            cn = dns_names.pop()
        dns_names -= set(ignore)

        return [cn] + sorted(list(dns_names))

    def _parse_vhosts_pl_section(self, vhosts_pl_path, section):
        return json.loads(subprocess.check_output([
            'perl', '-e', 'use JSON; require "' + vhosts_pl_path + '"; print encode_json($' + section + ');'
        ]))

    def _parse_vhosts_pl(self, vhosts_pl_path):
        vhosts = self._parse_vhosts_pl_section(vhosts_pl_path, 'vhosts')
        return vhosts
