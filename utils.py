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
            'servers': ['ocelot', 'leopard', 'crow', 'pelican'],
            'aliases': ['mx1.mysociety.org', 'mx0.ukcod.org.uk', 'mx1.ukcod.org.uk', 'mailbox.mysociety.org', ]
        }
        self.vhosts['git.mysociety.org'] = {
            'ssl_group': 'mySociety',
            'servers': ['leopard', 'ocelot', 'vesta', 'panther', 'kingfisher'],
            'aliases': ['debian.mysociety.org', 'nagios.mysociety.org', 'nagios-external.mysociety.org',
                'cacti.mysociety.org', 'puppet-dashboard.mysociety.org', 'git.mysociety.org',
                'icinga.mysociety.org', 'icinga-external.mysociety.org'
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

    def _parse_vhosts_pl_section(self, vhosts_pl_path, section):
        return json.loads(subprocess.check_output([
            'perl', '-e', 'use JSON; require "' + vhosts_pl_path + '"; print encode_json($' + section + ');'
        ]))

    def _parse_vhosts_pl(self, vhosts_pl_path):
        vhosts = self._parse_vhosts_pl_section(vhosts_pl_path, 'vhosts')
        return vhosts
