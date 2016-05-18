# -*- coding: utf-8 -*-
'''
Reference:
https://stat.ripe.net/docs/data_api
https://github.com/RIPE-NCC/whois/wiki/WHOIS-REST-API-abuse-contact

TODO: Load RIPE networks prefixes into memory.
TODO: Compare each IP with networks prefixes loaded.
TODO: If ip matches, query RIPE
'''
import sys
import ast

from intelmq.bots.experts.ripencc_abuse_contact import lib
from intelmq.lib.bot import Bot
from intelmq.lib.cache import Cache
from intelmq.lib.harmonization import IPAddress

MINIMUM_BGP_PREFIX_IPV4 = 24
MINIMUM_BGP_PREFIX_IPV6 = 128  # FIXME

class RIPENCCExpertBot(Bot):

    def init(self):
        self.query_db_asn = getattr(self.parameters, 'query_ripe_db_asn', True)
        self.query_db_ip = getattr(self.parameters, 'query_ripe_db_ip', True)
        self.query_stat_asn = getattr(self.parameters, 'query_ripe_stat', True)
        self.query_stat_ip = getattr(self.parameters, 'query_ripe_stat', True)
        self.cache = Cache(self.parameters.redis_cache_host,
                           self.parameters.redis_cache_port,
                           self.parameters.redis_cache_db,
                           self.parameters.redis_cache_ttl,
                           )

    def process(self):
        event = self.receive_message()

        if event is None:
            self.acknowledge_message()
            return

        for key in ['source.', 'destination.']:
            ip_key = key + "ip"
            abuse_key = key + "abuse_contact"
            asn_key = key + "asn"

            ip = event.get(ip_key, None)
            if not ip:
                continue
            ip_version = IPAddress.version(ip)
            ip_integer = IPAddress.to_int(ip)

            if ip_version == 4:
                minimum = MINIMUM_BGP_PREFIX_IPV4

            elif ip_version == 6:
                minimum = MINIMUM_BGP_PREFIX_IPV6

            else:
                raise ValueError('Unexpected IP version '
                                 '{!r}.'.format(ip_version))

            cache_key = bin(ip_integer)[2: minimum + 2]
            cache_result = self.cache.get(cache_key)

            abuse = (event.get(abuse_key).split(',') if abuse_key in event
                     else [])

            if cache_result:
                cache_result = ast.literal_eval(cache_result)
                cache_result = [n.strip() for n in cache_result]
                abuse.extend(cache_result)

            else:
                asn = event.get(asn_key, None)
                if self.query_db_asn and asn:
                    abuse.extend(lib.query_asn(asn))
                if self.query_db_ip and ip:
                    abuse.extend(lib.query_ripedb(ip))
                if self.query_stat_asn and asn:
                    abuse.extend(lib.query_ripestat(asn))
                if self.query_stat_ip and ip:
                    abuse.extend(lib.query_ripestat(ip))
                self.cache.set(cache_key,abuse)

            event.add(abuse_key, ','.join(filter(None, set(abuse))), force=True)

        self.send_message(event)
        self.acknowledge_message()

if __name__ == "__main__":
    bot = RIPENCCExpertBot(sys.argv[1])
    bot.start()
