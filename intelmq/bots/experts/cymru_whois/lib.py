# -*- coding: utf-8 -*-
"""
Reference: http://www.team-cymru.org/Services/ip-to-asn.html#dns
"""
import io

import dns.resolver

import intelmq.lib.utils as utils
from intelmq.lib.harmonization import IPAddress

IP_QUERY = "%s.origin%s.asn.cymru.com"
ASN_QUERY = "AS%s.asn.cymru.com"


class Cymru():

    @staticmethod
    def query(ip):
        raw_result = Cymru.__ip_query(ip)
        result = Cymru.__ip_query_parse(raw_result)

        if "asn" in result:
            raw_result = Cymru.__asn_query(result['asn'])
            extra_info = Cymru.__asn_query_parse(raw_result)
            result.update(extra_info)

        return result

    @staticmethod
    def __query(query):
        try:
            for query_result in dns.resolver.query(query, rdtype='TXT'):
                fp = io.BytesIO()
                query_result.to_wire(fp)
                value = fp.getvalue()[1:]  # ignore first character
                fp.close()
                return utils.decode(value)

        except dns.exception.DNSException:
            return None

    @staticmethod
    def __ip_query(ip):
        ip_version = IPAddress.version(ip)
        reverse_ip = IPAddress.to_reverse(ip)

        if ip_version == 4:
            reverse = reverse_ip.split('.in-addr.arpa.')[0]
            version = ""
        else:
            reverse = reverse_ip.split('.ip6.arpa.')[0]
            version = "6"

        query = IP_QUERY % (reverse, version)
        return Cymru.__query(query)

    @staticmethod
    def __asn_query(asn):
        query = ASN_QUERY % (asn)
        return Cymru.__query(query)

    @staticmethod
    def __query_parse(text):
        items = list()
        for item in text.split('|'):
            item = item.replace('"', '')
            item = item.strip()
            if item == "NA" or item == "":
                item = None
            items.append(item)
        return items

    @staticmethod
    def __ip_query_parse(text):
        """
        Example:   "1930       | 193.136.0.0/15  | PT | ripencc |"
        Exception: "9395 17431 | 219.234.80.0/20 | CN | apnic   | 2002-04-17"
        """

        result = dict()

        if not text:
            return result

        items = Cymru.__query_parse(text)

        if items[0]:
            # In case of multiple ASNs received, get the first one.
            asn = items[0].split(' ')[0]
            try:
                int(asn)
                result['asn'] = asn
            except:
                pass

        if items[1]:
            result['network'] = items[1]

        if items[2]:
            result['geolocation.cc'] = items[2]

        if items[3]:
            result['registry'] = items[3]

        if items[4]:
            result['allocated'] = items[4] + 'T00:00:00+00:00'

        return result

    @staticmethod
    def __asn_query_parse(text):
        """
        Example:   "23028 | US | arin    | 2002-01-04 | TEAM-CYMRU - Team Cymru
        Inc.,US"
        Exception: "1930  | EU | ripencc |            | RCCN Rede Ciencia
        Tecnologia e Sociedade (RCTS),PT"
        """

        result = dict()

        if not text:
            return result

        items = Cymru.__query_parse(text)

        if items[4]:
            result['as_name'] = items[4]

        return result
