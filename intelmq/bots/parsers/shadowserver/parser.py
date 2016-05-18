import csv
import sys
import ipaddress
from io import StringIO
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event
from intelmq.lib import utils

if sys.version_info[0] == 2:
    import unicodecsv as csv
else:
    import csv


class ShadowServerParserBot(Bot):

    def process(self):
        report = self.receive_message()

        columns = self.parameters.columns

        if not report or not report.contains("raw"):
            self.acknowledge_message()
            return

        if report:
            raw_report = utils.base64_decode(report.get("raw"))

            rows = csv.DictReader(StringIO(raw_report))

            for row in rows:
                event = Event(report)

                for key, value in row.items():

                    key = columns[key]

                    if not value:
                        continue

                    value = value.strip()

                    if key == u'__IGNORE__' or key == u'__TBD__':
                        continue

                    # set timezone explicitly to UTC as it is absent in the input 
                    if key == "time.source":
                        value += " UTC"

                    if "hash" in key:
                        key = key.replace(':','')

                    #if "reverse_dns" in key:
                        #try:
                        #       ipaddress.ip_address(value)
                        #       continue
                        #except:
                        #       pass

                    if key == "destination.geolocation.cc" and (value == "**" or value =="--" or value == "??"):
                        continue

                    #There are a lot of non harmonizable values in reverse_dns, i decided to ignore them when they are wrong.   
                    if "reverse_dns" in key:
                        try:
                                event.add(key, value, sanitize= True)
                        except:
                                continue
                    else:
                        event.add(key, value, sanitize= True)

                event.add('classification.type', u'vulnerable service')

                self.addextraparams(event, event.get('feed.name'))

                self.send_message(event)
        self.acknowledge_message()

    def addextraparams(self, event, feedname):
        if feedname == 'shadowserver-dnsopenresolver':
                event.add('protocol.application',u'dns')
                event.add('classification.identifier',u'dns')

        elif feedname == 'shadowserver-drone' or feedname == 'shadowserver-mssinkhole':
                event.update('classification.type',u'botnet drone')
                event.add('classification.identifier',u'botnet')

        elif feedname == 'shadowserver-ipmi':
                event.add('protocol.application',u'ipmi')
                event.add('classification.identifier',u'ipmi')

        elif feedname == 'shadowserver-mongodb':
                event.add('protocol.application',u'mongodb')
                event.add('classification.identifier',u'mongodb')

        elif feedname == 'shadowserver-nat-pmp':
                event.add('protocol.application',u'nat-pmp')
                event.add('classification.identifier',u'nat-pmp')

        elif feedname == 'shadowserver-netbios':
                event.add('protocol.application',u'netbios')
                event.add('classification.identifier',u'netbios')

        elif 'ntp' in feedname:
                event.add('protocol.application',u'ntp')
                event.add('classification.identifier',u'ntp')

        elif feedname == 'shadowserver-sslpoodle':
                event.add('protocol.application',u'ssl')
                event.add('classification.identifier',u'ssl')

        elif feedname == 'shadowserver-qotd':
                event.add('protocol.application',u'qotd')
                event.add('classification.identifier',u'qotd')

        elif feedname == 'shadowserver-redis':
                event.add('protocol.application',u'redis')
                event.add('classification.identifier',u'redis')
        elif feedname == 'shadowserver-httpdrone':
                event.add('protocol.application',u'http')
                event.update('classification.type',u'botnet drone')
                event.add('classification.identifier',u'botnet')

        elif feedname == 'shadowserver-snmp':
                event.add('protocol.application',u'snmp')
                event.add('classification.identifier',u'snmp')

        elif feedname == 'shadowserver-ssdp':
                event.add('protocol.application',u'ssdp')
                event.add('classification.identifier',u'ssdp')

        elif feedname == 'shadowserver-portmapper':
                event.add('protocol.application',u'portmapper')
                event.add('classification.identifier',u'portmapper')

        elif feedname == 'shadowserver-elasticsearch':
                event.add('protocol.application',u'elasticsearch')
                event.add('classification.identifier',u'elasticsearch')



if __name__ == "__main__":
    bot = ShadowServerParserBot(sys.argv[1])
    bot.start()

