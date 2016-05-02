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

                    event.add(key, value, sanitize= True)

                event.add('classification.type', u'vulnerable service')


                self.send_message(event)
        self.acknowledge_message()

if __name__ == "__main__":
    bot = ShadowServerParserBot(sys.argv[1])
    bot.start()
