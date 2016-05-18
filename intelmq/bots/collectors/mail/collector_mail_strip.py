import re
import imbox
import zipfile
import requests
from intelmq.lib.bot import Bot, sys
from intelmq.bots.collectors.mail.lib import Mail

from intelmq.lib.harmonization import DateTime
from intelmq.lib.message import Report
import intelmq.lib.utils as utils

class MailStripCollectorBot(Bot):

    def process(self):
        mailbox = imbox.Imbox(self.parameters.mail_host, self.parameters.mail_user, utils.base64_decode(self.parameters.mail_password), self.parameters.mail_ssl)
        self.logger.info("Connected to mail server")
        emails = mailbox.messages(folder=self.parameters.folder, unread=True)
        try:
            if emails:
                    self.logger.info("Parsing emails in mailbox")
                    for uid, message in emails:
                        if self.parameters.subject_regex and not re.search(self.parameters.subject_regex, message.subject):
                            continue
                        self.logger.info("Reading email report")

                        if hasattr(message,'attachments') and message.attachments:
                                for attach in message.attachments:
                                    if not attach:
                                        continue

                                    attach_name = attach['filename'][1:len(attach['filename'])-1] # remove quote marks from filename
                                    if re.search(self.parameters.attach_regex, attach_name):

                                        self.logger.info("Parsing attachment")
                                        if self.parameters.attach_unzip:
                                            zipped = zipfile.ZipFile(attach['content'])
                                            raw_report = zipped.read(zipped.namelist()[0])
                                        else:
                                            raw_report = attach['content'].read()

                                        self.logger.info('content read')
                                        report = Report()
                                        report.add("raw", raw_report, sanitize=True)
                                        report.add("feed.name", self.parameters.feed,sanitize=True)
                                        report.add("feed.accuracy", self.parameters.accuracy, sanitize=True)
                                        time_observation = DateTime().generate_datetime_now()
                                        #report.add('time.observation', time_observation)
                                        report.add('feed.reportname', message.subject, sanitize=True)
                                        self.logger.info('rocking in a free world')

                                        self.send_message(report)
                                self.logger.info('just some administration left')
                                mailbox.mark_seen(uid)
                                self.logger.info("Email report read")
                        else:
                                # If no attachment, read from url
                                # update way of fetching from url to new way in http/
                                self.logger.info("No attachment found, trying collecting from URL")
                                for body in message.body['plain']:
                                    self.logger.info("Parsing message body")
                                    match = re.search(self.parameters.url_regex, body)
                                    if match:
                                        url = match.group()

                                        self.logger.info("Downloading report from %s" % url)
                                        resp = requests.get(url=url)
                                        if resp.status_code // 100 != 2: 
                                            raise ValueError('HTTP response status code was {}.' ''.format(resp.status_code))

                                        raw_report = resp.content

                                        self.logger.info("Report downloaded.")

                                        report = Report()
                                        report.add("raw", raw_report, sanitize=True)
                                        report.add("feed.name", self.parameters.feed, sanitize=True)
                                        report.add("feed.accuracy", self.parameters.accuracy, sanitize=True)
                                        self.logger.info("all is well sir")
                                        time_observation = DateTime().generate_datetime_now()
                                        #report.add('time.observation', time_observation, sanitize=True)
                                        report.add('feed.reportname', message.subject, sanitize=True)

                                        self.send_message(report)

                                mailbox.mark_seen(uid)
                                self.logger.info("Email report read")
        except:
                self.logger.info("ERROR with the collector ---")
if __name__ == "__main__":
    bot = MailStripCollectorBot(sys.argv[1])
    bot.start()

