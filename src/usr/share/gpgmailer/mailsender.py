
# Copyright 2015-2016 Joel Allen Luellwitz and Andrew Klapp
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import random
import smtplib
import time

class MailSender:
    def __init__(self, config):
        self.logger = logging.getLogger()

        self.config = config
        self.smtp = None

        self._connect()
        self.lastSentTime = time.time()

    def _connect(self):
        # TODO: Failed DNS lookups of the mail server might be eating messages. Investigate immediately.
        self.logger.info('Connecting.')
        if (self.smtp != None):
            # I originally tried to quit the existing SMTP session here, but that just slowed things down
            #   too much and usually threw an exception.
            self.smtp = None
        
        # Create a random number as our host id
        self.logger.debug('Generating random ehlo.')
        self.ehlo_id = str(random.SystemRandom().random()).split('.', 1)[1]
        self.logger.debug('Random ehlo generated.')
        connected = False
        while not(connected):
	    try:
                self.smtp = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'], self.ehlo_id, int(self.config['smtp_sending_timeout']))
                self.logger.debug('starttls.')
                self.smtp.starttls()
                self.logger.debug('smtp.login.')
                self.smtp.login(self.config['smtp_user'], self.config['smtp_pass'])
                self.logger.info('Connected!')
                connected = True
            except smtplib.SMTPAuthenticationError, e:
                # TODO: Decide how to handle authentication errors
                self.logger.error('Failed to connect. Authentication error. Exception %s:%s' % (type(e).__name__, e.message))
                # TODO: Make this configurable?
                time.sleep(.1)
            except smtplib.SMTPDataError, e:
                # TODO: Backoff strategy
                self.logger.error('Failed to connect. Invalid response from server. Exception %s:%s' % (type(e).__name__, e.message))
                # TODO: Make this configurable?
                time.sleep(.1)
            except Exception, e:
                self.logger.error('Failed to connect. Waiting to try again. Exception %s:%s' % (type(e).__name__, e.message))
                # TODO: Make this configurable?
                time.sleep(.1)

    def sendmail(self, message_string):
        sent_successfully = False

        # Get a list of recipients from config
        recipients = []
        for recipient in self.config['recipients']:
            recipients.append(recipient['email'])

        # Mail servers will probably deauth you after a fixed period of inactivity.
        # TODO: There is probably also a hard session limit too.
        if (time.time() - self.lastSentTime) > self.config['smtp_max_idle']:
            self.logger.info("Assuming the connection is dead.")
            self._connect()


        if not(message_string == None):
            try:
                self.smtp.sendmail(self.config['sender']['email'], recipients, message_string)
                sent_successfully = True
            except Exception as e:
                self.logger.error("Failed to send: %s: %s\n" % (type(e).__name__, e.message))
                self.logger.error(traceback.format_exc())

                # Try reconnecting and resending
                self._connect()
                self.smtp.sendmail(self.config['sender']['email'], recipients, message_string)
                sent_successfully = True
            self.lastSentTime = time.time()
        else:
            self.logger.error('Message is empty, encryption or signing failed, not sending.')

        return sent_successfully
