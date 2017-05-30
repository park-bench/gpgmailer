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
import traceback


# Maintains an SMTP connection and sends emails.
class MailSender:
    def __init__(self, config):
        self.logger = logging.getLogger('MailSender')

        self.config = config
        self.smtp = None

        self._connect()

        # Used to determine SMTP session idle time.
        self.lastSentTime = time.time()

    # Attempts to connect to the configured mail server.
    def _connect(self):
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
                self.smtp = smtplib.SMTP(self.config['smtp_domain'], self.config['smtp_port'], self.ehlo_id, int(self.config['smtp_sending_timeout']))
                self.logger.debug('starttls.')
                self.smtp.starttls()
                self.logger.debug('smtp.login.')
                self.smtp.login(self.config['smtp_username'], self.config['smtp_password'])
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
                self.logger.error(traceback.format_exc())
                # TODO: Make this configurable?
                time.sleep(.1)

    # TODO: Make this comment more useful.
    # Sends an email from a string.
    def sendmail(self, message_string, recipients):
        # TODO: Eventually, send encrypted messages to all recipients,
        #   regardless of whether it was encrypted with their key, so that they
        #   are aware that mail is being sent. Make it an option.

        # Mail servers will probably deauth you after a fixed period of inactivity.
        # TODO: There is probably also a hard session limit too.
        if (time.time() - self.lastSentTime) > self.config['smtp_max_idle']:
            self.logger.info('Max idle time reached, assuming the SMTP connection has been remotely severed.')
            self._connect()

        try:
            self.smtp.sendmail(self.config['sender']['email'], recipients, message_string)
        except Exception as e:
            self.logger.error('Failed to send: %s: %s\n' % (type(e).__name__, e.message))
            self.logger.error(traceback.format_exc())
            self.logger.info('Retrying.')

            # Try reconnecting and resending
            self._connect()
            self.smtp.sendmail(self.config['sender']['email'], recipients, message_string)

        self.lastSentTime = time.time()
