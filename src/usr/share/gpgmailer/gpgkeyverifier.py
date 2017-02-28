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

import datetime
import gpgmailmessage
import logging
import time

# TODO: Comment.
class GpgKeyVerifier:
    def __init__(self, gpgkeyring, config):
        self.logger = logging.getLogger('GpgKeyVerifier')
        self.gpgkeyring = gpgkeyring
        self.config = config

        self.recipient_index = {}

        for recipient in config['recipients']:
            recipient_dict = { 'fingerprint': recipient['fingerprint'],
            'expired_email_sent': False,
            'expiring_soon_email_sent': False }

            self.recipient_index[recipient['email']] = recipient_dict

        self.first_run = True

        self.sender_key_expired_email_sent = False
        self.sender_key_expiring_soon_email_sent = False

    # This method processes all of the recipients in the config, returns a list of 
    #   recipients with valid keys, the valid key fingerprints themselves, and
    #   whether or not to send a separate expiration message email.
    def get_recipient_info(self, loop_start_time):
        self.logger.info('Rebuilding recipient information.')
        valid_recipients = []
        valid_keys = []
        expired_messages = []
        expiring_soon_messages = []
        send_email = False

        expiration_date = loop_start_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        sender_expiration = self._build_sender_expiration_message(loop_start_time)
        send_email = sender_expiration['send_email']
        sender_expiration_message = sender_expiration['expiration_message']

        if self.first_run:
            send_email = True
            self.first_run = False
            sender_expiration_message += 'Gpgmailer just restarted. Here is a list of keys that are expired or will be expiring soon.'


        for email in self.recipient_index.keys():
            # Check for expiry during the current loop.
            #   Build an appropriate message and set
            # Check for expiry during the expiration threshold
            #   Build an appropriate message

            fingerprint = self.recipient_index[email]['fingerprint']

            if self.gpgkeyring.is_current(fingerprint, expiration_date):
                message = 'Key <%s> (%s) is expired.' % (fingerprint, email)
                self.logger.warn(message)
                expired_messages.append(message)

                if not(self.recipient_index[email]['expired_email_sent']):
                    send_email = True
                    self.recipient_index[email]['expired_email_sent'] = True

            elif self.gpgkeyring.is_current(fingerprint, expiring_soon_date):
                key_expiration_date = self.gpgkeyring.get_key_expiration_date(fingerprint)
                pretty_expiration_date = datetime.datetime.fromtimestamp(key_expiration_date).strftime('%Y-%m-%d %H:%M:%S')
                message = ('Key <%s> (%s) will expire soon on date %s.' % (fingerprint, email, pretty_expiration_date))
                self.logger.warn(message)
                expiring_soon_messages.append(message)

                if not(self.recipient_index[email]['expiring_soon_email_sent']):
                    send_email = True
                    self.recipient_index[email]['expiring_soon_email_sent'] = True

            else:
                self.logger.trace('Key %s is current.' % fingerprint)
                valid_recipients.append(email)

                if not(fingerprint in valid_keys):
                    valid_keys.append(fingerprint)

        joined_expired_messages = '\n'.join(expired_messages)
        joined_expiring_soon_messages = '\n'.join(expiring_soon_messages)

        expiration_message = '\n'.join([sender_expiration_message, joined_expired_messages, joined_expiring_soon_messages])

        
        recipient_info = { 'valid_recipients': valid_recipients,
            'valid_keys': valid_keys,
            'expiration_message': expiration_message,
            'send_email': send_email }

        return recipient_info

    def _build_sender_expiration_message(self, loop_start_time):
        expiration_message = ''
        send_email = False

        expiration_date = loop_start_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        email = self.config['sender']['email']
        fingerprint = self.config['sender']['fingerprint']
        
        if not(self.gpgkeyring.is_current(fingerprint, expiration_date)):
            expiration_message = 'Sender key <%s> (%s) has expired.' % (fingerprint, email)
            self.sender_key_expired_email_sent = True
            send_email = True

        elif not(self.gpgkeyring.is_current(fingerprint, expiring_soon_date)):
            key_expiration_date = self.gpgkeyring.get_key_expiration_date(fingerprint)
            pretty_expiration_date = datetime.datetime.fromtimestamp(key_expiration_date).strftime('%Y-%m-%d %H:%M:%S')
            expiration_message = 'Sender key <%s> (%s) will be expiring soon on date %s.' % (fingerprint, email, pretty_expiration_date)
            self.sender_key_expiring_soon_email_sent = True
            send_email = True

        return {'expiration_message': expiration_message,
            'send_email': send_email }
