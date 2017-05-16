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

# Raised when there are no current keys available for encryption.
class NoUsableKeysException:
    pass

# Manages a list of recipients where the key has not expired and constructs warning
#   messages for keys that have expired or are about to expire.
class GpgKeyVerifier:
    def __init__(self, gpgkeyring, config):
        self.logger = logging.getLogger('GpgKeyVerifier')
        self.gpgkeyring = gpgkeyring
        self.config = config

        self.all_addresses = {}
        self.recipients = []

        for recipient in config['recipients']:
            recipient_dict = { 'fingerprint': recipient['fingerprint'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False,
                'is_sender': False,
                'is_recipient': True }

            self.all_addresses[recipient['email']] = recipient_dict
            self.recipients.append(recipient['email'])

        sender_email = config['sender']['email']

        if sender_email in self.all_addresses.keys():
            self.all_addresses[sender_email]['is_sender'] = True

        else:
            sender_dict = { 'fingerprint': config['sender']['fingerprint'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False,
                'is_sender': True,
                'is_recipient': False}

            self.all_addresses[sender_email] = sender_dict

        self.sender = sender_email

    # TODO: Explain what the separate expiration email is.
    # TODO: If it builds the first run email, the comment should say that.
    # TODO: Explain what loop_start_time is.
    # TODO: Break this method up some more.
    # This method processes all of the recipients in the config, returns a list of 
    #   recipients with valid keys, the valid key fingerprints themselves, and
    #   whether or not to send a separate expiration message email.
    def get_recipient_info(self, loop_start_time):
        self.logger.trace('Recalculating the list of keys that are about to expire.')
        all_expiration_messages = []
        expiration_warning_email_message = ''
        expired_messages = []
        expiring_soon_messages = []
        send_email = False
        valid_recipients = []
        valid_keys = []

        expiration_date = loop_start_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        # TODO: Change this to sender_key_expiration_message.
        sender_expiration = self._build_sender_expiration_message(loop_start_time)
        send_email = sender_expiration['send_email']
        expired_messages.append(sender_expiration['expiration_message'])

        # TODO: Process sender key separately.

        self.logger.trace('Checking recipient keys.')

        for email in self.recipients:
            if self.all_addresses[email]['is_sender']:
                self.logger.trace('Recipient %s is also a sender. Skipping.' % email)

            else:
                expiration_data = self._build_key_expiration_message(email, loop_start_time)

                if 'has expired' in expiration_data['expiration_message']:
                    expired_messages.append(expiration_data['expiration_message'])

                else:
                    if 'will expire on' in expiration_data['expiration_message']:
                        expiring_soon_messages.append(expiration_data['expiration_message'])

                    valid_keys.append(self.all_addresses[email['fingerprint'])
                    valid_recipients.append(email)

                if expiration_data['send_email']:
                    expiration_warning_email_message = 'A new key has expired.\n\n'

        if(valid_keys == []):
            raise NoUsableKeysException()

        if(expired_messages or expiring_soon_messages):
            expired_messages.insert(0, 'Here are the keys that have expired or will be expiring soon:')


        all_expiration_messages = '\n'.join(expired_messages + expiring_soon_messages)

        if expiration_warning_email_message:
            expiration_warning_email_message = '%s%s' (expiration_warning_email_message, all_expiration_messages)


        recipient_info = { 'valid_recipients': valid_recipients,
            'valid_keys': valid_keys,
            'expiration_message': expiration_message.strip(),
            'expiration_email_message': expiration_email_message.strip()}

        return recipient_info

    # Build an expiration message for an individual email and fingerprint pair,
    #   checking expiration based on loop_start_time and configured expiration
    #   windows.
    def _build_key_expiration_message(self, email, loop_start_time):
        self.logger.trace('Building expiration message for address %s.' % email)

        expiration_message = ''
        send_email = False
        expiration_date = loop_start_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']
        fingerprint = self.all_addresses[email]['fingerprint']

        if self.all_addresses[email]['is_sender']:
            address_type = 'Sender'

        else:
            address_type = 'Recipient'

        if not(self.gpgkeyring.is_current(fingerprint, expiration_date)):
            expiration_message = '%s key %s (%s) has expired.' % (address_type, fingerprint, email)
            self.logger.trace(expiration_message)

            if not(self.all_addresses[email]['expired_email_sent']):
                send_email = True
                self.logger.warn(expiration_message)
                self.all_addresses[email]['expired_email_sent'] = True

        elif not(self.gpgkeyring.is_current(fingerprint, expiring_soon_date)):
            key_expiration_date = self.gpgkeyring.get_key_expiration_date(fingerprint)
            pretty_expiration_date = datetime.datetime.fromtimestamp(key_expiration_date).strftime('%Y-%m-%d %H:%M:%S')
            expiration_message = ('%s key %s (%s) will expire on date %s.' % (address_type, fingerprint, email, pretty_expiration_date))
            self.logger.trace(expiration_message)

            if not(self.all_addresses[email]['expiring_soon_email_sent']):
                send_email = True
                self.logger.warn(expiration_message)
                self.all_addresses[email]['expiring_soon_email_sent'] = True

        else:
            self.logger.trace('Key %s (%s) is current.' % (fingerprint, email))

        return { 'expiration_message': expiration_message,
            'send_email': send_email }

    # TODO: Rename to _build_sender_key_expiration_message
    # TODO: Method comment.
    # TODO: Similar to get_recipient_info, see if it can be consolidated.
    def _build_sender_expiration_message(self, loop_start_time):
        self.logger.trace('Building sender expiration message.')
        expiration_message = ''
        send_email = False

        expiration_date = loop_start_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        email = self.config['sender']['email']
        fingerprint = self.config['sender']['fingerprint']
        
        # TODO: This happens twice. See if it can be only done once.
        if not(self.gpgkeyring.is_current(fingerprint, expiration_date)):
            expiration_message = 'Sender key %s (%s) has expired.' % (fingerprint, email)
            if not(self.sender_key_expired_email_sent):
                self.sender_key_expired_email_sent = True
                send_email = True

        elif not(self.gpgkeyring.is_current(fingerprint, expiring_soon_date)):
            key_expiration_date = self.gpgkeyring.get_key_expiration_date(fingerprint)
            pretty_expiration_date = datetime.datetime.fromtimestamp(key_expiration_date).strftime('%Y-%m-%d %H:%M:%S')
            expiration_message = 'Sender key %s (%s) will expire on date %s.' % (fingerprint, email, pretty_expiration_date)
            if not(self.sender_key_expiring_soon_email_sent):
                self.sender_key_expiring_soon_email_sent = True
                send_email = True

        self.logger.trace(expiration_message)

        return {'expiration_message': expiration_message,
            'send_email': send_email }
