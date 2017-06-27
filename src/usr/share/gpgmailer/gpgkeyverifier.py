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

import gpgmailmessage
import logging
import time

# Raised when there are no current keys available for encryption.
class NoUsableKeysException:
    pass

# Raised when the sender key expires during runtime and sending unsigned messages
#   is not allowed.
class SenderKeyExpiredException:
    pass

# Manages a list of recipients where the key has not expired and constructs warning
#   messages for keys that have expired or are about to expire.
class GpgKeyVerifier:
    # Reads recipients from the config dict and adds them to its' own and builds a
    #   map from fingerprints to addresses.
    #
    # gpgkeyring: a gpgkeyring object
    # config: a config dictionary from gpgmailer-daemon
    def __init__(self, gpgkeyring, config):
        self.logger = logging.getLogger('GpgKeyVerifier')
        self.gpgkeyring = gpgkeyring
        self.config = config

        self.all_addresses = {}
        self.recipients = []
        self.valid_recipients = []
        self.valid_keys = []
        self.expiration_message = ''
        self.expiration_email_message = ''
        self.next_key_check_time = 0

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


    # Return a list of valid keys.
    def get_valid_keys(self, loop_start_time):
        self._update_if_info_is_stale(loop_start_time)
        return self.valid_keys


    # Return a list of recipients that have valid keys associated with them.
    def get_valid_recipients(self, loop_start_time):
        self._update_if_info_is_stale(loop_start_time)
        return self.valid_recipients


    # Return a string describing keys that have expired or will expire "soon"
    #   as defined in the config file.
    def get_expiration_message(self, loop_start_time):
        self._update_if_info_is_stale(loop_start_time)
        return self.expiration_message


    # Calculates which recipients and keys are valid and assembles an expiration
    #   warning message, with expiration checks based on the loop_start_time
    #   parameter.
    #
    # loop_start_time: the time to base all expiration checks on
    def _calculate_recipient_info(self, loop_start_time):
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

        self.logger.trace('Checking sender key.')
        sender_expiration_data = self._build_key_expiration_message(self.sender, loop_start_time)

        if sender_expiration_data['expiration_message']:
            if ('has expired' in expiration_data['expiration_message']):
                if not(config['allow_expired_signing_key']):
                    raise SenderKeyExpiredException()

            else:
                valid_keys.append(self.all_addresses[self.sender]['fingerprint'])
                valid_recipients.append(self.sender)

            expired_messages.append(sender_expiration_data['expiration_message'])
            if sender_expiration_data['send_email']:
                expiration_warning_email_message = 'A new key has expired.\n\n'

        else:
            valid_keys.append(self.all_addresses[self.sender]['fingerprint'])
            valid_recipients.append(self.sender)


        self.logger.trace('Checking recipient keys.')

        # TODO: Eventually, optimize all key checking, not just sender key. Maybe have a list
        #   of checked fingerprints.
        for email in self.recipients:
            if self.all_addresses[email]['is_sender']:
                self.logger.trace('Recipient %s is also a sender.' % email)
                expiration_data = sender_expiration_data

            else:
                expiration_data = self._build_key_expiration_message(email, loop_start_time)

                if 'has expired' in expiration_data['expiration_message']:
                    expired_messages.append(expiration_data['expiration_message'])

                else:
                    if 'will expire on' in expiration_data['expiration_message']:
                        expiring_soon_messages.append(expiration_data['expiration_message'])

                    valid_keys.append(self.all_addresses[email['fingerprint']])
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


        self.valid_recipients = valid_recipients
        self.valid_keys = valid_keys
        self.expiration_message = all_expiration_messages.strip()
        self.expiration_email_message = expiration_warning_email_message.strip()


    # Build an expiration message for an individual email and fingerprint pair,
    #   checking expiration based on loop_start_time and configured expiration
    #   windows.
    #
    # email: the email associated with the expired key
    # loop_start_time: the time to base all expiration checks on
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
            key_expiration_date = self.gpgkeyring.get_key_expiration_date(fingerprint, date_format='%Y-%m-%d %H:%M:%S')
            expiration_message = ('%s key %s (%s) will expire on date %s.' % (address_type, fingerprint, email, key_expiration_date))
            self.logger.trace(expiration_message)

            if not(self.all_addresses[email]['expiring_soon_email_sent']):
                send_email = True
                self.logger.warn(expiration_message)
                self.all_addresses[email]['expiring_soon_email_sent'] = True

        else:
            self.logger.trace('Key %s (%s) is current.' % (fingerprint, email))

        return { 'expiration_message': expiration_message,
            'send_email': send_email }


    # Determine whether the current recipient information is valid for the next
    #   full loop. If it isn't, recalculate.
    #
    # loop_start_time: the time to base all expiration checks on
    def _update_if_info_is_stale(self, loop_start_time):
        info_is_stale = time.time() + self.config['key_check_interval'] < loop_start_time

        if info_is_stale or not self.valid_keys:
            self._calculate_recipient_info(loop_start_time)
            self.next_key_check_time = time.time() + self.config['key_check_interval']
