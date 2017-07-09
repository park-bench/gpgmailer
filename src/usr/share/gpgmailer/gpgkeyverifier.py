# Copyright 2015-2017 Joel Allen Luellwitz and Andrew Klapp
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
class NoUsableKeysException(Exception):
    pass

# Raised when the sender key expires during runtime and sending unsigned messages
#   is not allowed.
class SenderKeyExpiredException(Exception):
    pass

# Manages expiration information for the sender, recipients, and key expiration warning messages
#   for keys that have expired or are about to expire.
class GpgKeyVerifier:

    # Initializes an instance of the class. Reads the config object for sender and recipient
    #   information.
    #
    # gpgkeyring: The GpgKeyring object containing information on all the GPG keys in the program's
    #   keyring.
    # config: The config dictionary read from the program configuration file.
    def __init__(self, gpgkeyring, config):
        self.logger = logging.getLogger('GpgKeyVerifier')
        self.gpgkeyring = gpgkeyring
        self.config = config

        self.email_dicts = {}
        self.all_recipient_emails = []
        self.valid_recipient_emails = []
        self.valid_key_fingerprints = []
        self.expiration_warning_message = ''
        self.next_key_check_time = 0  # Forces an expiration check on the first program loop.

        for recipient in config['recipients']:
            recipient_dict = { 'fingerprint': recipient['fingerprint'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False,
                'is_sender': False,
                'is_recipient': True }

            self.email_dicts[recipient['email']] = recipient_dict
            self.all_recipient_emails.append(recipient['email'])

        self.sender_email = config['sender']['email']

        if self.sender_email in self.email_dicts.keys():
            self.email_dicts[self.sender_email]['is_sender'] = True

        else:
            sender_dict = { 'fingerprint': config['sender']['fingerprint'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False,
                'is_sender': True,
                'is_recipient': False}

            self.email_dicts[self.sender_email] = sender_dict


    # Returns a list of valid GPG key fingerprints.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def get_valid_key_fingerprints(self, loop_current_time):
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.valid_key_fingerprints


    # Returns a list of recipient e-mail addresses that have valid GPG keys associated with them.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def get_valid_recipient_emails(self, loop_current_time):
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.valid_recipient_emails


    # Returns a string describing keys that have expired or will expire "soon"
    #   as defined in the configuration.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def get_expiration_warning_message(self, loop_current_time):
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.expiration_warning_message


    # Calculates which recipients keys have expired and which have not. Builds a list of currently
    #   valid recipients and constructs an expiration warning messages for keys that have expired
    #   or will be expiring soon.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def _calculate_recipient_info(self, loop_current_time):
        self.logger.trace('Recalculating the list of keys that are about to expire.')
        all_expiration_warning_messages = []
        expiration_warning_email_message = ''
        expired_messages = []
        expiring_soon_messages = []
        send_email = False
        valid_recipient_emails = []
        valid_key_fingerprints = []

        expiration_date = loop_current_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        self.logger.trace('Checking sender key.')
        sender_expiration_data = self._build_key_expiration_warning_message(self.sender_email,
            loop_current_time)

        if sender_expiration_data['warning_message'] is not None:
            if 'has expired' in expiration_data['warning_message']:
                if not(config['allow_expired_signing_key']):
                    raise SenderKeyExpiredException()

            else:
                valid_key_fingerprints.append(self.email_dicts[self.sender_email]['fingerprint'])
                valid_recipient_emails.append(self.sender_email)

            expired_messages.append(sender_expiration_data['warning_message'])
            if sender_expiration_data['send_email']:
                expiration_warning_email_message = 'A new key has expired.\n\n'

        else:
            valid_key_fingerprints.append(self.email_dicts[self.sender_email]['fingerprint'])
            valid_recipient_emails.append(self.sender_email)


        self.logger.trace('Checking recipient keys.')

        for recpient_email in self.all_recipient_emails:
            # Reuse the sender expiration data if the sender is also a recipient.
            # TODO: Eventually, optimize all key checking, not just sender key. Maybe have a list
            #   of checked fingerprints.
            if self.email_dicts[recipient_email]['is_sender']:
                self.logger.trace('Recipient %s is also a sender.' % recipient_email)
                expiration_data = sender_expiration_data

            else:
                expiration_data = self._build_key_expiration_warning_message(recipient_email,
                    loop_current_time)

                if 'has expired' in expiration_data['warning_message']:
                    expired_messages.append(expiration_data['warning_message'])

                else:
                    if 'will expire on' in expiration_data['warning_message']:
                        expiring_soon_messages.append(expiration_data['warning_message'])

                    valid_key_fingerprints.append(self.email_dicts[recipient_email['fingerprint']])
                    valid_recipient_emails.append(recipient_email)

                if expiration_data['send_email']:
                    expiration_warning_email_message = 'A new key has expired.\n\n'

        if valid_key_fingerprints == []:
            raise NoUsableKeysException('No usable recipient keys.')

        if expired_messages or expiring_soon_messages:
            expired_messages.insert(0, 'Here are the keys that have expired or will be expiring soon:')

        all_expiration_warning_messages = '\n'.join(expired_messages + expiring_soon_messages).strip()

        self.valid_recipient_emails = valid_recipient_emails
        self.valid_key_fingerprints = valid_key_fingerprints
        self.expiration_warning_message = all_expiration_warning_messages


    # Build an expiration warning message for an individual e-mail and fingerprint pair. There
    #   are essentially two types of messages that can be generated by this method. One is a warning
    #   message that the GPG key is about to expire. The other is a warning message that the GPG
    #   key has already expired. The returned message will distinguish between sender and recipient
    #   keys.
    #
    # email: The e-mail address associated with the expired key.
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def _build_key_expiration_warning_message(self, email, loop_current_time):
        self.logger.trace('Building expiration message for address %s.' % email)

        expiration_warning_message = ''
        send_email = False
        expiration_date = loop_current_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']
        fingerprint = self.email_dicts[email]['fingerprint']

        if self.email_dicts[email]['is_sender']:
            address_type = 'Sender'

        else:
            address_type = 'Recipient'

        if not self.gpgkeyring.is_current(fingerprint, expiration_date):
            expiration_warning_message = '%s key %s (%s) has expired.' % \
                (address_type, fingerprint, email)
            self.logger.trace(expiration_warning_message)

            if not(self.email_dicts[email]['expired_email_sent']):
                send_email = True
                self.logger.warn(expiration_warning_message)
                self.email_dicts[email]['expired_email_sent'] = True

        elif not self.gpgkeyring.is_current(fingerprint, expiring_soon_date):
            key_expiration_date = datetime.datetime.fromtimestamp(
                self.gpgkeyring.get_key_expiration_date(fingerprint)).strftime('%Y-%m-%d %H:%M:%S')
            expiration_warning_message = ('%s key %s (%s) will expire on date %s.' % \
                (address_type, fingerprint, email, key_expiration_date))
            self.logger.trace(expiration_warning_message)

            if not self.email_dicts[email]['expiring_soon_email_sent']:
                send_email = True
                self.logger.warn(expiration_warning_message)
                self.email_dicts[email]['expiring_soon_email_sent'] = True

        else:
            self.logger.trace('Key %s (%s) is current.' % (fingerprint, email))

        return { 'warning_message': expiration_warning_message,
            'send_email': send_email }


    # Determines whether the recipient and sender GPG key expiration information is current for
    #   the next full loop. If it isn't, recalculate. Recalculation occurs at a configurable
    #   period.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def _update_if_expiration_info_is_stale(self, loop_current_time):

        if self.next_key_check_time <= loop_current_time:
            self._calculate_recipient_info(loop_current_time)
            self.next_key_check_time = loop_current_time + self.config['key_check_interval']
