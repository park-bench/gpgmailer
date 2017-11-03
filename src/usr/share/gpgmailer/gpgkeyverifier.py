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

# Raised when two recipient keys have the same e-mail address.
class RecipientEmailCollision(Exception):
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
        self.expiration_warning_message = None
        # Forces an expiration check the first time a public method is called.
        self.next_key_check_time = time.time()

        self._initialize_email_dicts(config)


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
    #   as defined in the configuration. None is returned if no keys have expired or will be
    #   expiring soon.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def get_expiration_warning_message(self, loop_current_time):
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.expiration_warning_message


    # Initializes a dictionary that records information about all the e-mail addresses defined in the
    #   program configuration file (both sender and receiver e-mail addresses). This dictionary
    #   records (in RAM only) when an expiration warning e-mail is sent (both types), whether the
    #   e-mail address is associated with the sender, and whether the e-mail address is associated
    #   with a receiver.
    #
    # config: The config dictionary read from the program configuration file.
    def _initialize_email_dicts(self, config):

        recipient_fingerprints = []

        # Record e-mail information for all the recipients.
        for recipient in config['recipients']:
            # TODO: Eventually, handle multiple keys for one address.
            if recipient['email'] in self.all_recipient_emails:
                raise RecipientEmailCollision('Email %s is already configured.' % recipient['email'])

            email_dict = { 'fingerprint': recipient['fingerprint'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False,
                'is_sender': False,
                'is_recipient': True }

            recipient_fingerprints.append(recipient['fingerprint'])
            self.email_dicts[recipient['email']] = email_dict
            self.all_recipient_emails.append(recipient['email'])

        # The sender might also be a receipient.
        self.sender_email = config['sender']['email']
        if self.sender_email in self.email_dicts.keys():
            # The sender is also a recipient.
            self.email_dicts[self.sender_email]['is_sender'] = True

            if config['sender']['fingerprint'] not in recipient_fingerprints:
                raise RecipientEmailCollision('Email %s is already configured with a different key.' % recipient['email'])

        else:
            # The sender is NOT a recipient.
            email_dict = { 'fingerprint': config['sender']['fingerprint'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False,
                'is_sender': True,
                'is_recipient': False}

            self.email_dicts[self.sender_email] = email_dict


    # Calculates which recipients keys have expired and which have not. Builds a list of currently
    #   valid recipients and constructs an expiration warning messages for keys that have expired
    #   or will be expiring soon.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def _calculate_recipient_info(self, loop_current_time):
        self.logger.trace('Recalculating the list of keys that are about to expire.')
        all_expiration_warning_messages = []
        expired_messages = []
        expiring_soon_messages = []
        valid_recipient_emails = []
        valid_key_fingerprints = []

        expiration_date = loop_current_time + self.config['key_check_interval'] + \
            self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        self.logger.trace('Checking sender key.')
        sender_expiration_data = self._build_key_expiration_warning_message(self.sender_email,
            expiration_date, expiring_soon_date)

        if sender_expiration_data['expiring_soon'] or sender_expiration_data['is_expired']:
            if sender_expiration_data['is_expired']:
                if not self.config['allow_expired_signing_key']:
                    raise SenderKeyExpiredException('Sender key has expired and the program is not ' +
                        'configured to send e-mail with an expired sender GPG key.')

            else:
                # Always encrypt with the sender key. TODO: Eventually make this an option.
                valid_key_fingerprints.append(self.email_dicts[self.sender_email]['fingerprint'])

                if self.email_dicts[self.sender_email]['is_recipient']:
                    valid_recipient_emails.append(self.sender_email)

            # The sender's message always shows up on top regardless of whether the key has expired
            #   or will expire soon.
            expired_messages.append(sender_expiration_data['warning_message'])

        else:
            # Always encrypt with the sender key. TODO: Eventually make this an option.
            valid_key_fingerprints.append(self.email_dicts[self.sender_email]['fingerprint'])

            if self.email_dicts[self.sender_email]['is_recipient']:
                valid_recipient_emails.append(self.sender_email)

        self.logger.trace('Checking recipient keys.')
        for recipient_email in self.all_recipient_emails:
            # Reuse the sender expiration data if the sender is also a recipient.
            # TODO: Eventually, optimize all key checking, not just sender key. Maybe have a list
            #   of checked fingerprints.
            if self.email_dicts[recipient_email]['is_sender']:
                self.logger.trace('Recipient %s is also a sender.' % recipient_email)
                expiration_data = sender_expiration_data

            else:
                expiration_data = self._build_key_expiration_warning_message(recipient_email,
                    expiration_date, expiring_soon_date)

                if expiration_data['is_expired']:
                    expired_messages.append(expiration_data['warning_message'])

                elif expiration_data['expiring_soon']:
                    expiring_soon_messages.append(expiration_data['warning_message'])

                    valid_key_fingerprints.append(self.email_dicts[recipient_email]['fingerprint'])
                    valid_recipient_emails.append(recipient_email)

                else:
                    valid_key_fingerprints.append(self.email_dicts[recipient_email]['fingerprint'])
                    valid_recipient_emails.append(recipient_email)

        # The sender key might be in valid_key_fingerprints despite not being a recipient. Check
        #   valid_recipient_emails instead.
        if valid_recipient_emails == []:
            raise NoUsableKeysException('All recipient GPG keys have expired.')

        if expired_messages or expiring_soon_messages:
            expired_messages.insert(0, 'Here are the keys that have expired or will be expiring soon:')

        all_expiration_warning_messages = '\n'.join(expired_messages + expiring_soon_messages).strip()

        self.valid_recipient_emails = valid_recipient_emails
        self.valid_key_fingerprints = valid_key_fingerprints
        if all_expiration_warning_messages == '':
            self.expiration_warning_message = None
        else:
            self.expiration_warning_message = all_expiration_warning_messages


    # Build an expiration warning message for an individual e-mail and fingerprint pair. There
    #   are essentially two types of messages that can be generated by this method. One is a warning
    #   message that the GPG key is about to expire. The other is a warning message that the GPG
    #   key has already expired. The returned message will distinguish between sender and recipient
    #   keys.
    #
    # email: The e-mail address associated with the expired key.
    # expiration_date: The date after which a key's expiration date should be considered
    #   expired. Will be slightly before the current time.
    # expiring_soon_date: The date after which a key's expiration date should be should be
    #   considered expiring soon.
    def _build_key_expiration_warning_message(self, email, expiration_date,
            expiring_soon_date):
        self.logger.trace('Building expiration message for address %s.' % email)

        expiration_warning_message = None
        is_expired = False
        expiring_soon = False
        fingerprint = self.email_dicts[email]['fingerprint']

        if self.email_dicts[email]['is_sender'] and self.email_dicts[email]['is_recipient']:
            address_type = 'Sender and recipient'
        elif self.email_dicts[email]['is_sender']:
            address_type = 'Sender'
        else:
            address_type = 'Recipient'

        if not self.gpgkeyring.is_current(fingerprint, expiration_date):
            is_expired = True
            expiration_warning_message = '%s key %s (%s) has expired.' % \
                (address_type, fingerprint, email)
            self.logger.trace(expiration_warning_message)

            if not self.email_dicts[email]['expired_email_sent']:
                self.logger.warn(expiration_warning_message)
                self.email_dicts[email]['expired_email_sent'] = True

        elif not self.gpgkeyring.is_current(fingerprint, expiring_soon_date):
            expiring_soon = True
            key_expiration_date = datetime.datetime.fromtimestamp(
                self.gpgkeyring.get_key_expiration_date(fingerprint)).strftime('%Y-%m-%d %H:%M:%S')
            expiration_warning_message = ('%s key %s (%s) will expire on %s.' % \
                (address_type, fingerprint, email, key_expiration_date))
            self.logger.trace(expiration_warning_message)

            if not self.email_dicts[email]['expiring_soon_email_sent']:
                self.logger.warn(expiration_warning_message)
                self.email_dicts[email]['expiring_soon_email_sent'] = True

        else:
            self.logger.trace('Key %s (%s) is current.' % (fingerprint, email))

        return { 'warning_message': expiration_warning_message,
            'is_expired': is_expired,
            'expiring_soon': expiring_soon }


    # Determines whether the recipient and sender GPG key expiration information is current for
    #   the next full loop. If it isn't, recalculate. Recalculation occurs at a configurable
    #   period.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def _update_if_expiration_info_is_stale(self, loop_current_time):

        # TODO: Eventually we should better support long pauses in execution (such as
        #   suspend).
        if self.next_key_check_time <= loop_current_time:
            self._calculate_recipient_info(loop_current_time)
            self.next_key_check_time += self.config['key_check_interval']
