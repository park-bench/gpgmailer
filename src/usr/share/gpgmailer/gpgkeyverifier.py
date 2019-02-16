# Copyright 2015-2018 Joel Allen Luellwitz and Andrew Klapp
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

__all__ = ['NoUsableKeysException', 'SenderKeyExpiredException', 'GpgKeyVerifier']
__author__ = 'Joel Luellwitz and Andrew Klapp'
__version__ = '0.8'

import datetime
import logging
import time


class NoUsableKeysException(Exception):
    """Raised when there are no current keys available for encryption."""


class SenderKeyExpiredException(Exception):
    """Raised when the sender key expires during runtime and sending unsigned messages
    is not allowed.
    """


class SenderKeyNotFoundException(Exception):
    """Raised when the sender key is not found in the keyring."""


class GpgKeyVerifier(object):
    """Manages expiration information for the sender, recipients, and key expiration warning
    messages for keys that have expired or are about to expire.
    """

    def __init__(self, gpgkeyring, config):
        """Initializes an instance of the class. Reads the config object for sender and
        recipient information.

        gpgkeyring: The GpgKeyring object containing information on all the GPG keys in the
          program's keyring.
        config: The config dictionary read from the program configuration file.
        """
        self.logger = logging.getLogger('GpgKeyVerifier')
        self.gpgkeyring = gpgkeyring
        self.config = config

        # Note that recipient keys will always include the sender key.
        self.recipient_keys = {}
        self.sender_key = {}
        self.valid_recipient_emails = []
        self.valid_key_fingerprints = []
        self.expiration_warning_message = None
        # Forces an expiration check the first time a public method is called.
        self.next_key_check_time = time.time()

        self._initialize_key_dicts(config)

    def get_valid_key_fingerprints(self, loop_current_time):
        """Returns a list of valid GPG key fingerprints.

        loop_current_time: The Unix time associated with the main program loop from which
          all GPG key expiration checks are based.
        """
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.valid_key_fingerprints

    def get_valid_recipient_emails(self, loop_current_time):
        """Returns a list of recipient e-mail addresses that have valid GPG keys associated
        with them.

        loop_current_time: The Unix time associated with the main program loop from which
          all GPG key expiration checks are based.
        """
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.valid_recipient_emails

    def get_expiration_warning_message(self, loop_current_time):
        """Returns a string describing keys that have expired or will expire "soon"
        as defined in the configuration. None is returned if no keys have expired or
        will be expiring soon.

        loop_current_time: The Unix time associated with the main program loop from which all
          GPG key expiration checks are based.
        """
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.expiration_warning_message

    def _initialize_key_dicts(self, config):
        """Initializes a dictionary that records information about all the e-mail addresses
        defined in the program configuration file (both sender and receiver e-mail
        addresses). This dictionary records (in RAM only) when an expiration warning e-mail
        is sent (both types), whether the e-mail address is associated with the sender, and
        whether the e-mail address is associated with a receiver.

        config: The config dictionary read from the program configuration file.
        """

        # TODO: Update the following comment:
        # Build a dict of fingerprints from the keyring that includes associated email
        #   addresses, whether the key is the gpgmailer configured sender, and whether any
        #   expiry emails have been sent for this key.
        fingerprint_to_key_dict = self.gpgkeyring.fingerprint_to_key_dict
        for fingerprint in fingerprint_to_key_dict:

            key_dict = {
                'fingerprint': fingerprint,
                'emails': fingerprint_to_key_dict[fingerprint]['emails'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False
            }

            # TODO: do an email dict again too

            self.recipient_keys[fingerprint] = key_dict

        # Mark the gpgmailer configured sender key.
        self.sender_key = self.recipient_keys[config['sender']['fingerprint']]
        if not self.sender_key:
            raise SenderKeyNotFoundException("Sender key %s not found on keyring." %
                                             config['sender']['fingerprint'])

    def _calculate_recipient_info(self, loop_current_time):
        """Calculates which keys in the keyring have expired and which have not. Builds a
        list of currently valid recipient keys and constructs expiration warning messages
        for keys that have expired or will be expiring soon.

        loop_current_time: The Unix time associated with the main program loop from which
          all GPG key expiration checks are based.
        """
        self.logger.trace('Recalculating the list of keys that are about to expire.')
        expired_messages = []
        expiring_soon_messages = []
        valid_recipient_emails = []
        valid_key_fingerprints = []

        # Set the threshold dates for expired/expiring "soon."
        expiration_date = loop_current_time + self.config[
            'key_check_interval'] + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        # Calculate all of the expiration information for the sender.
        self.logger.trace('Checking sender key.')
        sender_expiration_data = self._build_key_expiration_warning_message(
            self.sender_key['fingerprint'], expiration_date, expiring_soon_date)

        # Add expiry messages or raise exception based on sender expiry info generated above.
        if sender_expiration_data['expiring_soon'] or sender_expiration_data['is_expired']:
            if sender_expiration_data['is_expired']:
                if not self.config['allow_expired_signing_key']:
                    raise SenderKeyExpiredException(
                        'Sender key has expired and the program is not configured to send '
                        'e-mail with an expired sender GPG key.')

            else:
                # Always encrypt with the sender key.
                #   TODO: Eventually make this an option. (issue 36)
                # TODO: What if the sender is already a recipient?
                valid_key_fingerprints.append(self.sender_key['fingerprint'])
                # TODO: I'm not sure if it is necessary to actually send the e-mail to the
                #   sender. The message should be in the outbox.
                valid_recipient_emails.extend(self.sender_key['emails'])

            # The sender's message always shows up on top regardless of whether the key
            #   has expired or will expire soon.
            expired_messages.append(sender_expiration_data['warning_message'])

        else:
            # Always encrypt with the sender key.
            #   TODO: Eventually make this an option. (issue 36)
            # TODO: What if the sender is already a recipient?
            valid_key_fingerprints.append(self.sender_key['fingerprint'])
            # TODO: I'm not sure if it is necessary to actually send the e-mail to the
            #   sender. The message should be in the outbox.
            valid_recipient_emails.extend(self.sender_key['emails'])

        # Calculate all of the expiration information for each recipient (i.e. non-sender
        #   keys).
        self.logger.trace('Checking recipient keys.')
        #
        for fingerprint in self.gpgkeyring.fingerprint_to_key_dict.keys():
            # Skip processing the sender because the sender was already processed above.
            if fingerprint == self.sender_key['fingerprint']:
                # TODO: Should the parameter be an array of e-mail addresses?
                self.logger.trace(
                    'Recipient %s is also a sender.', self.sender_key['emails'])

            else:
                expiration_data = self._build_key_expiration_warning_message(
                    fingerprint, expiration_date, expiring_soon_date)

                if expiration_data['is_expired']:
                    expired_messages.append(expiration_data['warning_message'])

                elif expiration_data['expiring_soon']:
                    expiring_soon_messages.append(expiration_data['warning_message'])

                    valid_key_fingerprints.append(fingerprint)
                    valid_recipient_emails.extend(
                        self.recipient_keys[fingerprint]['emails'])

                else:
                    valid_key_fingerprints.append(fingerprint)
                    valid_recipient_emails.extend(
                        self.recipient_keys[fingerprint]['emails'])

        # There should be at least one valid, non-expired fingerprint at this point.
        if not valid_key_fingerprints:
            raise NoUsableKeysException('All possible recipient GPG keys have expired.')

        if expired_messages or expiring_soon_messages:
            expired_messages.insert(
                0, 'Here are the keys that have expired or will be expiring soon:')

        all_expiration_warning_messages = '\n'.join(
            expired_messages + expiring_soon_messages).strip()

        self.valid_recipient_emails = valid_recipient_emails
        self.valid_key_fingerprints = valid_key_fingerprints
        # Set these as class fields so they can be sent as email body by gpgmailer.
        if all_expiration_warning_messages == '':
            self.expiration_warning_message = None
        else:
            self.expiration_warning_message = all_expiration_warning_messages

    def _build_key_expiration_warning_message(self, fingerprint, expiration_date,
                                              expiring_soon_date):
        """Build an expiration warning message for an individual fingerprint. There are
        essentially two types of messages that can be generated by this method. One is a
        warning message that the GPG key is about to expire. The other is a warning message
        that the GPG key has already expired. The returned message will distinguish between
        sender/recipient and recipient only keys.

        fingerprint: The fingerprint of the key whose expiration should be checked.
        expiration_date: The date after which a key's expiration date should be considered
          expired. Will be slightly before the current time.
        expiring_soon_date: The date after which a key's expiration date should be should be
          considered expiring soon.
        """

        # TODO: Comma delimit the e-mails addresses.
        key_associated_email = self.recipient_keys[fingerprint]['emails']

        self.logger.trace('Building expiration message for key %s to be sent to address %s.',
                          fingerprint, key_associated_email)
        expiration_warning_message = None
        is_expired = False
        expiring_soon = False

        if fingerprint == self.sender_key['fingerprint']:
            address_type = 'Sender/recipient'
        else:
            address_type = 'Recipient'

        if not self.gpgkeyring.is_current(fingerprint, expiration_date):
            is_expired = True
            expiration_warning_message = '%s key %s (%s) has expired.' % (
                address_type, fingerprint, key_associated_email)
            self.logger.trace(expiration_warning_message)

            if not self.recipient_keys[fingerprint]['expired_email_sent']:
                self.logger.warn(expiration_warning_message)
                self.recipient_keys[fingerprint]['expired_email_sent'] = True

        elif not self.gpgkeyring.is_current(fingerprint, expiring_soon_date):
            expiring_soon = True
            key_expiration_date = datetime.datetime.fromtimestamp(
                self.gpgkeyring.get_key_expiration_date(fingerprint)).strftime(
                    '%Y-%m-%d %H:%M:%S')
            expiration_warning_message = ('%s key %s (%s) will expire on %s.' % (
                address_type, fingerprint, key_associated_email, key_expiration_date))
            self.logger.trace(expiration_warning_message)

            if not self.recipient_keys[fingerprint]['expiring_soon_email_sent']:
                self.logger.warn(expiration_warning_message)
                self.recipient_keys[fingerprint]['expiring_soon_email_sent'] = True

        else:
            # TODO: See how the e-mail addresses are formatted as it is right now.
            self.logger.trace('Key %s (%s) is current.' % (fingerprint, key_associated_email))

        return {'warning_message': expiration_warning_message,
                'is_expired': is_expired,
                'expiring_soon': expiring_soon}

    # TODO: Eventually we should better support long pauses in execution (such as
    #   suspend). (issue 40)
    def _update_if_expiration_info_is_stale(self, loop_current_time):
        """Determines whether the recipient and sender GPG key expiration information is
        current for the next full loop. If it isn't, recalculate. Recalculation occurs at a
        configurable period.

        loop_current_time: The Unix time associated with the main program loop from which all
          GPG key expiration checks are based.
        """
        if self.next_key_check_time <= loop_current_time:
            self._calculate_recipient_info(loop_current_time)
            self.next_key_check_time += self.config['key_check_interval']
