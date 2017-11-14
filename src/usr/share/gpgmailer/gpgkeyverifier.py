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

    # Initializes an instance of the class. Reads the config object for sender information.
    #
    # gpgkeyring: The GpgKeyring object containing information on all the GPG keys in the program's
    #   keyring.
    # config: The config dictionary read from the program configuration file.
    def __init__(self, gpgkeyring, config):
        self.logger = logging.getLogger('GpgKeyVerifier')
        self.gpgkeyring = gpgkeyring
        self.config = config

        # Note that recipient keys will always include the sender key.
        self.recipient_keys = {}
        self.sender_key = {}
        # TODO Do I even want to maintain a list of valid recipient emails?
        self.valid_recipient_emails = []
        self.valid_key_fingerprints = []
        self.expiration_warning_message = ''
        self.expiration_warning_email_message = ''
        # Forces an expiration check the first time a public method is called.
        self.next_key_check_time = time.time()

        self._initialize_key_dicts(config)


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
    # TODO: Return None if it's an empty string.
    def get_expiration_warning_message(self, loop_current_time):
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.expiration_warning_message


    # Returns a string intended for e-mail describing keys that have expired or will expire "soon"
    #   as defined in the configuration.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    # TODO: Return None if it's an empty string.
    def get_expiration_warning_email_message(self, loop_current_time):
        self._update_if_expiration_info_is_stale(loop_current_time)
        return self.expiration_warning_email_message


    # Initializes a dictionary that records information about all the gpg keys in the specified keyring.
    # This dictionary records (in RAM only) when an expiration warning e-mail is sent to the address
    # associated with the key and whether the key is the one used to send gpgmailer emails.
    #
    # config: The config dictionary read from the program configuration file.
    def _initialize_key_dicts(self, config):

        # Build a dict of fingerprints from the keyring that includes associated email addresses,
        # whether the key is the gpgmailer configured sender, and whether any expiry emails have
        # been sent for this key.
        fp_to_key_dict = self.gpgkeyring.fingerprint_to_key_dict
        for fingerprint in fp_to_key_dict:

            key_dict = {
                'fingerprint': fp_to_key_dict[fingerprint]['fingerprint'],
                'email_list': fp_to_key_dict[fingerprint]['emails'],
                'expired_email_sent': False,
                'expiring_soon_email_sent': False
            }

            # Mark the gpgmailer configured sender key.
            if fp_to_key_dict[fingerprint]['fingerprint'] == config['sender']['fingerprint']:
                self.sender_key = key_dict

            self.recipient_keys[fp_to_key_dict[fingerprint]['fingerprint']] = key_dict

            self.logger.debug("The sender key is: ")
            self.logger.debug(self.sender_key)
            self.logger.debug("The key being added is: ")
            self.logger.debug(key_dict)


        # recipient_fingerprints = []
        #
        # # Record e-mail information for all the recipients.
        # for recipient in config['recipients']:
        #     # TODO: Eventually, handle multiple keys for one address.
        #     if recipient['email'] in self.all_recipient_emails:
        #         raise RecipientEmailCollision('Email %s is already configured.' % recipient['email'])
        #
        #     email_dict = { 'fingerprint': recipient['fingerprint'],
        #         'expired_email_sent': False,
        #         'expiring_soon_email_sent': False,
        #         'is_sender': False,
        #         'is_recipient': True }
        #
        #     recipient_fingerprints.append(recipient['fingerprint'])
        #     self.email_dicts[recipient['email']] = email_dict
        #     self.all_recipient_emails.append(recipient['email'])
        #
        # # The sender might also be a receipient.
        # self.sender_email = config['sender']['email']
        # if self.sender_email in self.email_dicts.keys():
        #     # The sender is also a recipient.
        #     self.email_dicts[self.sender_email]['is_sender'] = True
        #
        #     if config['sender']['fingerprint'] not in recipient_fingerprints:
        #         raise RecipientEmailCollision('Email %s is already configured with a different key.' % recipient['email'])
        #
        # else:
        #     # The sender is NOT a recipient.
        #     email_dict = { 'fingerprint': config['sender']['fingerprint'],
        #         'expired_email_sent': False,
        #         'expiring_soon_email_sent': False,
        #         'is_sender': True,
        #         'is_recipient': False}
        #
        #     self.email_dicts[self.sender_email] = email_dict


    # Calculates which keys in the keyring have expired and which have not. Builds a list of currently
    #   valid recipient keys and constructs an expiration warning messages for keys that have expired
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
        valid_recipient_emails = []
        valid_key_fingerprints = []

        # Set the threshold dates for expired/expiring "soon."
        expiration_date = loop_current_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']

        # Calculate all of the expiration information for the sender.
        self.logger.trace('Checking sender key.')
        if not self.sender_key:
            raise NoUsableKeysException("The sender key was not found in the keyring.")
        else:
            sender_expiration_data = self._build_key_expiration_warning_message(
                self.sender_key['fingerprint'], loop_current_time)

        # Add expiry messages or raise exception based on sender expiry info generated above.
        if sender_expiration_data['expiring_soon'] or sender_expiration_data['is_expired']:
            if sender_expiration_data['is_expired']:
                if not self.config['allow_expired_signing_key']:
                    raise SenderKeyExpiredException('Sender key has expired and the program is not ' +
                        'configured to send e-mail with an expired sender GPG key.')

            else:
                # Always encrypt with the sender key. TODO: Eventually make this an option.
                valid_key_fingerprints.append(self.sender_key['fingerprint'])
                # TODO: This should add all of the associated email addresses, but for now I'm arbitrarily using only the first one just to get started.
                valid_recipient_emails.append(self.sender_key['email_list'])

            # The sender's message always shows up on top regardless of whether the key has expired
            #   or will expire soon.
            expired_messages.append(sender_expiration_data['warning_message'])
            if sender_expiration_data['new_message']:
                expiration_warning_email_message = 'A new key has expired or will expire soon.'

        else:
            # Always encrypt with the sender key. TODO: Eventually make this an option.
            valid_key_fingerprints.append(self.sender_key['fingerprint'])
            valid_recipient_emails.append(self.sender_key['email_list'])

        # Calculate all of the expiration information for each recipient (i.e. non-sender keys).
        self.logger.trace('Checking recipient keys.')
        #
        for fingerprint in self.gpgkeyring.fingerprint_to_key_dict.keys():
            # Reuse the sender expiration data if the sender is also a recipient.
            # TODO: Eventually, optimize all key checking, not just sender key. Maybe have a list
            #   of checked fingerprints.

            if fingerprint == self.sender_key['fingerprint']:
                self.logger.trace('Recipient %s is also a sender.' % self.sender_key['email_list'])
                expiration_data = sender_expiration_data

            else:
                expiration_data = self._build_key_expiration_warning_message(fingerprint,
                    loop_current_time)

                if expiration_data['is_expired']:
                    expired_messages.append(expiration_data['warning_message'])

                elif expiration_data['expiring_soon']:
                    expiring_soon_messages.append(expiration_data['warning_message'])

                    valid_key_fingerprints.append(fingerprint)
                    # TODO: Again, loop through to append all associated email addresses.
                    valid_recipient_emails.append(self.recipient_keys[fingerprint]['email_list'])

                else:
                    valid_key_fingerprints.append(fingerprint)
                    valid_recipient_emails.append(self.recipient_keys[fingerprint]['email_list'])

                if expiration_data['new_message']:
                    expiration_warning_email_message = 'A new key has expired or will expire soon.'

        # There should be at least one valid, non-expired fingerprint at this point.
        if not valid_key_fingerprints:
            raise NoUsableKeysException('All GPG keys have expired.')

        if expired_messages or expiring_soon_messages:
            expired_messages.insert(0, 'Here are the keys that have expired or will be expiring soon:')

        all_expiration_warning_messages = '\n'.join(expired_messages + expiring_soon_messages).strip()

        self.valid_recipient_emails = valid_recipient_emails
        self.valid_key_fingerprints = valid_key_fingerprints

        # Set these as class fields so they can be sent as email body by gpgmailer.
        self.expiration_warning_message = all_expiration_warning_messages
        self.expiration_warning_email_message = '%s\n\n%s' % (expiration_warning_email_message,
            all_expiration_warning_messages)


    # Build an expiration warning message for an individual fingerprint. There
    #   are essentially two types of messages that can be generated by this method. One is a warning
    #   message that the GPG key is about to expire. The other is a warning message that the GPG
    #   key has already expired. The returned message will distinguish between sender and non-sender
    #   (potential recipient only) keys.
    #
    # fingerprint: The fingerprint of the key whose expiration should be checked.
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def _build_key_expiration_warning_message(self, fingerprint, loop_current_time):

        # TODO Arbitrarily taking the first email in the list for now.
        key_associated_email = self.recipient_keys[fingerprint]['email_list']

        self.logger.trace('Building expiration message for key %s to be sent to address %s.' % (fingerprint, key_associated_email))

        expiration_warning_message = None
        new_message = False
        is_expired = False
        expiring_soon = False
        expiration_date = loop_current_time + self.config['main_loop_duration']
        expiring_soon_date = expiration_date + self.config['expiration_warning_threshold']
        #fingerprint = key_fingerprint['fingerprint']

        if fingerprint == self.recipient_keys[fingerprint]: # self.sender_key['fingerprint']:
            address_type = 'Sender'
        else:
            address_type = 'Recipient'

        if not self.gpgkeyring.is_current(fingerprint, expiration_date):
            is_expired = True
            expiration_warning_message = '%s key %s (%s) has expired.' % \
                (address_type, fingerprint, key_associated_email)
            self.logger.trace(expiration_warning_message)

            if not self.recipient_keys[fingerprint]['expired_email_sent']:
                new_message = True
                self.logger.warn(expiration_warning_message)
                self.recipient_keys[fingerprint]['expired_email_sent'] = True

        elif not self.gpgkeyring.is_current(fingerprint, expiring_soon_date):
            expiring_soon = True
            key_expiration_date = datetime.datetime.fromtimestamp(
                self.gpgkeyring.get_key_expiration_date(fingerprint)).strftime('%Y-%m-%d %H:%M:%S')
            expiration_warning_message = ('%s key %s (%s) will expire on date %s.' % \
                                          (address_type, fingerprint, key_associated_email, key_expiration_date))
            self.logger.trace(expiration_warning_message)

            if not self.recipient_keys[fingerprint]['expiring_soon_email_sent']:
                new_message = True
                self.logger.warn(expiration_warning_message)
                self.recipient_keys[fingerprint]['expiring_soon_email_sent'] = True

        else:
            self.logger.trace('Key %s (%s) is current.' % (fingerprint, key_associated_email))

        return { 'warning_message': expiration_warning_message,
            'is_expired': is_expired,
            'expiring_soon': expiring_soon,
            'new_message': new_message }


    # Determines whether the recipient and sender GPG key expiration information is current for
    #   the next full loop. If it isn't, recalculate. Recalculation occurs at a configurable
    #   period.
    #
    # loop_current_time: The Unix time associated with the main program loop from which all
    #   GPG key expiration checks are based.
    def _update_if_expiration_info_is_stale(self, loop_current_time):

        if self.next_key_check_time <= loop_current_time:
            self._calculate_recipient_info(loop_current_time)
            self.next_key_check_time += self.config['key_check_interval']
