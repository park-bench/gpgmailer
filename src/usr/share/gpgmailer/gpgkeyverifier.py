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
        valid_recipients = []
        valid_keys = []
        expired_messages = []
        expiring_soon_messages = []
        send_email = False

        expiration_date = loop_start_time + self.config['main_loop_duration']
        expiring_soon_date = expiring_time + self.config['expiration_warning_threshold']

        if self.first_run:
            send_email = True
            self.first_run = False
            expiration_message.append('Gpgmailer just restarted. Here is a list of keys that are expired or will be expiring soon.')

        # TODO: Check the sender key first.

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
                message = ('Key <%s> (%s) will expire soon on date %s.' % (fingerprint, email, pretty_expiration_date)
                self.logger.warn(message)
                expiring_soon_messages.append(message)

                if not(self.recipient_index[email]['expiring_soon_email_sent']):
                    send_email = True
                    self.recipient_index[email]['expiring_soon_email_sent'] = True

            else:
                self.logger.trace('Key %s is current.' % fingerprint
                valid_recipients.append(email)

                if not(fingerprint in valid_keys):
                    valid_keys.append(fingerprint)

        joined_expired_messages = '\n'.join(expired_messages)
        joined_expiring_soon_messages = '\n'.join(expiring_soon_messages)

        expiration_message = '\n'.join([joined_expired_mesages, joined_expiring_soon_messages])

        
        recipient_info = { 'valid_recipients': valid_recipients,
            'valid_keys': valid_keys,
            'expiration_message': expiration_message,
            'send_email': send_email }

        return recipient_info

    def _build_sender_expiration_message(self, loop_start_time):
        expiration_message = ''
        send_email = False

        expiration_date = loop_start_time + self.config['main_loop_duration']
        expiring_soon_date = expiring_time + self.config['expiration_warning_threshold']

        email = self.config['sender']['email']
        fingerprint = self.config['sender']['fingerprint']
        
        if not(self.gpgkeyring.is_current(email, expiration_date)):
            expiration_message = 'Sender key <%s> (%s) has expired.' % (fingerprint, email)
            self.sender_key_expired_email_sent = True
            send_email = True

        elif not(self.gpgkeyring.is_current(email, expiring_soon_date)):
            key_expiration_date = self.gpgkeyring.get_key_expiration_date(fingerprint)
            pretty_expiration_date = datetime.datetime.fromtimestamp(key_expiration_date).strftime('%Y-%m-%d %H:%M:%S')
            expiration_message = 'Sender key <%s> (%s) will be expiring soon on date %s.'
                 % (fingerprint, email, pretty_expiration_date)
            self.sender_key_expiring_soon_email_sent = True
            send_email = True

        return {'expiration_message': expiration_message,
            'send_email': send_email }

    # TODO: Remove this method.
    # Accepts a list of keys and only returns the ones that are trusted and do not expire by the
    #   time the next loop starts.
    def filter_valid_keys(self, fingerprint_list):
        self.logger.info('Filtering keys in list')
        valid_keys = []

        # TODO: Change check_date to expiration_date.
        # TODO: Change the main_loop_delay reference to a new config variable: main_loop_duration.
        # TODO: Pass in the loop started instead of calling time.time() here.
        # Add the amount of time the main loop is expected to run to the current time
        #   so that keys don't expire during a loop.
        check_date = time.time() + self.config['main_loop_delay']

        for fingerprint in fingerprint_list:
            if self.gpgkeyring.is_expired(fingerprint, check_date=check_date):
                self.logger.error('Key with fingerprint %s is expired and will not be used.' % fingerprint)

            else:
                # TODO: Trust checks only need to happen during init, move this
                #   and cache the result.
                if not(self.gpgkeyring.is_trusted(fingerprint)):
                    self.logger.error('Key with fingerprint %s is not trusted and will not be used.' % fingerprint)

                else:
                    self.logger.trace('Key with fingerprint %s is valid and will be used.' % fingerprint)
                    valid_keys.append(fingerprint)

        return valid_keys

    
    # TODO: Remove this method.
    # Builds the expiration warnings that are prepended to each outgoing message
    #   and sends an email if this is the first time this method is run.
    def build_key_expiration_message(self, expiration_warning_threshold, key_fingerprint_list, first_run=False):

        self.logger.info('Building key expiration message.')
        expired_messages = []
        expiring_soon_messages = []

        # TODO: key_dict_list can be an object variable instead of being rebuilt
        #   each time this is called.
        # TODO: Store emails associated with keys here.
        key_dict_list = []

        for key_fingerprint in key_fingerprint_list:
            # TODO: get_key_data will become get_key_expiration_date
            key_dict_list.append(self.gpgkeyring.get_key_data(key_fingerprint))

        # TODO: Clear up added_messages
        # TODO: Move message compilation to _queue_warning_email
        if first_run:
            added_messages = ['Gpgmailer just restarted. Here are the keys that \
                have expired or will be expiring soon.']
        else:
            added_messages = []

        for key_dict in key_dict_list:
            self.logger.debug('Checking if key <%s> (%s) with expiration date <%s> has expired or is expiring soon.' \
                % (key_dict['fingerprint'], key_dict['email'], key_dict['expires']))

            # TODO: Expired_email and expiring_soon_email should be in the local
            #   key_dict_list, not in gpgkeyring.
            if (self.gpgkeyring.is_expired(key_dict['fingerprint'])):
                if not(self.gpgkeyring.keys[key_dict['fingerprint']]['expired_email']):
                    self.gpgkeyring.keys[key_dict['fingerprint']]['expired_email'] = True
                    if not(first_run):
                        added_messages.append('Added key %s to expiration message.' % key_dict['fingerprint'])

                message = 'Key <%s> (%s) is expired!' % (key_dict['fingerprint'], key_dict['email'])
                expired_messages.append(message)
                self.logger.warn(message)

            elif self.gpgkeyring.is_expired(key_dict['fingerprint'], check_date = time.time() + expiration_warning_threshold):
                if not(self.gpgkeyring.keys[key_dict['fingerprint']]['expiring_soon_email']):
                    self.gpgkeyring.keys[key_dict['fingerprint']]['expiring_soon_email'] = True
                    if not(first_run):
                        added_messages.append('Added key %s to expiration message.' % key_dict['fingerprint'])

                pretty_expiration_date = datetime.datetime.fromtimestamp(key_dict['expires']).strftime('%Y-%m-%d %H:%M:%S')
                message = 'Key <%s> (%s) will be expiring on date <%s>!' % \
                    (key_dict['fingerprint'], key_dict['email'], pretty_expiration_date)
                expiring_soon_messages.append(message)
                self.logger.warn(message)

        self._queue_warning_email('\n'.join(added_messages))

        full_message = '%s\n%s\n' % ('\n'.join(expired_messages), '\n'.join(expiring_soon_messages))

        return full_message

    # TODO: Move this functionality into gpgmailer
    # This queues a warning email for expired or soon to expire keys.
    def _queue_warning_email(self, message_body):
        # TODO: Build message and send using sendmail instead of saving it to disk.
        if(message_body):
            self.logger.info('Sending key warning digest.')
            message = gpgmailmessage.GpgMailMessage()
            message.set_subject(self.config['default_subject'])
            message.set_body(message_body)
            message.queue_for_sending()
