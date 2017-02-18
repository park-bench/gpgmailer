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

import base64
import gpgkeyverifier
import gpgkeyring
import gpgmailbuilder
import gpgmailmessage
import json
import logging
import mailsender
import os
import sys
import time

# TODO: Write more effective logging.
# TODO: Class-level comments.
# TODO: Prefer named parameters for more than one parameter.
class GpgMailer:
    # TODO: Document the constructor.
    def __init__(self, config, gpgkeyring):
        self.logger = logging.getLogger('GpgMailer')
        self.logger.info('Gpgmailer initializing.')

        self.config = config
        self.gpgkeyring = gpgkeyring
        self.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(self.config['gpg_dir'], self.config['allow_expired_signing_key'])

        # TODO: Don't pass in main_loop_delay, just read from config.
        self.gpgkeyverifier = gpgkeyverifier.GpgKeyVerifier(self.gpgkeyring, self.config['main_loop_delay'], self.config)

        self.mailsender = mailsender.MailSender(self.config)

        all_key_fingerprints = [key['fingerprint'] for key in self.config['recipients']]

        # Add the sender key if it isn't already in the list.
        if not(self.config['sender']['fingerprint'] in all_key_fingerprints):
            all_key_fingerprints.append(self.config['sender']['fingerprint'])

        # TODO: Don't send email with the constructor.
        self.gpgkeyverifier.build_key_expiration_message(self.config['expiration_warning_threshold'], all_key_fingerprints, first_run=True)

        self.logger.info('GpgMailer initialized.')

    # Gpgmailer's main loop. Reads the watch directory and then calls other modules
    #   to build and send email.
    def start_monitoring(self, directory):
        # TODO: Remove unused parameter.
        # TODO: Use more helper methods.

        # TODO: Put the contents of this loop in a try/catch block.
        while True:
            # The first element of os.walk is the full path, the second is a
            #   list of directories, and the third is a list of non-directory
            #   files.
            file_list = next(os.walk(self.config['watch_dir']))[2]
            for file_name in file_list:
                self.logger.info("Found file %s." % file_name)
                message_dict = self._read_message_file(file_name)

                # TODO: Remove this condition, it will be unnecessary with the
                #   main loop being in a try/except block.
                if message_dict == {}:
                    # TODO: Some mechanism to ignore broken files
                    self.logger.error('Message file %s could not be read.' % file_name)

                else:
                    self.logger.trace('Message file %s read.' % file_name)

                    # TODO: Do key checking on a time interval, keep key data in a class variable.
                    # TODO: Use key_check_date for checking keys on an interval.
                    key_check_date = time.time() + self.config['main_loop_delay']

                    recipient_fingerprints = [key['fingerprint'] for key in self.config['recipients']]
                    valid_recipient_fingerprints = self.gpgkeyverifier.filter_valid_keys(recipient_fingerprints)

                    if(valid_recipient_fingerprints == []):
                        self.logger.critical('No recipient keys available. Exiting.')
                        sys.exit(1)

                    # TODO: This should be done on a configurable interval, not every time it sends.
                    sender_expiration_message = self.gpgkeyverifier.build_key_expiration_message(self.config['expiration_warning_threshold'], \
                        [self.config['sender']['fingerprint']])

                    # Remove sender key from message, as it will be prepended later
                    unique_recipient_fingerprints = list(recipient_fingerprints)
                    unique_recipient_fingerprints.remove(self.config['sender']['fingerprint'])

                    key_expiration_message = self.gpgkeyverifier.build_key_expiration_message(self.config['expiration_warning_threshold'], unique_recipient_fingerprints)
                    message_dict['body'] = '%s%s%s' % (sender_expiration_message, key_expiration_message, message_dict['body'])

                    # Set default subject if the queued message does not have one.
                    if message_dict['subject'] == None:
                        message_dict['subject'] = self.config['default_subject']

                    # Try to encrypt the message.
                    # TODO: encrypted_message should return status information, not set class/instance variable.
                    # TODO: gpgmailer.build_message should throw exceptions on errors.
                    encrypted_message = self.gpgmailbuilder.build_message(message_dict, valid_recipient_fingerprints, self.config['sender']['fingerprint'], \
                        self.config['sender']['password'])

                    # TODO: Explain this, regardless of future changes.
                    # TODO: Joel wants to see if we can distinguish different 
                    #   kinds of failure for signing and only crash on some.
                    if self.gpgmailbuilder.signature_error and not(self.config['allow_expired_signing_key']):
                        self.logger.critical('Signing message %s failed and sending unsigned messages is not allowed. Exiting.' % file_name)
                        sys.exit(1)

                    # TODO: Find out if we can get more granular error info
                    #   and handle it.
                    if self.gpgmailbuilder.encryption_error:
                        self.logger.error('Encrypting message %s failed.' % file_name)

                    else:
                        self.logger.trace('Successfully built message %s.' % file_name)

                        # TODO: Don't put this in an if statement, throw exceptions
                        #   for errors instead.
                        if not(self.mailsender.sendmail(encrypted_message)):
                            # TODO: Some mechanism to handle mail errors.
                            self.logger.error('Failed to send message %s.' % file_name)

                        else:
                            self.logger.info('Message %s sent successfully.' % file_name)
                            # TODO: Use os.path.join here instead.
                            os.remove('%s%s' % (self.config['watch_dir'],file_name))
                            

            time.sleep(self.config['main_loop_delay'])

    # Read a message file and build a dictionary of message information 
    #   appropriate for gpgmailbuilder.
    def _read_message_file(self, file_name):

        message_dict = {}

        # TODO: Move try/except statements to start_montiring.
        try:
            # TODO: Use os.path.join instead of string concatenation.
            with open('%s%s' % (self.config['watch_dir'], file_name), 'r') as file_handle:
                message_dict = json.loads(file_handle.read())

            for attachment in message_dict['attachments']:
                # Attachment data is assumed to be encoded in base64.
                attachment['data'] = base64.b64decode(attachment['data'])
            
        except Exception as e:
            # TODO: Log the stack trace in error level.
            self.logger.error('Exception: %s\n' % e.message);

        return message_dict
