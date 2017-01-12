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
class GpgMailer:
    def __init__(self, config, gpgkeyring):
        self.logger = logging.getLogger('GpgMailer')
        self.config = config
        self.gpgkeyring = gpgkeyring
        self.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(self.config['gpg_dir'], self.config['send_unsigned_messages'])
        self.gpgkeyverifier = gpgkeyverifier.GpgKeyVerifier(self.gpgkeyring, self.config['main_loop_delay'], self.config)

        self.mailsender = mailsender.MailSender(self.config)

        all_key_fingerprints = [key['fingerprint'] for key in self.config['recipients']]
        if not(self.config['sender']['fingerprint'] in all_key_fingerprints):
            all_key_fingerprints.append(self.config['sender']['fingerprint'])

        self.gpgkeyverifier.build_key_expiration_message(self.config['expiration_warning_threshold'], all_key_fingerprints, first_run=True)

        self.logger.info('GpgMailer initialized.')

    def start_monitoring(self, directory):
        
        while True:
            file_list = next(os.walk(self.config['watch_dir']))[2]
            for file_name in file_list:
                self.logger.info("Found file %s." % file_name)
                message_dict = self._read_message_file(file_name)
                if message_dict == {}:
                    # TODO: Some mechanism to ignore broken files
                    self.logger.error('Message file %s could not be read.' % file_name)

                else:
                    self.logger.info('Message file read.')

                    key_check_date = time.time() + self.config['main_loop_delay']

                    recipient_fingerprints = [key['fingerprint'] for key in self.config['recipients']]
                    valid_recipient_fingerprints = self.gpgkeyverifier.filter_valid_keys(recipient_fingerprints)

                    if(valid_recipient_fingerprints == []):
                        self.logger.critical('No recipient keys available. Exiting.')
                        sys.exit(1)

                    sender_expiration_message = self.gpgkeyverifier.build_key_expiration_message(self.config['expiration_warning_threshold'], \
                        [self.config['sender']['fingerprint']])

                    # Remove sender key from message, as it will be prepended later
                    unique_recipient_fingerprints = list(recipient_fingerprints)
                    unique_recipient_fingerprints.remove(self.config['sender']['fingerprint'])

                    key_expiration_message = self.gpgkeyverifier.build_key_expiration_message(self.config['expiration_warning_threshold'], unique_recipient_fingerprints)
                    message_dict['body'] = '%s%s%s' % (sender_expiration_message, key_expiration_message, message_dict['body'])

                    if not(message_dict['subject']):
                        message_dict['subject'] = self.config['default_subject']

                    # Try to encrypt the message.
                    encrypted_message = self.gpgmailbuilder.build_message(message_dict, valid_recipient_fingerprints, self.config['sender']['fingerprint'], \
                        self.config['sender']['password'])


                    if self.gpgmailbuilder.signature_error and not(self.config['send_unsigned_messages']):
                        # TODO: Handle signing/encryption errors properly
                        self.logger.critical('Signing message %s failed and sending unsigned messages is not allowed. Exiting.' % file_name)
                        sys.exit(1)

                    elif self.gpgmailbuilder.encryption_error:
                        # TODO: Handle signing/encryption errors properly
                        self.logger.error('Encrypting message %s failed.' % file_name)

                    else:
                        self.logger.info('Successfully read message %s.' % file_name)
                        if not(self.mailsender.sendmail(encrypted_message)):
                            # TODO: Some mechanism to handle mail errors.
                            self.logger.error('Failed to send message %s.' % file_name)

                        else:
                            self.logger.info('Message %s sent successfully.' % file_name)
                            os.remove('%s%s' % (self.config['watch_dir'],file_name))
                            

            time.sleep(self.config['main_loop_delay'])

    # Read a message file and build a dictionary appropriate for gpgmailbuilder.
    def _read_message_file(self, file_name):

        message_dict = {}

        try:
            with open('%s%s' % (self.config['watch_dir'], file_name), 'r') as file_handle:
                message_dict = json.loads(file_handle.read())

            if('attachments' in message_dict.keys()):
                for attachment in message_dict['attachments']:
                    # Attachment data is assumed to be encoded in base64.
                    attachment['data'] = base64.b64decode(attachment['data'])
            
        except Exception as e:
            self.logger.error('Exception: %s\n' % e.message);

        return message_dict
