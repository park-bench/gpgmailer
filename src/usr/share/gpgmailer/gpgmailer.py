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
import traceback

# TODO: Write more effective logging.
# TODO: Prefer named parameters for more than one parameter.
# Manages all of the other classes to send emails based on the files in the
#   outbox directory.
class GpgMailer:
    # TODO: Document the constructor.
    def __init__(self, config, gpgkeyring):
        self.logger = logging.getLogger('GpgMailer')
        self.logger.info('Gpgmailer initializing.')

        self.config = config
        self.gpgkeyring = gpgkeyring
        self.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(self.config['gpg_dir'], self.config['main_loop_duration'])

        self.gpgkeyverifier = gpgkeyverifier.GpgKeyVerifier(self.gpgkeyring, self.config)

        self.mailsender = mailsender.MailSender(self.config)

        self.last_recipient_update = 0
        self._update_recipient_info(time.time())

        self.outbox_path = os.path.join(self.config['watch_dir'], 'outbox')

        self.logger.info('GpgMailer initialized.')

    # Gpgmailer's main loop. Reads the watch directory and then calls other modules
    #   to build and send email.
    def start_monitoring(self):
        try:
            while True:
                # The first element of os.walk is the full path, the second is a
                #   list of directories, and the third is a list of non-directory
                #   files.
                file_list = next(os.walk(self.outbox_path))[2]

                loop_start_time = time.time()

                self._update_recipient_info(loop_start_time)

                if(self.send_warning_email):
                    self.logger.info('Sending an expiration warning email.')
                    self._send_warning_email()
                    self.send_warning_email = False


                for file_name in file_list:
                    self.logger.info("Found file %s." % file_name)

                    fullpath = os.path.join(self.outbox_path, file_name)
                    message_dict = self._read_message_file(fullpath)

                    self.logger.trace('Message file %s read.' % file_name)

                    # Set default subject if the queued message does not have one.
                    if message_dict['subject'] == None:
                        message_dict['subject'] = self.config['default_subject']

                    encrypted_message = self._build_encrypted_message(message_dict)

                    self.mailsender.sendmail(message_string=encrypted_message, recipients=self.recipients)
                    self.logger.info('Message %s sent successfully.' % file_name)

                    os.remove(os.path.join(self.outbox_path, file_name))

                time.sleep(self.config['main_loop_delay'])

        except Exception as e:
            self.logger.error('Exception %s:%s.' % (type(e).__name__, e.message))
            self.logger.debug(traceback.format_exc())


    # Read a message file and build a dictionary of message information 
    #   appropriate for gpgmailbuilder.
    def _read_message_file(self, fullpath):

        message_dict = {}

        with open(fullpath, 'r') as file_handle:
            message_dict = json.loads(file_handle.read())

        for attachment in message_dict['attachments']:
            # Attachment data is assumed to be encoded in base64.
            attachment['data'] = base64.b64decode(attachment['data'])

        return message_dict

    # Get recipient list, key list, expiration message, and whether to send an
    #   email from gpgkeyverifier.
    def _update_recipient_info(self, loop_start_time):
        if self.last_recipient_update + self.config['key_check_interval'] < loop_start_time:
            recipient_info = self.gpgkeyverifier.get_recipient_info(loop_start_time)

            self.recipients = recipient_info['valid_recipients']
            self.keys = recipient_info['valid_keys']
            self.expiration_message = recipient_info['expiration_message']
            self.send_warning_email = recipient_info['send_email']

            self.last_recipient_update = loop_start_time

    # Send a warning email containing the expiration message.
    def _send_warning_email(self):
        message_dict = { 'body': self.expiration_message,
                    'subject': self.config['default_subject']}

        encrypted_message = self._build_encrypted_message(message_dict)

        self.mailsender.sendmail(encrypted_message, self.recipients)

    # Build an encrypted email string with a signature if possible.
    def _build_encrypted_message(self, message_dict):
        if(self.config['send_unsigned_email']):
            message = self.gpgmailbuilder.build_encrypted_message(message_dict=message_dict, 
                encryption_keys=self.keys)

        else:
            message = self.gpgmailbuilder.build_signed_encrypted_message(message_dict=message_dict,
                signing_key=self.config['sender']['fingerprint'], 
                signing_key_passphrase=self.config['sender']['password'], 
                encryption_keys=self.keys)

        return message
