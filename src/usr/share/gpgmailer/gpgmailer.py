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
import gpgmailbuilder
import gpgmailmessage
import gpgkeyverifier
import json
import logging
import mailsender
import os
import sys
import time
import traceback

# TODO: Write more effective logging.

# Monitors the outbox directory, manages keys, and coordinates sending email.
class GpgMailer:
    # Initialize the mailsender and gpgmailbuilder objects
    #
    # config: the config dict read from the config file
    # gpgkeyring: the GpgKeyring object containing all configured keys
    # gpgkeyverifier: the GpgKeyVerifier object managing all configured keys
    def __init__(self, config, gpgkeyring, gpgkeyverifier):
        self.logger = logging.getLogger('GpgMailer')
        self.logger.info('Initializing gpgmailer module.')
        self.new_expiration_warning_messages = False

        self.config = config
        self.gpgkeyring = gpgkeyring
        self.gpgkeyverifier = gpgkeyverifier
        self.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(self.gpgkeyring, self.config['main_loop_duration'])
        self.mailsender = mailsender.MailSender(self.config)

        self.outbox_path = os.path.join(self.config['watch_dir'], 'outbox')

        # Set expiration_warning_message so that it is not detected as changed immediately
        #   after gpgmailer-daemon sends an email.
        self.expiration_warning_message = gpgkeyverifier.get_expiration_warning_message(time.time())

        self.logger.info('Done initializing gpgmailer module.')

    # Gpgmailer's main loop. Reads the watch directory and then calls other modules
    #   to build and send email.
    def start_monitoring(self):
        try:
            while True:
                loop_start_time = time.time()

                self.recipients = self.gpgkeyverifier.get_valid_recipients(loop_start_time)
                self.keys = self.gpgkeyverifier.get_valid_keys(loop_start_time)

                new_expiration_warning_message = self.gpgkeyverifier.get_expiration_warning_message(loop_start_time)
                self._update_expiration_warning_message(new_expiration_warning_message)
                self._send_email_if_new_expiration_warning_messages()

                for file_name in self._get_file_list():
                    self.logger.info("Found queued email in file %s." % file_name)

                    message_dict = self._read_message_file(file_name)

                    self.logger.trace('Message file %s read.' % file_name)

                    # Set default subject if the queued message does not have one.
                    if message_dict['subject'] == None:
                        message_dict['subject'] = self.config['default_subject']

                    encrypted_message = self._build_encrypted_message(loop_start_time, message_dict)

                    self.mailsender.sendmail(message_string=encrypted_message, recipients=self.recipients)
                    self.logger.info('Message %s sent successfully.' % file_name)

                    os.remove(os.path.join(self.outbox_path, file_name))

                time.sleep(self.config['main_loop_delay'])

        except gpgkeyverifier.NoUsableKeysException as e:
            self.logger.critical('No keys available for encryption. Exiting.')
            sys.exit(1)
        except gpgkeyverifier.SenderKeyExpiredException as e:
            self.logger.critical('Sender key has expired and sending unsigned emails is not allowed. Exiting.')
            sys.exit(1)
        except Exception as e:
            self.logger.error('Exception %s:%s.' % (type(e).__name__, e.message))
            self.logger.error(traceback.format_exc())

    # Return a list of non-directory files in the outbox directory.
    def _get_file_list(self):
        # The first element of os.walk is the full path, the second is a
        #   list of directories, and the third is a list of non-directory
        #   files.
        return next(os.walk(self.outbox_path))[2]


    # Read a message file and build a dictionary of message information 
    #   appropriate for gpgmailbuilder.
    #
    # file_name: the name of the file in the outbox, not a full path.
    def _read_message_file(self, file_name):
        fullpath = os.path.join(self.outbox_path, file_name)

        message_dict = {}

        with open(fullpath, 'r') as file_handle:
            message_dict = json.loads(file_handle.read())

        for attachment in message_dict['attachments']:
            # Attachment data is assumed to be encoded in base64.
            attachment['data'] = base64.b64decode(attachment['data'])

        return message_dict


    # Send an email if there are new expiration warnings.
    def _send_email_if_new_expiration_warning_messages(self):
        if self.new_expiration_warning_messages:
            self.logger.info('Sending an expiration warning email.')
            self._send_warning_email(self, loop_start_time, self.expiration_warning_message)
            self.new_expiration_warning_messages = False


    # Determine whether the new expiration message differs from the old one, and
    #   if it does, update it and set the new expiration warnings flag.
    def _update_expiration_warning_message(self, new_expiration_warning_message):
        if self.expiration_warning_message != new_expiration_warning_message:
            self.logger.info('A new key is no longer current. Sending an email.')
            self.expiration_warning_message = new_expiration_warning_message
            self.new_expiration_warning_messages = True


    # Send an email containing the expiration warning message.
    #
    # loop_start_time: the time from which all expiration checks are based
    # expiration_warning_email_text: the body of the warning email
    def _send_warning_email(self, loop_start_time, expiration_warning_email_text):

        message_dict = { 'body': expiration_warning_email_text,
                    'subject': self.config['default_subject']}

        encrypted_message = self._build_encrypted_message(loop_start_time, message_dict)

        self.mailsender.sendmail(encrypted_message, self.recipients)


    # Build an encrypted email string with a signature if possible.
    #
    # loop_start_time: the time from which all expiration checks are based
    # message_dict: a dictionary containing the body, subject, and attachments of a message
    def _build_encrypted_message(self, loop_start_time, message_dict):
        # gpgkeyverifier already throws an exception when the sender key expires
        #   and sending unsigned email is not allowed, no need to do it again.
        sender_key_is_current = self.config['sender']['fingerprint'] in self.keys

        if not(sender_key_is_current or self.config['sender']['can_sign']):
            message = self.gpgmailbuilder.build_encrypted_message(loop_start_time=loop_start_time, message_dict=message_dict, 
                encryption_keys=self.keys)

        else:
            message = self.gpgmailbuilder.build_signed_encrypted_message(loop_start_time, message_dict=message_dict,
                signing_key=self.config['sender']['fingerprint'], 
                signing_key_passphrase=self.config['sender']['password'], 
                encryption_keys=self.keys)

        return message
