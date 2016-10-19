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
import gpgkeyring
import gpgmailbuilder
import json
import logging
import os
import timber
import time

class GpgMailer:
    def __init__(self, config, gpgkeyring):
        self.logger = timber.get_instance()
=======
# TODO: Write more effective logging.
# TODO: I kinda want to review method separation and naming for the entire file.

class mailer ():
    
    def __init__(self, config):
        self.logger = logging.getLogger()
>>>>>>> master:src/usr/share/gpgmailer/gpgmailer.py
        self.config = config
        self.gpgkeyring = gpgkeyring
        self.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(self.config['gpg_home'])
        # self.gpgkeychecker = gpgkeychecker.GpgKeyChecker(self.gpgkeyring, config['expiration_warning_threshold'])

        self.logger.info('GpgMailer initialized.')
        # TODO: Check keys here.

    def start_monitoring(self, directory):
        
        while True:
            file_list = next(os.walk(self.config['watch_dir']))[2]
            for file_name in file_list:
                message_dict = self._read_message_file(file_name)
                if message_dict == {}:
                    # TODO: Some mechanism to ignore broken files
                    self.logger.error('Message file %s could not be read.' % file_name)

                else:
                    # Try to encrypt the message.
                    encrypted_message = self.gpgmailbuilder.build_message(message_dict, recipient_fingerprints)

                    if encrypted_message == None:
                        # TODO: Some mechanism to ignore broken files
                        self.logger.error('Encrypting or signing message %s failed.' % file_name)

                    else:
                        # TODO Actually send mail. For testing, just logging is fine.
                        self.logger.info('Successfully read message %s.' % file_name)

            # TODO: Move key expiration checks into this area.
            # TODO: Make configurable.
            time.sleep(.1)

    # Read a message file and build a dictionary appropriate for gpgmailbuilder.
    def _read_message_file(self, file_name):

        message_dict = {}

        try:
            with open('%s%s' % (self.config['watch_dir'], file_name), 'r') as file_handle:
                message_dict = json.loads(file_handle.read())

            # TODO: This stuff goes in gpgmailbuilder.
            '''
            message_dict['sender'] = self.config['sender'].email
            message_dict['signing_key_fingerprint'] = self.config['sender'].fingerprint
            '''

            if('attachments' in message_dict.keys()):
                for attachment in message_dict['attachments']:
                    # Attachment data is assumed to be encoded in base64.
                    attachment['data'] = base64.b64decode(attachment['data'])
            
            # TODO: This functionality goes in another bit of the code.
            '''
            self.logger.info('Sending %s' % file_name)
            sending_successful = self.the_mailer.sendmail(file_dict)

            # Remove the file after it has been sent, but not if it failed.
            if sending_successful:
                os.remove('%s%s' % (self.config['watch_dir'],file_name))
            '''

        except Exception as e:
            self.logger.error('Exception: %s\n' % e.message);

        return message_dict
