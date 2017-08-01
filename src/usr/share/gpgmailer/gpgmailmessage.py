#!/usr/bin/env python2

# Copyright 2015-2017 Joel Allen Luellwitz, Andrew Klapp and Brittney
# Scaccia.
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

import confighelper
import ConfigParser
import base64
import datetime
import hashlib
import json
import logging
import os
import shutil
import sys

# Constructs an e-mail message and serializes it to the mail queue directory.
#   Messages are queued in JSON format.
#
# This class is not thread safe.
#
# This class assumes a logger has already been instantiated.
#
# Note: Each method should check if this object has already been saved and
#   throw an exception if it has.
class GpgMailMessage:

    _outbox_dir = None
    _draft_dir = None

    # Reads the gpgmailer config file to obtain the watch directory's path name.
    #   This method must be called before any instances are created.
    @classmethod
    def configure(cls):
        logger = logging.getLogger('GpgMailMessage')

        config_file = ConfigParser.SafeConfigParser()
        config_file.read('/etc/gpgmailer/gpgmailer.conf')

        config_helper = confighelper.ConfigHelper()


        mail_dir = config_helper.verify_string_exists(config_file, 'watch_dir')
        cls._outbox_dir = os.path.join(mail_dir, 'outbox')
        cls._draft_dir = os.path.join(mail_dir, 'draft')

        # TODO: If the watch directory is not on a ramdisk, (i.e. if the daemon has
        #   not started) and mail is saved, then the daemon will fail to start.

        if not(os.path.isdir(cls._outbox_dir)) or not(os.path.isdir(cls._draft_dir)):
            logger.critical('A watch subdirectory does not exist. Quitting.')
            sys.exit(1)

    # Initializes the class.
    def __init__(self):

        # Verify the 'configure' class method was called.
        if (self._outbox_dir == None) or (self._draft_dir == None):
            #TODO: We should thrown our own exception here, not a builtin generic one.
            raise RuntimeError('GpgMailMessage.configure() must be called before an instance ' + \
                'can be created.')

        self.saved = False
        self.message = {}
        self.message['attachments'] = []
        self.message['subject'] = None

    # Adds the plain-text subject of the message.
    #
    # subject: The plain-text subject to set.
    def set_subject(self, subject):
        self._check_if_saved()
        self.message['subject'] = subject

    # Adds the plain-text body of the message.
    #
    # body: The plain-text body to set.
    def set_body(self, body):
        self._check_if_saved()
        self.message['body'] = body

    # Adds an attachment to the message.
    #
    # filename: The filename for the attachment.
    # data: The binary content of the attachment.
    def add_attachment(self, filename, data):
        self._check_if_saved()
        self.message['attachments'].append({ 'filename': filename, 'data': data })

    # Saves the message to the 'outbox' directory and marks this message class instance as 'saved'
    #   meaning no addtional method calls can be made on the current message object.
    def queue_for_sending(self):
        self._check_if_saved()

        if self.message['body'] == None:
            #TODO: We should thrown our own exception here, not a builtin generic one.
            raise Exception('Tried to save message without a body.')

        # Encode any attachments as base64.
        for attachment in self.message['attachments']:
            attachment['data'] = base64.b64encode(attachment['data'])

        # Serialize into JSON.
        message_json = json.dumps(self.message)

        # Write message to filesystem.
        message_sha256 = hashlib.sha256(message_json).hexdigest()
        time_string = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%f')
        # Write to a draft directory so the message doesn't get picked up before it is
        #   fully created.
        message_filename = '%s-%s' % (time_string, message_sha256)
        draft_pathname = os.path.join(self._draft_dir, message_filename)
        message_file = open(draft_pathname, 'w+')
        message_file.write(message_json)
        message_file.close()

        # Move the file to the outbox which should be an atomic operation
        outbox_pathname = os.path.join(self._outbox_dir, message_filename)
        shutil.move(draft_pathname, outbox_pathname)

        # Causes all future methods calls to fail.
        self.saved = True

        return self.saved

    # Checks if this message has already been saved and throws an Exception if it has been.
    def _check_if_saved(self):
        if self.saved:
            #TODO: We should thrown our own exception here, not a builtin generic one.
            raise Exception('Tried to save an already saved message.')
