#!/usr/bin/env python2

# Copyright 2015-2017 Joel Allen Luellwitz and Emily Frost
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

__all__ = [
    'WatchDirectoryMissingException', 'SaveMessageWithoutBodyException',
    'ModifyAlreadySavedMessageException', 'GpgMailMessageNotConfiguredException',
    'GpgMailMessage']
__author__ = 'Joel Luellwitz, Emily Frost, and Brittney Scaccia'
__version__ = '0.8'

from parkbenchcommon import confighelper
import ConfigParser
import base64
import datetime
import hashlib
import json
import logging
import os
import shutil


class WatchDirectoryMissingException(Exception):
    """This exception is raised when gpgmailer is configured but the watch directories do not
    exist.
    """


class SaveMessageWithoutBodyException(Exception):
    """This exception is raised when a message without a body is attempted to be saved."""


class ModifyAlreadySavedMessageException(Exception):
    """This exception is raised when a message is attempted to be saved after already having
    been saved.
    """


class GpgMailMessageNotConfiguredException(Exception):
    """This exception is raised when a GpgMailMessage object is instantiated without calling
    the class's configure method beforehand.
    """


class GpgMailMessage:
    """Constructs an e-mail message and serializes it to the mail queue directory.
    Messages are queued in JSON format.

    This class is not thread safe.

    This class assumes a logger has already been instantiated.

    Note: Each method should check if this object has already been saved and
      throw an exception if it has.
    """
    _outbox_dir = None
    _draft_dir = None

    # TODO: Eventually make this method so it can be called twice.
    @classmethod
    def configure(cls):
        """Reads the gpgmailer config file to obtain the watch directory's path name.
        This method must be called before any instances are created.
        """
        logger = logging.getLogger('GpgMailMessage')

        config_file = ConfigParser.SafeConfigParser()
        config_file.read('/etc/gpgmailer/gpgmailer.conf')

        config_helper = confighelper.ConfigHelper()

        mail_dir = config_helper.verify_string_exists(config_file, 'watch_dir')
        cls._outbox_dir = os.path.join(mail_dir, 'outbox')
        cls._draft_dir = os.path.join(mail_dir, 'draft')

        if not(os.path.isdir(cls._outbox_dir)) or not(os.path.isdir(cls._draft_dir)):
            logger.critical('A watch subdirectory does not exist. Quitting.')
            raise WatchDirectoryMissingException('A watch subdirectory does not exist.')

    def __init__(self):
        """Initializes the class."""

        # Verify the 'configure' class method was called.
        if (self._outbox_dir is None) or (self._draft_dir is None):
            # TODO: Consider just calling configure here instead of raising an exception.
            raise GpgMailMessageNotConfiguredException(
                'GpgMailMessage.configure() must be called an instance can be created.')

        self.saved = False
        self.message = {}
        self.message['body'] = None
        self.message['attachments'] = []
        self.message['subject'] = None

    def set_subject(self, subject):
        """Adds the plain-text subject of the message.

        subject: The plain-text subject to set.
        """
        self._check_if_saved()
        self.message['subject'] = subject

    def set_body(self, body):
        """Adds the plain-text body of the message.

        body: The plain-text body to set.
        """
        self._check_if_saved()
        self.message['body'] = body

    def add_attachment(self, filename, data):
        """Adds an attachment to the message.

        filename: The filename for the attachment.
        data: The binary content of the attachment.
        """
        self._check_if_saved()
        self.message['attachments'].append({'filename': filename, 'data': data})

    def queue_for_sending(self):
        """Saves the message to the 'outbox' directory and marks this message class instance
        as 'saved' meaning no addtional method calls can be made on the current message
        object.
        """
        self._check_if_saved()

        if self.message['body'] is None:
            raise SaveMessageWithoutBodyException('Tried to save a message without a body.')

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

    def _check_if_saved(self):
        """Checks if this message has already been saved and throws an Exception if it has
        been.
        """
        if self.saved:
            raise ModifyAlreadySavedMessageException(
                'Tried to modify an already saved message.')
