# Copyright 2015-2018 Joel Allen Luellwitz and Emily Frost
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
import configparser
import base64
import datetime
import json
import logging
import os
import shutil
import stat

SPOOL_DIR = '/var/spool/gpgmailer'
PARTIAL_DIR = os.path.join(SPOOL_DIR, 'partial')
OUTBOX_DIR = os.path.join(SPOOL_DIR, 'outbox')


class WatchDirectoryMissingException(Exception):
    """This exception is raised when gpgmailer is configured but the spool directories do not
    exist.
    """


class SaveMessageWithoutBodyException(Exception):
    """This exception is raised when a message without a body is attempted to be saved."""


class ModifyAlreadySavedMessageException(Exception):
    """This exception is raised when a message is attempted to be saved after already having
    been saved.
    """


class GpgMailMessage(object):
    """Constructs an e-mail message and serializes it to the mail queue directory.
    Messages are queued in JSON format.

    This class is not thread safe.

    This class assumes a logger has already been instantiated.

    Note: Each method should check if this object has already been saved and
      throw an exception if it has.
    """

    def __init__(self):
        """Initializes the class."""

        logger = logging.getLogger(__name__)

        # Verify there is some place to save the e-mails.
        if not os.path.isdir(PARTIAL_DIR) or not os.path.isdir(OUTBOX_DIR):
            error_message = 'A gpgmailer spool subdirectory does not exist.'
            logger.error(error_message)
            raise WatchDirectoryMissingException(error_message)

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
            attachment['data'] = base64.b64encode(attachment['data']).decode('utf-8')

        # Serialize into JSON.
        message_json = json.dumps(self.message)

        # Write message to filesystem.
        time_string = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%f')
        # For security, the filename should not be guessable. Hence the random component.
        message_filename = '%s-%s' % (time_string, os.urandom(16).hex())
        # Write to a 'partial' directory so the message doesn't get picked up before it is
        #   fully created.
        partial_pathname = os.path.join(PARTIAL_DIR, message_filename)
        with os.fdopen(os.open(
            partial_pathname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            # -rw-r-----
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP), 'w') as message_file:
            message_file.write(message_json)

        # Move the file to the outbox which should be an atomic operation
        outbox_pathname = os.path.join(OUTBOX_DIR, message_filename)
        shutil.move(partial_pathname, outbox_pathname)

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
