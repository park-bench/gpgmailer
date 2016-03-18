#!/usr/bin/env python2
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
import copy
import datetime
import hashlib
import json
import os
import shutil

# TODO: Remove hard-coded mail directory.
mail_dir = '/tmp/gpgmailer'

# Constructs an e-mail message and serializes it to the mail queue directory.
#   Messages are queued in json format.
#
# Note: Each method should check if this object has already been saved and
#   throw an exception if it has.
class GpgMailMessage:

    # Initializes the class.
    def __init__(self):
        self.saved = False
        self.message = {}
        self.message['attachments'] = []

    # Adds the subject of the message.
    def set_subject(self, subject):
        self._check_if_saved()
        self.message['subject'] = subject

    # Adds the text body of the message.
    def set_body(self, body):
        self._check_if_saved()
        self.message['body'] = body

    # Adds an attachment to the message.
    def add_attachment(self, filename, data):
        self._check_if_saved()
        self.message['attachments'].append({ 'filename': filename, 'data': data })

    # Saves the message to the outbox directory and marks this message class as saved
    #   meaning no addtional method calls can be made on the current message object.
    def save(self):
        self._check_if_saved()

        # Check for subject and message, throw an exception if they aren't there
        if(self.message['subject'] == None):
            raise Exception('Tried to save message without a subject.')

        if(self.message['body'] == None):
            raise Exception('Tried to save message without a body.')

        # Encode any attachments as base64
        for attachment in self.message['attachments']:
            attachment['data'] = base64.b64encode(attachment['data'])

        # Serialize into JSON
        message_json = json.dumps(self.message)
        message_sha256 = hashlib.sha256(message_json).hexdigest()
        time_string = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%f')

        # Write to a draft directory to so the message doesn't get picked up before it is
        #   fully created.
        draft_pathname = '%s/draft/%s-%s' % (mail_dir, time_string, message_sha256)
        message_file = open(draft_pathname, 'w+')
        message_file.write(message_json)
        message_file.close()

        # Move the file to the outbox which should be an atomic operation
        outbox_pathname = '%s/outbox/%s-%s' % (mail_dir, time_string, message_sha256)
        shutil.move(draft_pathname, outbox_pathname)

        # Causes all future methods calls to fail.
        self.saved = True

    # Checks if this message has already been saved and throws an Exception if it has been.
    def _check_if_saved(self):
        if(self.saved):
            raise Exception('Tried to save an already saved message.')
