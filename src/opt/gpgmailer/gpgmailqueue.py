#!/usr/bin/env python2
# Copyright 2015 Joel Allen Luellwitz and Andrew Klapp
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
MAIL_DIR = '/tmp/gpgmailer'

# Each method should check if this object has already been saved and throw an
#   exception if it has
class GpgMailQueue:
    def __init__(self):
        self.saved = False
        self.message = {}

    def _check_if_saved(self):
        # Check if this object has been saved and throw an exception if it has
        if(self.saved):
            raise Exception('Tried to save an already saved message.')

    def set_subject(self, subject):
        self._check_if_saved()
        self.message['subject'] = subject

    def set_body(self, body):
        self._check_if_saved()
        self.message['body'] = body

    def add_attachment(self, filename, data):
        self._check_if_saved()
        if not('attachments' in self.message.keys()):
            self.message['attachments'] = []

        self.message['attachments'].append({ 'filename': filename, 'data': data })

    def save(self):
        self._check_if_saved()
        # Check for subject and message, throw an exception if they aren't there
        if(self.message['subject'] == None):
            raise Exception('Tried to save message without a subject.')

        if(self.message['body'] == None):
            raise Exception('Tried to save message without a body.')

        # Encode any attachments as base64
        if('attachments' in self.message.keys()):
            for attachment in self.message['attachments']:
                attachment['data'] = base64.b64encode(attachment['data'])

        # Serialize into JSON
        message_json = json.dumps(self.message)
        message_sha256 = hashlib.sha256(message_json).hexdigest()
        time_string = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%f')

        try:
            # Write to a draft directory to so the message doesn't get picked up before it is
            #   fully created.
            # TODO: These paths should be configurable.
            draft_pathname = '%s/draft/%s-%s' % (MAIL_DIR, time_string, message_sha256)
            message_file = open(draft_pathname, 'w+')
            message_file.write(message_json)
            message_file.close()

            # Move the file to the outbox which should be an atomic operation
            # TODO: Make this path configurable.
            outbox_pathname = '%s/outbox/%s-%s' % (MAIL_DIR, time_string, message_sha256)
            shutil.move(draft_pathname, outbox_pathname)
            self.saved = True
        except Exception as e:
            raise e
