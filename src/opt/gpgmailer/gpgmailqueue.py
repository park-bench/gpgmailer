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

def send(message):

    # message is expected to be a dict that looks something like this one:
    #   { 'subject': 'the subject you want', 'message': 'message body', 'attachments',
    #   [ 'attachment1', 'attachment2', 'etc' ] }

    # Deep copy the object so we don't modify the original (when we return).
    message_copy = copy.deepcopy(message)

    # Base64 encode the attachments. Yeah, binary data doesn't serialize to JSON well.
    if('attachments' in message_copy.keys()):
        for attachment in message_copy['attachments']:
            attachment['data'] = base64.b64encode(attachment['data'])

    message_json = json.dumps(message_copy)
    # Adversaries aren't going to be able to control our input, so MD5 is acceptable
    #   and concise.
    # TODO: Just change to SHA256 for the hell of it.
    message_md5 = hashlib.md5(message_json).hexdigest()
    time_string = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%f')
    # Write to a draft directory to so the message doesn't get picked up before it is
    #   fully created.
    # TODO: These paths should be configurable.
    draft_pathname = '/tmp/gpgmailer/draft/%s-%s' % (time_string, message_md5)
    message_file = open(draft_pathname, 'w+')
    message_file.write(message_json)
    message_file.close()

    # Move the file to the outbox which should be an atomic operation
    # TODO: Make this path configurable.
    outbox_pathname = '/tmp/gpgmailer/outbox/%s-%s' % (time_string, message_md5)
    shutil.move(draft_pathname, outbox_pathname)
