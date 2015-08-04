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

# class mailer_monitor
#   monitors arbitrary directory
#   iterates through JSON object files
#   sends emails using gpgmailer based on the object files

import gpgmailer
import os
import timber
import time
import base64
import json


# TODO: I'm not sure class names are suppose to be snake case.
class mailer_monitor():
    def __init__(self, config):
        self.logger = timber.get_instance()
        self.config = config
        self.the_mailer = gpgmailer.mailer(self.config)

    def start_monitoring(self):

        while 1:
            # check for new files and send them with _sendmail()
            # TODO: decide how to handle directories in the watch_dir
            # TODO: add a way to handle invalid json objects/non-json files
            file_list = next(os.walk(self.config['watch_dir']))[2]
            file_list.sort()
            for file_name in file_list:
                file_handle = open('%s%s' % (self.config['watch_dir'], file_name), 'r')
                try:
                    file_dict = json.loads(file_handle.read())
                    file_handle.close()
                    file_dict['sender'] = self.config['sender']['email']
                    file_dict['signing_key_fingerprint'] = self.config['sender']['fingerprint']
                    for attachments in file_dict['attachments']:
                        attachments['data'] = base64.b64decode(attachments['data'])
                
                    self.logger.trace('Sending %s' % file_name)
                    self.the_mailer.sendmail(file_dict)
                    os.remove('%s%s' % (self.config['watch_dir'],file_name))
                except Exception as e:
                    self.logger.trace("Exception: %s\n" % e.message);
                    file_handle.close()

            time.sleep(.1)
  
