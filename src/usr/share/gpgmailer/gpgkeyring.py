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

import gnupg
import logging
import re
import time

key_fingerprint_regex = re.compile('^[0-9a-fA-F]{40}$')
valid_owner_trust_levels = ('u', 'f', 'm')

class GpgKeyRing:

    def __init__(self, gnupg_home):
        self.logger = logging.getLogger('GpgKeyRing')
        self.gpg = gnupg.GPG(gnupghome=gnupg_home)
        self.keys = {}

        for key in self.gpg.list_keys():
            
            if key['expires'] == '':
                key['expires'] = None
            else:
                key['expires'] = int(key['expires'])

            self.keys[key['fingerprint']] = {
                'expires': key['expires'],
                'ownertrust': key['ownertrust'],
                'email': None,
                'fingerprint': key['fingerprint'],
                'expired_email': False,
                'expiring_soon_email': False
            }


    # Check if key fingerprint is expired at date and return True or False.
    def is_expired(self, fingerprint, check_date=time.time()):
        # TODO: Also check the encryption subkey.
        expired = True

        if self._valid_fingerprint(fingerprint):
            self.logger.debug('Expiration: %s, check date: %s' % (self.keys[fingerprint]['expires'], check_date))
            if (self.keys[fingerprint]['expires'] == None) or (self.keys[fingerprint]['expires'] > check_date):
                expired = False

        self.logger.debug('Expired: %s' % expired)
        return expired

    # Check if key fingerprint is trusted and return True or False.
    def is_trusted(self, fingerprint):
        trusted = False

        if self._valid_fingerprint(fingerprint):
            if self.keys[fingerprint]['ownertrust'] in valid_owner_trust_levels:
                trusted = True

        return trusted

    # Returns the key's expiration date in Unix time.
    def get_key_data(self, fingerprint):
        result = None

        if self._valid_fingerprint(fingerprint):
            if fingerprint in self.keys.keys():
                result = self.keys[fingerprint]

        return result

    # Sets the passed email address for the given key.
    def set_key_email(self, fingerprint, email):
        success = False
        if self._valid_fingerprint(fingerprint):
            self.keys[fingerprint]['email'] = email
            success = True

        return success

    # Checks the formatting of a fingerprint string.
    def _valid_fingerprint(self, fingerprint):
        valid = False

        if not(key_fingerprint_regex.match(fingerprint)):
            self.logger.error('Key fingerprint %s is not a valid PGP fingerprint.' % fingerprint)
        
        elif not(fingerprint in self.keys.keys()):
            self.logger.error('Key fingerprint %s not found in GPG key store.' % fingerprint)

        else:
            self.logger.debug('Key fingerprint %s is good.' % fingerprint)
            valid = True

        return valid
