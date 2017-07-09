# Copyright 2015-2017 Joel Allen Luellwitz and Andrew Klapp
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

import datetime
import gnupg
import logging
import re
import time

# This exception is raised when a GPG fingerprint is not a 40-character hexadecimal
#   string.
class FingerprintSyntaxException(Exception):
    pass

# This exception is thrown when a GPG fingerprint is not in the given key ring.
class KeyNotFoundException(Exception):
    pass

key_fingerprint_regex = re.compile('^[0-9a-fA-F]{40}$')
# These trust levels come from GnuPG, 'u' means ultimate, 'f' means full, and 'm' means marginal.
valid_owner_trust_levels = ('u', 'f', 'm')

# GpgKeyRing caches and checks validity, expiration, and trust for GPG keys.
class GpgKeyRing:

    # Loads select portions of the GnuPG keyring and stores the information in an internal dict.
    #
    # gnupg_home: The GnuPG keyring directory.
    def __init__(self, gnupg_home):
        self.logger = logging.getLogger('GpgKeyRing')
        self.gnupg_home = gnupg_home
        self.gpg = gnupg.GPG(gnupghome=self.gnupg_home)
        self.fingerprint_to_key_dict = {}

        for key in self.gpg.list_keys():
            
            # Key expiration dates are in Unix time. An expiration date of None
            #   means that the key does not expire.
            if key['expires'] == '':
                key['expires'] = None
            else:
                key['expires'] = int(key['expires'])

            self.fingerprint_to_key_dict[key['fingerprint']] = {
                'expires': key['expires'],
                'ownertrust': key['ownertrust'],
                'fingerprint': key['fingerprint']
            }


    # Checks if the GPG key with the given fingerprint expires after the given date.
    #
    # fingerprint: The fingerprint of the GPG key to check for expiration.
    # expiration_date: The date (in Unix time) to compare against the GPG key's expiration date.
    def is_current(self, fingerprint, expiration_date):
        current = False
        self._fingerprint_is_valid(fingerprint)

        self.logger.trace('Checking expiration for GPG key %s at date %s.' % (fingerprint,
            expiration_date))

        if self.fingerprint_to_key_dict[fingerprint]['expires'] is None or 
            self.fingerprint_to_key_dict[fingerprint]['expires'] > expiration_date:

            current = True
            self.logger.trace('Key %s is current.' % fingerprint)

        else:
            self.logger.trace('Key %s expired after date %s.' % (fingerprint, expiration_date))

        return current


    # Checks if a GPG key with the given fingerprint is trusted.
    #
    # fingerprint: The fingerprint of the GPG key to check.
    def is_trusted(self, fingerprint):
        trusted = False
        self._fingerprint_is_valid(fingerprint)

        if self.fingerprint_to_key_dict[fingerprint]['ownertrust'] in valid_owner_trust_levels:
            trusted = True

        else:
            self.logger.warn('Key %s is not trusted.' % fingerprint)

        return trusted


    # Returns a GPG key expiration date based on a key fingerprint. If the key fingerprint is
    #   invalid or does not exist in the keyring, an exception is thrown.
    #
    # fingerprint: A GPG key fingerprint.
    # Returns the key's expiration date or None if no expiration date exist.
    def get_key_expiration_date(self, fingerprint):
        self._fingerprint_is_valid(fingerprint)

        return self.fingerprint_to_key_dict[fingerprint]['expires']


    # Checks if a GPG key fingerprint is valid and is in the keyring. If the key is not valid or
    #   does not exist in the keyring, an exception is thrown.
    #
    # fingerprint: The fingerprint of the GPG key to check.
    def _fingerprint_is_valid(self, fingerprint):

        if not key_fingerprint_regex.match(fingerprint):
            message = 'String %s is not a valid PGP fingerprint.' % fingerprint
            self.logger.error(message)
            raise FingerprintSyntaxException(message)

        elif not fingerprint in self.fingerprint_to_key_dict.keys():
            message = 'Key fingerprint %s not found in GPG key store.' % fingerprint
            self.logger.error(message)
            raise KeyNotFoundException(message)
