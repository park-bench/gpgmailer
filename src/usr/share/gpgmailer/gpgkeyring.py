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

import datetime
import gnupg
import logging
import re
import time

# This exception is raised when a PGP fingerprint is not a 40-character hexadecimal
#   string.
class FingerprintSyntaxException(Exception):
    pass

# This exception is thrown when a PGP fingerprint is not in the given key store.
class KeyNotFoundException(Exception):
    pass

key_fingerprint_regex = re.compile('^[0-9a-fA-F]{40}$')
# These trust levels come from gnupg, u means ultimate, f means full, and m
#   means marginal.
valid_owner_trust_levels = ('u', 'f', 'm')

# GpgKeyRing caches and checks validity, expiration, and trust for pgp keys.
class GpgKeyRing:
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


    # Check if a key with the given fingerprint is still valid after the given date.
    def is_current(self, fingerprint, expiration_date):
        current = False
        self._fingerprint_is_valid(fingerprint)

        self.logger.trace('Checking expiration for key %s at date %s.' % (fingerprint,
            expiration_date))

        if ((self.fingerprint_to_key_dict[fingerprint]['expires'] == None) or 
             (self.fingerprint_to_key_dict[fingerprint]['expires'] > expiration_date)):

            current = True
            self.logger.trace('Key %s is current.' % fingerprint)

        else:
            self.logger.trace('Key %s expires before date %s.' % (fingerprint, expiration_date))

        return current


    # Check if a key with the given fingerprint is trusted.
    def is_trusted(self, fingerprint):
        trusted = False
        self._fingerprint_is_valid(fingerprint)

        if self.fingerprint_to_key_dict[fingerprint]['ownertrust'] in valid_owner_trust_levels:
            trusted = True

        else:
            self.logger.warn('Key %s is not trusted' % fingerprint)

        return trusted


    # Looks up a key fingerprint and returns the expiration date if it exists,
    #   throws an exception if it is invalid or not in the keyring. If a format
    #   is specified, the date will be expressed in that format.
    #
    #   fingerprint: A PGP key fingerprint
    #   date_format: A format string compatible with Python's strftime.
    def get_key_expiration_date(self, fingerprint, date_format=None):
        result = None
        self._fingerprint_is_valid(fingerprint)

        result = self.fingerprint_to_key_dict[fingerprint]['expires']

        if date_format:
            result = datetime.datetime.fromtimestamp(result).strftime(date_format)

        return result


    # Check if a fingerprint is valid and is in the key store and throw an
    #   appropriate exception if necessary.
    def _fingerprint_is_valid(self, fingerprint):
        if not(key_fingerprint_regex.match(fingerprint)):
            message = 'String %s is not a valid PGP fingerprint.' % fingerprint
            self.logger.error(message)
            raise FingerprintSyntaxException(message)

        elif not(fingerprint in self.fingerprint_to_key_dict.keys()):
            message = 'Key fingerprint %s not found in GPG key store.' % fingerprint
            self.logger.error(message)
            raise KeyNotFoundException(message)
