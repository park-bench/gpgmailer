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

class FingerprintSyntaxException(Exception):
    pass

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
        self.gpg = gnupg.GPG(gnupghome=gnupg_home)
        self.keys = {}

        for key in self.gpg.list_keys():
            
            # Key expiration dates are in Unix time. An expiration date of None
            #   means that the key does not expire.
            if key['expires'] == '':
                key['expires'] = None
            else:
                key['expires'] = int(key['expires'])

            self.keys[key['fingerprint']] = {
                'expires': key['expires'],
                'ownertrust': key['ownertrust'],
                'email': None,
                'fingerprint': key['fingerprint'],
                # TODO: Add _sent to the end of both of these keys.
                'expired_email': False,
                'expiring_soon_email': False
            }


    # TODO: Remove this method in favor of is_current.
    # Check if key fingerprint is expired at check_date and return True or False.
    def is_expired(self, fingerprint, check_date=time.time()):
        #   with the gnupg library, and is more work than we plan for at this time.
        expired = True

        if self._valid_fingerprint(fingerprint):
            self.logger.debug('Expiration: %s, check date: %s' % (self.keys[fingerprint]['expires'], check_date))
            if (self.keys[fingerprint]['expires'] == None) or (self.keys[fingerprint]['expires'] > check_date):
                expired = False

        self.logger.debug('Expired: %s' % expired)
        return expired

    # Check if a key with the given fingerprint is still valid after the given date.
    def is_current(self, fingerprint, expiration_date):
        current = False
        self._fingerprint_is_valid(fingerprint)

        self.logger.trace('Checking expiration for key %s at date %s.' % (fingerprint,
            self.keys[fingerprint]['expires']))

        if ((self.keys[fingerprint]['expires'] == None) or 
             (self.keys[fingerprint]['expires'] < expiration_date)):

            current = True

        else:
            self.logger.warn('Key %s expires before date %s.' % (fingerprint, expiration_date))

        return current

    # Check if a key with the given fingerprint is trusted.
    def is_trusted(self, fingerprint):
        trusted = False
        self._fingerprint_is_valid(fingerprint)

        if self.keys[fingerprint]['ownertrust'] in valid_owner_trust_levels:
            trusted = True

        else:
            self.logger.warn('Key %s is not trusted' % fingerprint)

        return trusted

    # TODO: Fix the comment. Explain when it can return None.
    # TODO: Rename to get_key_expiration_date.
    # Returns the key's expiration date in Unix time.
    def get_key_data(self, fingerprint):
        # TODO: Check if fingerprint is in key store, return none if not.
        # TODO: Check if fingerprint is a valid fingerprint, throw an exception if it isn't.
        result = None

        if self._valid_fingerprint(fingerprint):
            if fingerprint in self.keys.keys():
                # TODO: deepcopy the result.
                result = self.keys[fingerprint]

        return result

    # Looks up a key fingerprint and returns the expiration date if it exists,
    #   returns None if key is not found.
    def get_key_expiration_date(self, fingerprint):
        result = None

        if not(fingerprint in self.keys.keys()):
            self.logger.warn('Key with fingerprint %s not found in key store.' % fingerprint)

        elif not(key_fingerprint_regex.match(fingerprint)):
            self.logger.error('String %s is not a valid PGP fingerprint.' % fingerprint)
            raise FingerprintSyntaxException("String %s is not a valid PGP fingerprint." % fingerprint)

        else:
            result = self.keys[fingerprint]['expires']

        return result

    # TODO: Move this method's functionality to gpgkeyverifier.
    # Sets the passed email address for the given key.
    def set_key_email(self, fingerprint, email):
        success = False
        if self._valid_fingerprint(fingerprint):
            self.keys[fingerprint]['email'] = email
            success = True

        return success

    # TODO: Remove this method in favor of _fingerprint_is_valid
    # Checks the formatting of a fingerprint string and looks for it in the keyring.
    def _valid_fingerprint(self, fingerprint):
        valid = False

        if not(key_fingerprint_regex.match(fingerprint)):
            self.logger.error('Key fingerprint %s is not a valid PGP fingerprint.' % fingerprint)
        
        elif not(fingerprint in self.keys.keys()):
            self.logger.error('Key fingerprint %s not found in GPG key store.' % fingerprint)

        else:
            self.logger.trace('Key fingerprint %s is good.' % fingerprint)
            valid = True

        return valid

    # Check if a fingerprint is valid and is in the key store and throw an
    #   appropriate exception if necessary.
    def _fingerprint_is_valid(self, fingerprint):
        if not(key_fingerprint_regex.match(fingerprint)):
            self.logger.error('String %s is not a valid PGP fingerprint.' % fingerprint)
            raise FingerprintSyntaxException("String %s is not a valid PGP fingerprint." % fingerprint)

        elif not(fingerprint in self.keys.keys()):
            self.logger.error('Key fingerprint %s not found in GPG key store.' % fingerprint)
            raise KeyNotFoundException('Key fingerprint %s not found in GPG key store.' % fingerprint)
