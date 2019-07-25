# Copyright 2015-2019 Joel Allen Luellwitz and Emily Frost
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

__all__ = ['FingerprintSyntaxException', 'KeyNotFoundException', 'GpgKeyRing']
__author__ = 'Joel Luellwitz and Emily Frost'
__version__ = '0.8'

import logging
import re
import time
import gnupg

KEY_FINGERPRINT_REGEX = re.compile('^[0-9a-fA-F]{40}$')
# This trust level comes from GnuPG. 'u' means ultimate.
VALID_OWNER_TRUST_LEVELS = ('u')


class FingerprintSyntaxException(Exception):
    """This exception is raised when a GPG fingerprint is not a 40-character hexadecimal
    string.
    """


class KeyNotFoundException(Exception):
    """This exception is thrown when a GPG fingerprint is not in the given key ring."""


class GpgKeyRing():
    """GpgKeyRing caches and checks validity, expiration, and trust for GPG keys."""

    def __init__(self, gnupg_home):
        """Loads select portions of the GnuPG keyring and stores the information in an
        internal dict.

        gnupg_home: The GnuPG keyring directory.
        """
        self.logger = logging.getLogger('GpgKeyRing')
        self.gnupg_home = gnupg_home
        self.gpg = gnupg.GPG(gnupghome=self.gnupg_home)
        self.fingerprint_to_key_dict = {}

        for key in self.gpg.list_keys():

            # Key expiration dates are in Unix time. An expiration date of None
            #   means that the key does not expire.
            # TODO: Eventually, change key expiration date to a date object instead of an
            #   int. (issue 37)
            expires = None
            if key['expires'] != '':
                expires = int(key['expires'])

            signed = self._is_key_signed(key)

            self.fingerprint_to_key_dict[key['fingerprint']] = {
                'expires': expires,
                'fingerprint': key['fingerprint'],
                'ownertrust': key['ownertrust'],
                'signed': signed
            }

    def is_current(self, fingerprint, expiration_date):
        """Checks if the GPG key with the given fingerprint expires after the given date.

        fingerprint: The fingerprint of the GPG key to check for expiration.
        expiration_date: The date (in Unix time) to compare against the GPG key's expiration
          date.
        """
        current = False
        self._fingerprint_is_valid(fingerprint)

        self.logger.trace('Checking expiration for GPG key %s at date %s.', fingerprint,
                          expiration_date)

        if (self.fingerprint_to_key_dict[fingerprint]['expires'] is None or
                self.fingerprint_to_key_dict[fingerprint]['expires'] > expiration_date):

            current = True
            self.logger.trace('Key %s is current.', fingerprint)

        else:
            self.logger.trace(
                'Key %s expired after date %s.', fingerprint, expiration_date)

        return current

    def is_signed(self, fingerprint):
        """Checks if a GPG key with the given fingerprint is signed.

        fingerprint: The fingerprint of the GPG key to check.
        """
        self._fingerprint_is_valid(fingerprint)

        return self.fingerprint_to_key_dict[fingerprint]['signed']

    def is_trusted(self, fingerprint):
        """Checks if a GPG key with the given fingerprint is trusted.

        fingerprint: The fingerprint of the GPG key to check.
        """
        trusted = False
        self._fingerprint_is_valid(fingerprint)

        if self.fingerprint_to_key_dict[
                fingerprint]['ownertrust'] in VALID_OWNER_TRUST_LEVELS:
            trusted = True

        else:
            self.logger.trace('Key %s is not trusted.', fingerprint)

        return trusted

    def get_key_expiration_date(self, fingerprint):
        """Returns a GPG key expiration date based on a key fingerprint. If the key
        fingerprint is invalid or does not exist in the keyring, an exception is thrown.

        fingerprint: A GPG key fingerprint.
        Returns the key's expiration date or None if no expiration date exist.
        """
        self._fingerprint_is_valid(fingerprint)

        return self.fingerprint_to_key_dict[fingerprint]['expires']

    def _is_key_signed(self, gpg_key):
        """Determines if a 'key' dictionary from the gnupg libary is signed. The method is
        intended to be called only during instantiation.

        key: A 'key' from the gnupg library.
        Returns true if the key is signed (or if we cannot determine if the key is signed).
          False otherwise. (We currently have no 100% reliable way to determine if a key is
          signed. However, with later versions of the gnupg library, we will eventually be
          able to determine this accurately.
        """
        signed = True

        # We assume the key is signed if the key is expired since we have no way of knowing
        #   if it is really signed or not.
        if gpg_key['expires'] == '' or float(gpg_key['expires']) > time.time():

            # Try to encrypt a test string. The key is considered signed if we encrypt
            #   successfully.
            encrypted_payload = self.gpg.encrypt(data='Test string.',
                                                 recipients=[gpg_key['fingerprint']])

            # The key probably isn't signed if the string did not encrypt.
            if encrypted_payload.ok is False:

                # Theoretically the key could have expired since our last expiration check.
                #   (Immediately before encrypting.) If so, assume the encryption failed
                #   because the key expired. (Skip setting signed to false.)
                if gpg_key['expires'] == '' or float(gpg_key['expires']) > time.time():
                    signed = False

        return signed

    # Checks if a GPG key fingerprint is valid and is in the keyring. If the key is not valid
    #   or does not exist in the keyring, an exception is thrown.
    #
    # fingerprint: The fingerprint of the GPG key to check.
    def _fingerprint_is_valid(self, fingerprint):

        if not KEY_FINGERPRINT_REGEX.match(fingerprint):
            message = 'String %s is not a valid PGP fingerprint.' % fingerprint
            self.logger.error(message)
            raise FingerprintSyntaxException(message)

        elif fingerprint not in self.fingerprint_to_key_dict.keys():
            message = 'Key fingerprint %s not found in GPG key store.' % fingerprint
            self.logger.error(message)
            raise KeyNotFoundException(message)
