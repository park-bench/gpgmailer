import gnupg
import logging
import re
import time

key_fingerprint_regex = re.compile('^[0-9a-fA-F]{40}$')
valid_owner_trust_levels = ('u', 'f', 'm')

class GpgKeyRing:
    def __init__(self, gnupg_home):
        self.logger = logging.getLogger()
        self.gpg = gnupg.GPG(gnupghome=gnupg_home)
        self.keys = {}

        for key in self.gpg.list_keys():
            self.keys[key['fingerprint']] = { 'expires': key['expires'],
                'ownertrust': key['ownertrust']
            }


    # Check if key fingerprint is expired at date and return a boolean.
    def is_expired(self, fingerprint, check_date=time.time()):
        expired = True

        if self._valid_fingerprint(fingerprint):
            if self.keys[fingerprint]['expires'] > check_date:
                expired = False

        return expired

    # Check if key fingerprint is trusted and return a boolean.
    def is_trusted(self, fingerprint):
        trusted = False

        if self._valid_fingerprint(fingerprint):
            if self.keys[fingerprint]['ownertrust'] in valid_owner_trust_levels:
                trusted = True

        return trusted

    def _valid_fingerprint(self, fingerprint):
        valid = False

        if not(key_fingerprint_regex.match(fingerprint)):
            self.logger.error('Key fingerprint %s is not a valid PGP fingerprint.' % fingerprint)
        
        elif not(fingerprint in self.keys.keys()):
            self.logger.error('Key fingerprint %s not found in GPG key store.' % fingerprint)

        else:
            self.logger.debug('Key fingerprint is good')
            valid = True

        return valid
