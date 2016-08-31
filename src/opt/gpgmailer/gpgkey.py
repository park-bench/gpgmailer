#!/usr/bin/env python2

import gnupg
import re
import timber
import time

key_fingerprint_regex = re.compile('^[0-9a-fA-F]{40}$')
valid_owner_trust_levels = ['u', 'f', 'm']

key_state_expired = 'expired'
key_state_expiring_soon = 'expiring_soon'
key_state_good = 'good'

# Builds a dict of key fingerprints that contains any needed key data, which
#   for now is just expiration date and owner trust. It is not included in the
#   GpgKey class because building a new dict for every class is rather ridiculous.
def build_key_hash_dict(gnupg_keylist):
    key_list = {}
    for key in gnupg_keylist:
        key_list[key['fingerprint']] = {
            'expires': key['expires'],
            'ownertrust': key['ownertrust']
        }

    return key_list

# Verifies fingerprint and populates key data. key_list should be a dict 
#   generated by build_key_dict_hash, and key_config_string should be in the
#   format described in the config file example.
class GpgKey:
    def __init__(self, key_list, key_config_string, expiration_warning_threshold, password=''):
        self.logger = timber.get_instance()
        self.key_list = key_list
        self.valid = False
        self.password = password
        self.expiration_warning_threshold = expiration_warning_threshold

        key_config_list = key_config_string.split(':')
        email = key_config_list[0].strip()
        key_fingerprint = key_config_list[1].strip()
        self.email = email

        if not(key_fingerprint_regex.match(key_fingerprint)):
            self.logger.error('Key fingerprint %s is not a valid PGP fingerprint.' % key_fingerprint)

        else:
            if not(key_fingerprint in key_list):
                self.logger.error('Key fingerprint %s not found in GPG key store.' % key_fingerprint)

            else:
                self.fingerprint = key_fingerprint
                self.expires = key_list[key_fingerprint]['expires']
                self.ownertrust = key_list[key_fingerprint]['ownertrust']
                if not(self.ownertrust in valid_owner_trust_levels) or (self.get_key_expiration_status() == 'expired'):
                    self.logger.error('Key %s is either expired or not trusted.' % key_fingerprint)

                else:
                    self.valid = True

    # Checks the expiration against the current date and returns a status
    #   of either 'good', 'expired', or 'expiring_soon'.
    def get_key_expiration_status(self):
        self.logger.info('Checking key expiration for key %s.' % self.fingerprint)
        key_expiration_state = key_state_expired

        if self.expires == '':
            self.logger.debug('Key does not expire.')
            key_expiration_state = key_state_good

        else:
            current_time = time.mktime(time.gmtime())
            time_delta = float(self.expires) - current_time

            if time_delta <= 0:
                self.logger.warn('Key %s is expired.' % self.fingerprint)
                self.valid = False

            elif time_delta <= self.expiration_warning_threshold:
                self.logger.warn('Key %s is expiring soon.' % self.fingerprint)
                key_expiration_state = key_state_expiring_soon

            else:
                key_expiration_state = key_state_good

        return key_expiration_state
