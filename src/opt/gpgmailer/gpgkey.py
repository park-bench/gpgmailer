#!/usr/bin/env python2

import gnupg
import re
import timber
import time

key_fingerprint_regex = re.compile('^[0-9a-fA-F]{40}$')

class GpgKey:
    def __init__(self, key_list, key_config_string, password=''):
        # key_list should be a dict of fingerprints with associated expiration dates.
        # Verifies fingerprint and populates key data
        self.logger = timber.get_instance()
        self.key_list = key_list
        self.valid = False
        self.password = password

        key_config_list = key_config_string.split(':')
        email = key_config_list[0].strip()
        key_fingerprint = key_config_list[1].strip()
        self.email = email

        if key_fingerprint_regex.match(key_fingerprint):
            if key_fingerprint in key_list:
                self.fingerprint = key_fingerprint
                self.expires = key_list[key_fingerprint]
                if not(self.is_expired() == 'expired'):
                    self.valid = True
            else:
                # TODO: Decide the right way to handle invalid keys here.
                self.logger.error('Key fingerprint %s not found in list.' % key_fingerprint)

        else:
            # TODO: Decide the right way to handle invalid keys here.
            self.logger.error('Key fingerprint %s is invalid.' % key_fingerprint)

    # Checks the expiration against the current date and returns a status
    #   of either 'good', 'expired', or 'expiring_soon'.
    def is_expired(self, expiration_threshhold=0):
        self.logger.info('Checking key expiration for key %s.' % self.fingerprint)
        key_expiration_state = 'expired'

        if self.expires == '':
            self.logger.trace('Key does not expire.')
            key_expiration_state = 'good'

        else:
            current_time = time.mktime(time.gmtime())
            time_delta = float(self.expires) - current_time

            if time_delta <= 0:
                self.logger.warn('Key %s is expired.' % self.fingerprint)
                self.valid = False

            elif time_delta <= expiration_threshhold:
                key_expiration_state = 'expiring_soon'

            else:
                key_expiration_state = 'good'

        return key_expiration_state
