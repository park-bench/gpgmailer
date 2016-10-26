import logging
import time

class GpgKeyVerifier:
    def __init__(self, gpgkeyring, expiration_margin):
        self.logger = logging.getLogger()
        self.expiration_margin = expiration_margin
        self.gpgkeyring = gpgkeyring

    def filter_valid_keys(self, fingerprint_list):
        valid_keys = []

        check_date = time.time() + self.expiration_margin

        for fingerprint in fingerprint_list:
            if not(self.gpgkeyring.is_expired(fingerprint, check_date=check_date)):
                self.logger.error('Key with fingerprint %s is expired.' % fingerprint)

            else:
                if not(self.gpgkeyring.is_trusted(fingerprint)):
                    self.logger.error('Key with fingerprint %s is not trusted.' % fingerprint)

                else:
                    valid_keys.append(fingerprint)
            

    def build_key_expiration_message(self, expiration_warning_threshold, key_dict_list):
        expired_messages = []
        expiring_soon_messages = []

        for key_dict in key_dict_list:
            self.logger.debug('Checking if key <%s> (%s) with expiration date <%s> has expired.' \
                % (key_dict['fingerprint'], key_dict['email'], key_dict['expires']))
            if (self.gpgkeyring.is_expired(key_dict['fingerprint'])):
                message = 'Key <%s> (%s) is expired!' % (key.fingerprint, key.email)
                expired_messages.append(message)
                self.logger.warn(message)

            elif (key_dict['expires'] <= time.time() - expiration_warning_threshold):
                pretty_expiration_date = time.strftime('%Y-%m-%d %H:%M:%S', key_dict['expires'])
                message = 'Key <%s> (%s) will be expiring on date <%s>!' % \
                    (key_dict['fingerprint'], key_dict['email'], pretty_expiration_date)
                expiring_soon_messages.append(message)
                self.logger.warn(message)

        joined_expired_messages = '\n'.join(expired_messages)
        joined_expiring_soon_messages = '\n'.join(expiring_soon_messages)
        full_message = '%s\n%s\n' % (joined_expired_messages, joined_expiring_soon_messages)

        return full_message
