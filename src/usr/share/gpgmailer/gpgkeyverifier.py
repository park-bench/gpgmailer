import datetime
import gpgmailmessage
import logging
import time

class GpgKeyVerifier:
    def __init__(self, gpgkeyring, expiration_margin, config):
        self.logger = logging.getLogger('GpgKeyVerifier')
        self.expiration_margin = expiration_margin
        self.gpgkeyring = gpgkeyring
        self.config = config

    def filter_valid_keys(self, fingerprint_list):
        self.logger.info('Filtering keys in list')
        valid_keys = []

        check_date = time.time() + self.expiration_margin

        for fingerprint in fingerprint_list:
            if self.gpgkeyring.is_expired(fingerprint, check_date=check_date):
                self.logger.error('Key with fingerprint %s is expired and will not be used.' % fingerprint)

            else:
                if not(self.gpgkeyring.is_trusted(fingerprint)):
                    self.logger.error('Key with fingerprint %s is not trusted and will not be used.' % fingerprint)

                else:
                    self.logger.trace('Key with fingerprint %s is valid and will be used.' % fingerprint)
                    valid_keys.append(fingerprint)

        return valid_keys

    def build_key_expiration_message(self, expiration_warning_threshold, key_fingerprint_list):
        # TODO: handle initial notifications specially
        #   - no 'key added' text

        self.logger.info('Building key expiration message.')
        expired_messages = []
        expiring_soon_messages = []

        key_dict_list = []

        for key_fingerprint in key_fingerprint_list:
            key_dict_list.append(self.gpgkeyring.get_key_data(key_fingerprint))

        added_messages = []

        for key_dict in key_dict_list:
            self.logger.debug('Checking if key <%s> (%s) with expiration date <%s> has expired.' \
                % (key_dict['fingerprint'], key_dict['email'], key_dict['expires']))

            if (self.gpgkeyring.is_expired(key_dict['fingerprint'])):
                if not(self.gpgkeyring.keys[key_dict['fingerprint']]['expired_email']):
                    added_messages.append('Added key %s to expiration message.' % key_dict['fingerprint'])
                    self.gpgkeyring.keys[key_dict['fingerprint']]['expired_email'] = True

                message = 'Key <%s> (%s) is expired!' % (key_dict['fingerprint'], key_dict['email'])
                expired_messages.append(message)
                self.logger.warn(message)

            elif self.gpgkeyring.is_expired(key_dict['fingerprint'], check_date = time.time() + expiration_warning_threshold):
                if not(self.gpgkeyring.keys[key_dict['fingerprint']]['expiring_soon_email']):
                    added_messages.append('Added key %s to expiration message.' % key_dict['fingerprint'])
                    self.gpgkeyring.keys[key_dict['fingerprint']]['expiring_soon_email'] = True

                pretty_expiration_date = datetime.datetime.fromtimestamp(key_dict['expires']).strftime('%Y-%m-%d %H:%M:%S')
                message = 'Key <%s> (%s) will be expiring on date <%s>!' % \
                    (key_dict['fingerprint'], key_dict['email'], pretty_expiration_date)
                expiring_soon_messages.append(message)
                self.logger.warn(message)

        added_message = '\n'.join(added_messages)

        self._queue_warning_email(added_messages)
        self.logger.info('Pretended to send digest message.')

        joined_expired_messages = '\n'.join(expired_messages)
        joined_expiring_soon_messages = '\n'.join(expiring_soon_messages)
        full_message = '%s\n%s\n' % (joined_expired_messages, joined_expiring_soon_messages)

        return full_message

    # This should queue a warning email for expired or soon to expire keys.
    def _queue_warning_email(self, message_body):
        if(message_body):
            self.logger.info('Sending key warning digest.')
            message = gpgmailmessage.GpgMailMessage()
            message.set_subject(self.config['default_subject'])
            message.set_body(message_body)
            message.queue_for_sending()
