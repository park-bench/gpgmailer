#!/usr/bin/env python2

import confighelper
import gnupg
import gpgkeyring
import gpgmailbuilder
import logging
import time
import unittest

# A few constants for testing.
log_file = "/dev/null"
log_level = "TRACE"
max_operation_time = 60
valid_signing_key_fingerprint = '32C39D741B2D0F56A57F3BD5C98DBEA2DE6613E9'
untrusted_signing_key_fingerprint = '580F6E7B9360235DD4227A21CE428A67F602976B'
expired_subkey_key_fingerprint = '3A227B3DA67B3EBB31DA16B117EE9CEDB09285D6'
expired_signing_key_fingerprint = 'A0D0781A34CDAC9ACCB5EEDB12FE6BD0CD7C2E0A'
# All three keys use the same passphrase
signing_key_correct_passphrase = 'lk\\4+v4*SL3r{vm^S(R";uP-l)nT+%)Ku;{0gS+"a5"1t;+6\'c]}TX4H)`c2'
signing_key_wrong_passphrase = 'php is a great language'
test_keyring_directory = './gpgmailbuilder-test-keyring'

message = {
        'subject': 'This won\'t be seen.',
        'body': 'Ever. By anyone.'
    }

class gpgmailbuildertest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Load the keyring
        # Initialize gpgmailbuilder

        config_helper = confighelper.ConfigHelper()
        config_helper.configure_logger(log_file, log_level)
        cls.logger = logging.getLogger(__name__)
        cls.gpgkeyring = gpgkeyring.GpgKeyRing(test_keyring_directory)
        cls.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(cls.gpgkeyring, max_operation_time)

        cls.logger.info('Test class setup complete.')

    def setUp(self):
        self.loop_current_time = time.time()

    # Happy path test. We just don't want it to raise exceptions.
    def test_sign_message(self):
        self.logger.info('Testing signature with valid key.')
        signed_message = self.gpgmailbuilder.build_signed_message(message, valid_signing_key_fingerprint,
            signing_key_correct_passphrase, self.loop_current_time)
        # TODO: Eventually, consider verifying the signature here.

    # Wrong passwords are not specifically handled, so this should raise the general
    #   SignatureError exception.
    def test_signing_bad_password(self):
        self.logger.info('Testing signature with bad password.')
        # should raise SignatureError
        with self.assertRaises(gpgmailbuilder.SignatureError):
            signed_message = self.gpgmailbuilder.build_signed_message(message, valid_signing_key_fingerprint,
                signing_key_wrong_passphrase, self.loop_current_time)

    # Any untrusted keys should throw an exception
    def test_signing_key_untrusted(self):
        self.logger.info('Testing signature with untrusted key.')
        # should raise GpgKeyUntrustedException
        with self.assertRaises(gpgmailbuilder.GpgKeyUntrustedException):
            signed_message = self.gpgmailbuilder.build_signed_message(message, untrusted_signing_key_fingerprint,
                signing_key_correct_passphrase, self.loop_current_time)

    def test_signing_key_expired(self):
        # should raise GpgKeyExpiredException
        self.logger.info('Testing signature with expired key.')
        with self.assertRaises(gpgmailbuilder.GpgKeyExpiredException):
            signed_message = self.gpgmailbuilder.build_signed_message(message, expired_signing_key_fingerprint,
                signing_key_correct_passphrase, self.loop_current_time)

    # Subkeys are not specifically handled, so this should raise the general EncryptionError.
    def test_encryption_failed(self):
        self.logger.info('Testing general encryption failure exception.')
        with self.assertRaises(gpgmailbuilder.EncryptionError):
            encrypted_message = self.gpgmailbuilder.build_encrypted_message(message, [expired_subkey_key_fingerprint],
                self.loop_current_time)

unittest.main()
