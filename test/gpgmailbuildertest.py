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
signing_key_fingerprint = '32C39D741B2D0F56A57F3BD5C98DBEA2DE6613E9'
signing_key_passphrase = 'lk\\4+v4*SL3r{vm^S(R";uP-l)nT+%)Ku;{0gS+"a5"1t;+6\'c]}TX4H)`c2'
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

    def setUp(self):
        self.loop_current_time = time.time()

    # Happy path test. We just don't want it to raise exceptions.
    def test_sign_message(self):
        signed_message = self.gpgmailbuilder.build_signed_message(message, signing_key_fingerprint,
            signing_key_passphrase, self.loop_current_time)
        # TODO: Eventually, consider verifying the signature here.

    def test_signing_failed(self):
        # should raise SignatureError
        pass

    def test_signing_key_untrusted(self):
        # should raise GpgKeyUntrustedException
        pass

    def test_signing_key_expired(self):
        # should raise GpgKeyExpiredException
        pass

    def test_encryption_failed(self):
        # just try to encrypt with expired or untrusted key
        # should raise EncryptionError
        pass

unittest.main()
