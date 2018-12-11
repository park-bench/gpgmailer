#!/usr/bin/env python2
# Copyright 2015-2018 Joel Allen Luellwitz and Emily Frost
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

__author__ = 'Joel Luellwitz and Emily Frost'
__version__ = '0.8'

import logging
import unittest
from parkbenchcommon import confighelper
import gpgkeyring
import gpgmailbuilder

# A few constants for testing.
log_file = "/dev/null"
log_level = "TRACE"
max_operation_time = 1
# TODO #42: Eventually redo key descriptions in keyring.
valid_signing_key_fingerprint = '32C39D741B2D0F56A57F3BD5C98DBEA2DE6613E9'
untrusted_signing_key_fingerprint = '580F6E7B9360235DD4227A21CE428A67F602976B'
unsigned_signing_key_fingerprint = 'B616361BA4F970857685C9076D061968AA33DD93'
expired_signing_key_fingerprint = 'A0D0781A34CDAC9ACCB5EEDB12FE6BD0CD7C2E0A'
expired_signing_subkey_key_fingerprint = '649F4097572E27FA57311FFED76BC35AA00A4047'
valid_encryption_key_fingerprint = 'DC15C702C00A857CD2A3A638067DD2B687ABB7BE'
unvalidated_encryption_key_fingerprint = '1DAFD4848F577404645B6BD0DCF9BC791CA5FD51'
expired_encryption_key_fingerprint = '4C3CFF38398060C8E1EFA78CD4199708797520DC'
expired_encryption_subkey_key_fingerprint = '56E3B2498A859953EF003FD8FC88955B8E4B0DF0'
# All three keys use the same passphrase
signing_key_correct_passphrase = \
    'lk\\4+v4*SL3r{vm^S(R";uP-l)nT+%)Ku;{0gS+"a5"1t;+6\'c]}TX4H)`c2'
signing_key_wrong_passphrase = 'php is a great language'
test_keyring_directory = './gpgmailbuilder-test-keyring'

message = {
        'subject': 'This won\'t be seen.',
        'body': 'Ever. By anyone.'
    }


class gpgmailbuildertest(unittest.TestCase):

    def setUp(self):
        # Load the keyring
        # Initialize gpgmailbuilder

        config_helper = confighelper.ConfigHelper()
        config_helper.configure_logger(log_file, log_level)
        self.logger = logging.getLogger(__name__)
        self.gpgkeyring = gpgkeyring.GpgKeyRing(test_keyring_directory)
        self.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(self.gpgkeyring,
                                                            max_operation_time)

        self.test_time = 1508460447  # 2017-10-20T00:47:27Z

        self.logger.info('Test class setup complete.')

    def test_sign_message_succeeds(self):
        self.logger.info('Testing signature with valid key.')
        signed_message = self.gpgmailbuilder.build_signed_message(
            message, valid_signing_key_fingerprint, signing_key_correct_passphrase,
            self.test_time)
        # Make sure the signed_message is not empty.
        self.assertTrue(signed_message)
        # TODO: Eventually, consider verifying the signature here. (issue 43)

    def test_encrypt_message_succeeds(self):
        self.logger.info('Testing encryption with valid key.')
        encrypted_message = self.gpgmailbuilder.build_encrypted_message(
            message, [valid_encryption_key_fingerprint], self.test_time)
        # Make sure the encrypted_message is not empty.
        self.assertTrue(encrypted_message)
        # TODO: Eventually, consider verifying the signature here. (issue 43)

    def test_signed_encrypted_message_succeeds(self):
        self.logger.info('Testing signed encrypted message with valid key.')
        signed_encrypted_message = self.gpgmailbuilder.build_signed_encrypted_message(
            message, [valid_encryption_key_fingerprint], valid_signing_key_fingerprint,
            signing_key_correct_passphrase, self.test_time)
        # Make sure the signed_encrypted_message is not empty.
        self.assertTrue(signed_encrypted_message)
        # TODO: Eventually, consider verifying the signature here. (issue 43)

    # Wrong passwords are not specifically handled, so this should raise the general
    #   SignatureError exception.
    def test_signing_bad_password(self):
        self.logger.info('Testing signature with bad password.')
        # should raise SignatureError
        with self.assertRaises(gpgmailbuilder.SignatureError):
            self.gpgmailbuilder.build_signed_message(
                message, valid_signing_key_fingerprint,
                signing_key_wrong_passphrase, self.test_time)

    # Any untrusted signing keys should throw an exception
    def test_signing_key_untrusted(self):
        self.logger.info('Testing signature with untrusted signing key.')
        # should raise GpgKeyNotTrustedException
        with self.assertRaises(gpgmailbuilder.GpgKeyNotTrustedException):
            self.gpgmailbuilder.build_signed_message(
                message, untrusted_signing_key_fingerprint, signing_key_correct_passphrase,
                self.test_time)

    # Any unsigned signing keys should throw an exception
    def test_signing_key_unsigned(self):
        self.logger.info('Testing signature with unsigned signing key.')
        # should raise GpgKeyNotSignedException
        with self.assertRaises(gpgmailbuilder.GpgKeyNotSignedException):
            self.gpgmailbuilder.build_signed_message(message,
                unsigned_signing_key_fingerprint, signing_key_correct_passphrase,
                self.test_time)

    # Any untrusted and unsigned recipient keys should throw an exception
    def test_recipient_key_unsigned_and_untrusted(self):
        self.logger.info('Testing encryption with untrusted and unsigned encryption key.')
        # should raise GpgKeyNotValidatedException
        with self.assertRaises(gpgmailbuilder.GpgKeyNotValidatedException):
            self.gpgmailbuilder.build_encrypted_message(
                message, [unvalidated_encryption_key_fingerprint], self.test_time)

    def test_signing_key_expired(self):
        # should raise GpgKeyExpiredException
        self.logger.info('Testing signature with expired signing key.')
        # Due to an error (mostly with python-pgp), it is nearly impossible to create a
        #   test key that is registered in memory as both expired and signed. To get around
        #   this limitation, just modify the internal gpgkeyring structure.
        self.gpgkeyring.fingerprint_to_key_dict[expired_signing_key_fingerprint]['signed'] = True
        with self.assertRaises(gpgmailbuilder.GpgKeyExpiredException):
            self.gpgmailbuilder.build_signed_message(
                message, expired_signing_key_fingerprint, signing_key_correct_passphrase,
                self.test_time)

    def test_encryption_failed_due_to_expired_key(self):
        # should raise GpgKeyExpiredException
        self.logger.info('Testing encryption with expired encryption key.')
        with self.assertRaises(gpgmailbuilder.GpgKeyExpiredException):
            self.gpgmailbuilder.build_encrypted_message(
                message, [expired_encryption_key_fingerprint], self.test_time)

    # Subkeys are not specifically handled, so this should raise the general SignatureError.
    def test_signing_failed_due_to_expired_subkey(self):
        self.logger.info('Testing signing with expired subkey.')
        # TODO: Eventually we should fix this to throw a GpgKeyExpirationError. (issue 41)
        with self.assertRaises(gpgmailbuilder.GpgKeyNotSignedException):
            self.gpgmailbuilder.build_signed_message(
                message, expired_signing_subkey_key_fingerprint,
                signing_key_correct_passphrase, self.test_time)

    # Subkeys are not specifically handled, so this should raise the general
    #   EncryptionError.
    def test_encryption_failed_due_to_expired_subkey(self):
        self.logger.info('Testing encryption with expired subkey.')
        # TODO: Eventually we should fix this to throw a GpgKeyExpirationError. (issue 41)
        with self.assertRaises(gpgmailbuilder.EncryptionError):
            self.gpgmailbuilder.build_encrypted_message(
                message, [expired_encryption_subkey_key_fingerprint],
                1483228800)  # 2017-01-01T00:00:00Z

unittest.main()
