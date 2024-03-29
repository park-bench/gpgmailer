# Copyright 2015-2021 Joel Allen Luellwitz and Emily Frost
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

__all__ = [
    'SignatureError', 'EncryptionError', 'GpgKeyExpiredException',
    'GpgKeyNotTrustedException', 'GpgKeyNotSignedException', 'GpgKeyNotValidatedException',
    'GpgMailBuilder']
__author__ = 'Joel Luellwitz and Emily Frost'
__version__ = '0.8'

import base64
from email.encoders import encode_7or8bit
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import gnupg


class SignatureError(Exception):
    """Raised when something goes wrong with a GnuPG signature."""


class EncryptionError(Exception):
    """Raised when something goes wrong with GnuPG encryption."""


class GpgKeyExpiredException(Exception):
    """Raised when attempting to use an expired key."""


class GpgKeyNotTrustedException(Exception):
    """Raised when attempting to use a sender untrusted key."""


class GpgKeyNotSignedException(Exception):
    """Raised when attempting to use a sender unsigned key."""


class GpgKeyNotValidatedException(Exception):
    """Raised when attempting to use a recipient untrusted or unsigned key."""


class GpgMailBuilder():
    """Builds, signs, and encrypts PGP/MIME emails with attachments.

    All public methods have a message_dict parameter which has the following format:
      message_dict
      +- subject: The plain-text message subject.
      +- body: The plain-text message body.
      +- attachments: An array of dictionaries.
         +- Array[n]
            +- filename: The filename of the attachment.
            +- data: The binary data of the attachment.
    """

    def __init__(self, gpg_keyring, max_operation_time):
        """Constructor.

        gpg_keyring: A GpgKeyring object.
        max_operation_time: The maximum time that building a message is expected to take.
          Used for 'last minute' key expiration checks that occur immediately prior to
          message construction.
        """
        self.logger = logging.getLogger('GpgMailBuilder')
        self.gpgkeyring = gpg_keyring
        self.gpg = gnupg.GPG(gnupghome=self.gpgkeyring.gnupg_home)
        self.max_operation_time = max_operation_time

        # These are constants that gnupg uses to represent different hash
        #   algorithms, which are part of the SIG_CREATED line in the output
        #   of the gnupg library we use.
        self.hash_algorithm_table = {
            '1': 'md5',
            '2': 'sha1',
            '3': 'rmd160',
            # 4-7 are reserved
            '8': 'sha256',
            '9': 'sha384',
            '10': 'sha512',
            '11': 'sha224'}

    def build_encrypted_message(self, message_dict, encryption_keys, loop_current_time):
        """Builds and returns an unsigned encrypted MIME message.

        message_dict: A dictionary containing the body, subject, and any attachments of the
          message. See class documentation for a description of the message_dict format.
        encryption_keys: A list of GPG key fingerprints to encrypt to.
        loop_current_time: The Unix time associated with the main program loop from which all
          PGP key expiration checks are based.
        """
        plain_message = self._build_plaintext_message_with_attachments(message_dict)
        encrypted_message = self._encrypt_message(
            message=plain_message, encryption_keys=encryption_keys,
            loop_current_time=loop_current_time)
        encrypted_message['Subject'] = message_dict['subject']

        return encrypted_message

    def build_signed_message(self, message_dict, signing_key_fingerprint,
                             signing_key_passphrase, loop_current_time):
        """Builds and returns a signed unencrypted MIME message.

        message_dict: A dictionary containing the body, subject, and any attachments of the
          message. See class documentation for a description of the message_dict format.
        signing_key_fingerprint: The fingerprint of the GPG key to sign with.
        signing_key_passphrase: The passphrase for the previously mentioned GPG key.
        loop_current_time: The Unix time associated with the main program loop from which all
          PGP key expiration checks are based.
        """
        plain_message = self._build_plaintext_message_with_attachments(message_dict)
        signed_message = self._sign_message(
            message=plain_message, signing_key_fingerprint=signing_key_fingerprint,
            signing_key_passphrase=signing_key_passphrase,
            loop_current_time=loop_current_time)
        signed_message['Subject'] = message_dict['subject']

        return signed_message

    def build_signed_encrypted_message(
            self, message_dict, encryption_keys, signing_key_fingerprint,
            signing_key_passphrase, loop_current_time):
        """Builds and returns a signed and encrypted MIME message.

        message_dict: A dictionary containing the body, subject, and any attachments of the
          message. See class documentation for a description of the message_dict format.
        encryption_keys: A list of GPG key fingerprints to encrypt to.
        signing_key_fingerprint: The fingerprint of the GPG key to sign with.
        signing_key_passphrase: The passphrase for the previously mentioned GPG key.
        loop_current_time: The Unix time associated with the main program loop from which
          all PGP key expiration checks are based.
        """
        plain_message = self._build_plaintext_message_with_attachments(message_dict)
        signed_message = self._sign_message(
            message=plain_message, loop_current_time=loop_current_time,
            signing_key_fingerprint=signing_key_fingerprint,
            signing_key_passphrase=signing_key_passphrase)

        encrypted_message = self._encrypt_message(
            message=signed_message, encryption_keys=encryption_keys,
            loop_current_time=loop_current_time)
        encrypted_message['Subject'] = message_dict['subject']

        return encrypted_message

    def _sign_message(self, message, signing_key_fingerprint, signing_key_passphrase,
                      loop_current_time):
        """Builds and returns a signed MIME message on the given MIME message part.

        message: A MIME message object to sign.
        signing_key_fingerprint: The fingerprint of the GPG key to sign with.
        signing_key_passphrase: The passphrase for the previously mentioned GPG key.
        loop_current_time: The Unix time associated with the main program loop from which
          all PGP key expiration checks are based.
        """
        self._validate_signing_key(signing_key_fingerprint, loop_current_time)

        # Replaces LF with CR/LF.
        message_string = str(message).replace('\n', '\r\n')

        # Make the signature component.
        signature_result = self.gpg.sign(
            message_string, detach=True, keyid=signing_key_fingerprint,
            passphrase=signing_key_passphrase)
        signature_text = str(signature_result)

        # The GnuPG library we use does not provide any granular error information
        #   or throw any exceptions for signature operations, so checking for an
        #   empty string is all we have.
        if signature_text.strip() == '':
            # TODO: Eventually, use signature_text.stderr for more granular error handling.
            #   (issue 7)
            raise SignatureError('Error while signing message.')

        signature_hash_algorithm = self.hash_algorithm_table[signature_result.hash_algo]

        self.logger.debug('Used hash algorithm %s.', signature_hash_algorithm)

        signature_part = MIMEApplication(
            _data=signature_text, _subtype='pgp-signature; name="signature.asc"',
            _encoder=encode_7or8bit)
        signature_part['Content-Description'] = 'OpenPGP Digital Signature'
        signature_part.set_charset('us-ascii')

        # Make a MIME box to put the message and signature in.
        signed_message = MIMEMultipart(
            _subtype='signed', micalg='pgp-%s' % signature_hash_algorithm,
            protocol='application/pgp-signature')
        signed_message.attach(message)
        signed_message.attach(signature_part)

        return signed_message

    def _encrypt_message(self, message, encryption_keys, loop_current_time):
        """Encrypts a MIME message object.

        message: A MIME message object to encrypt.
        encryption_keys: A list of GPG key fingerprints to encrypt to.
        loop_current_time: The Unix time associated with the main program loop from which
          all PGP key expiration checks are based.
        """
        for fingerprint in encryption_keys:
            self._validate_encryption_key(fingerprint, loop_current_time)

        # PGP needs a version attachment.
        pgp_version = MIMEApplication('', _subtype='pgp-encrypted', _encoder=encode_7or8bit)
        pgp_version['Content-Description'] = 'PGP/MIME version identification'
        pgp_version.set_payload('Version: 1\n')

        # Encrypt the message.
        encrypted_payload = self.gpg.encrypt(
            data=str(message), recipients=encryption_keys, always_trust=True)
        encrypted_payload_string = str(encrypted_payload)

        # This 'ok' variable is not as granular as we would like it to be.
        #   The GnuPG library does not provide more information.
        if encrypted_payload.ok is False:
            raise EncryptionError('Error from python-gnupg while encrypting message: %s.' %
                                  encrypted_payload.status)

        encrypted_part = MIMEApplication("", _encoder=encode_7or8bit)
        encrypted_part.set_payload(encrypted_payload_string)

        # Pack it all into one big message.
        encrypted_message = MIMEMultipart(_subtype='encrypted',
                                          protocol='application/pgp-encrypted')
        encrypted_message.attach(pgp_version)
        encrypted_message.attach(encrypted_part)

        return encrypted_message

    def _build_plaintext_message_with_attachments(self, message_dict):
        """Builds the initial plain-text multipart MIME message to be signed and/or
        encrypted.

        message_dict: A dictionary containing the body, subject, and any attachments of the
          message. See class documentation for a description of the message_dict format.
        """
        multipart_message = MIMEMultipart(_subtype='mixed')
        multipart_message.attach(MIMEText(message_dict['body']))

        # Loop over the attachments.
        if 'attachments' in message_dict.keys():
            for attachment in message_dict['attachments']:
                attachment_part = MIMEBase('application', 'octet-stream')
                attachment_part.set_payload(base64.b64encode(attachment['data']))
                attachment_part.add_header('Content-Transfer-Encoding', 'base64')
                attachment_part.add_header('Content-Disposition', 'attachment',
                                           filename=attachment['filename'])
                multipart_message.attach(attachment_part)

        return multipart_message

    def _validate_encryption_key(self, fingerprint, loop_current_time):
        """ Checks if the given fingerprint is expired or untrusted and throws an
        appropriate exception in either case. Never returns anything.

        fingerprint: The fingerprint of the key to be checked.
        loop_current_time: The Unix time associated with the main program loop from which
          all PGP key expiration checks are based.
        """

        if not self.gpgkeyring.is_current(fingerprint, loop_current_time +
                                          self.max_operation_time):
            raise GpgKeyExpiredException('Key %s is expired.' % fingerprint)

    def _validate_signing_key(self, fingerprint, loop_current_time):
        """Checks if the given signing key fingerprint is expired, unsigned or untrusted and
        throws an appropriate exception in either case. Never returns anything.

        fingerprint: The fingerprint of the key to be checked.
        loop_current_time: The Unix time associated with the main program loop from which
          all PGP key expiration checks are based.
        """

        if not self.gpgkeyring.is_trusted(fingerprint):
            raise GpgKeyNotTrustedException('Signing key is not trusted.')
        elif not self.gpgkeyring.is_signed(fingerprint):
            raise GpgKeyNotSignedException('Signing key is not signed.')
        elif not self.gpgkeyring.is_current(fingerprint, loop_current_time +
                                            self.max_operation_time):
            raise GpgKeyExpiredException('Signing key is expired.')
