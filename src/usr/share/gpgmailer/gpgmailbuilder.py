# Copyright 2015-2016 Joel Allen Luellwitz and Andrew Klapp
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

import base64
from email.Encoders import encode_7or8bit
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import gnupg
import logging
import time

# Raised when something goes wrong with a GnuPG signature.
class SignatureError(Exception):
    pass

# Raised when something goes wrong with GnuPG encryption.
class EncryptionError(Exception):
    pass

# Raised when attempting to use an expired key.
class GpgKeyExpiredException(Exception):
    pass

# Raised when attempting to use an untrusted key.
class GpgKeyUntrustedException(Exception):
    pass

# Builds, signs, and encrypts PGP/MIME emails with attachments.
class GpgMailBuilder:
    # TODO: Explain init's parameters.
    # TODO: Pass in a keyring instead of making a second one.
    def __init__(self, gpg_keyring, max_operation_time):
        self.logger = logging.getLogger('GpgMailBuilder')
        self.gpgkeyring = gpg_keyring
        self.gpg = gnupg.GPG(gnupghome=self.gpgkeyring.gnupg_home)
        self.max_operation_time = max_operation_time


    # TODO: Method comment.
    def build_encrypted_message(self, expiration_check_time, message_dict, encryption_keys):

        plain_message = self._build_plaintext_message(message_dict)
        encrypted_message = self._encrypt_message(message=plain_message, 
            expiration_check_time=expiration_check_time, encryption_keys=encryption_keys)
        encrypted_message['Subject'] = message_dict['subject']

        return str(encrypted_message)


    # TODO: Method comment.
    def build_signed_message(self, expiration_check_time, message_dict, signing_key, singing_key_passphrase):

        plain_message = self._build_plaintext_message(message_dict)
        signed_message = self._sign_message(message=plain_message, signing_key_fingerprint=signing_key, 
            expiration_check_time=expiration_check_time, signing_key_passphrase=signing_key_passphrase)
        signed_message['Subject'] = message_dict['subject']

        return str(signed_message)


    # TODO: Method comment.
    def build_signed_encrypted_message(self, expiration_check_time, message_dict, signing_key, signing_key_passphrase, encryption_keys):

        plain_message = self._build_plaintext_message(message_dict)
        signed_message = self._sign_message(message=plain_message, expiration_check_time=expiration_check_time, 
            signing_key_fingerprint=signing_key, signing_key_passphrase=signing_key_passphrase)

        encrypted_message = self._encrypt_message(message=signed_message, 
            expiration_check_time=expiration_check_time, encryption_keys=encryption_keys)
        encrypted_message['Subject'] = message_dict['subject']

        return str(encrypted_message)


    # Builds and returns a signed email based on the given message part.
    def _sign_message(self, message, expiration_check_time, signing_key_fingerprint, signing_key_passphrase):
        self._validate_key(signing_key_fingerprint, expiration_check_time)

        # Removes the first line and replaces LF with CR/LF
        message_string = str(message).split('\n', 1)[1].replace('\n', '\r\n')

        # Make the signature component
        signature_result = self.gpg.sign(message_string, detach=True, keyid=signing_key_fingerprint, passphrase=signing_key_passphrase)
        signature_text = str(signature_result)

        # The GnuPG library we use does not provide any granular error information
        #   or throw any exceptions for signature operations, so checking for an
        #   empty string is all we have.
        if(signature_text.strip() == ''):
            raise SignatureError('Error while signing message.')

        signature_part = MIMEApplication(_data=signature_text, _subtype='pgp-signature; name="signature.asc"', _encoder=encode_7or8bit)
        signature_part['Content-Description'] = 'OpenPGP Digital Signature'
        signature_part.set_charset('us-ascii')

        # Make a box to put the message and signature in
        # TODO: Sha1 is kind of broken, find an alternative.
        signed_message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
        signed_message.attach(message)
        signed_message.attach(signature_part)

        return signed_message


    # Encrypt a message object.
    def _encrypt_message(self, message, expiration_check_time, encryption_keys):
        for fingerprint in encryption_keys:
            self._validate_key(fingerprint, expiration_check_time)

        # PGP needs a version attachment
        pgp_version = MIMEApplication("", _subtype="pgp-encrypted", _encoder=encode_7or8bit)
        pgp_version["Content-Description"] = "PGP/MIME version identification"
        pgp_version.set_payload("Version: 1\n")

        # Encrypt the message
        encrypted_payload = self.gpg.encrypt(data=str(message), recipients=encryption_keys)
        encrypted_payload_string = str(encrypted_payload)

        # This ok variable is not as granular as we would like it to be.
        #   The gnupg library does not provide more information.
        if(encrypted_payload.ok == False):
            # TODO: If the status variable is not a string, decode it.
            raise EncryptionError('Error from python-gnupg while encrypting message: %s.' % encrypted_payload.status)

        encrypted_part = MIMEApplication("", _encoder=encode_7or8bit)
        encrypted_part.set_payload(encrypted_payload_string)

        # Pack it all into one big message
        encrypted_message = MIMEMultipart(_subtype="encrypted", protocol="application/pgp-encrypted")
        encrypted_message.attach(pgp_version)
        encrypted_message.attach(encrypted_part)

        return encrypted_message


    # Builds the initial mulipart message to be signed and/or encrypted
    # TODO: Change name to _build_plaintext_message_with_attachments.
    def _build_plaintext_message(self, message_dict):
        multipart_message = MIMEMultipart(_subtype="mixed")

        # TODO: This may need an extra newline. Test with attachments.
        multipart_message.attach(MIMEText(message_dict['body']))

        # Loop over the attachments
        if('attachments' in message_dict.keys()):
            for attachment in message_dict['attachments']:
                attachment_part = MIMEBase('application', 'octet-stream')
                attachment_part.set_payload(base64.b64encode(attachment['data']))
                attachment_part.add_header('Content-Transfer-Encoding', 'base64')
                attachment_part.add_header('Content-Disposition', 'attachment', filename=attachment['filename'])
                multipart_message.attach(attachment_part)

        return multipart_message


    # Checks if the given fingerprint is expired or untrusted and throws an
    #   appropriate exception in either case. Never returns anything.
    def _validate_key(self, fingerprint, expiration_check_time):

        if not(self.gpgkeyring.is_trusted(fingerprint)):
            raise GpgKeyUntrustedException('Key %s is not trusted.' % fingerprint)

        if not(self.gpgkeyring.is_current(fingerprint, expiration_check_time + self.max_operation_time)):
            raise GpgKeyExpiredException('Key %s is expired.' % fingerprint)
