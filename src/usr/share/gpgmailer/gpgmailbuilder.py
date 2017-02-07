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
import gpgkeyring
import logging
import time

# TODO: Class-level comment.
class GpgMailBuilder:
    # TODO: GpgMailBuilder should not care about allow_expired_signing_key.
    # TODO: Add max_operation_time variable to add time to expiration checks.
    # TODO: Should have 3 exposed methods for signing, encrypting, and both.
    def __init__(self, gpg_home, allow_expired_signing_key):
        self.logger = logging.getLogger('GpgMailBuilder')
        self.gpgkeyring = gpgkeyring.GpgKeyRing(gpg_home)
        self.gpg = gnupg.GPG(gnupghome=gpg_home)
        self.allow_expired_signing_key = allow_expired_signing_key

        # TODO: Handle these with exceptions and return values, not class variables.
        self.signature_error = False
        self.encryption_error = False

    # Builds an encrypted and/or signed email message from the passed message dictionary.
    #   Formerly known as eldtdritch_crypto_magic. #NoFunAllowed
    # TODO: Have two separate methods for building signed and unsigned messages.
    def build_message(self, message_dict, encryption_fingerprints, signing_key_fingerprint, signing_key_passphrase):

        # Reinitialize the error variables
        self.signature_error = False
        self.encryption_error = False
        
        encrypted_message = None

        # PGP needs a version attachment
        pgp_version = MIMEApplication("", _subtype="pgp-encrypted", _encoder=encode_7or8bit)
        pgp_version["Content-Description"] = "PGP/MIME version identification"
        pgp_version.set_payload("Version: 1\n")

        # Sign the message
        signed_message = self._build_signed_message(message_dict, signing_key_fingerprint, signing_key_passphrase)

        # We need all encryption keys in a list
        valid_encryption_fingerprints = []

        for fingerprint in encryption_fingerprints:
            if self.gpgkeyring.is_trusted(fingerprint) and not(self.gpgkeyring.is_expired(fingerprint)):
                valid_encryption_fingerprints.append(fingerprint)

        if(valid_encryption_fingerprints == []):
            self.logger.critical('No keys usable for encryption.')
            # TODO: Throw exception here.
            self.encryption_error = True

        # TODO: Handle errors first here.
        elif signed_message:
            self.logger.debug('Encrypting with valid fingerprints: %s' % valid_encryption_fingerprints)
            # Encrypt the message
            encrypted_part = MIMEApplication("", _encoder=encode_7or8bit)
            encrypted_payload = self.gpg.encrypt(data=signed_message.as_string(), recipients=valid_encryption_fingerprints)
            encrypted_payload_string = str(encrypted_payload)

            # This ok variable is not as granular as we would like it to be.
            #   The gnupg library does not provide more information.
            if(encrypted_payload.ok == False):
                self.logger.error('Error while encrypting message: %s.' % encrypted_payload.status)
                # TODO: Throw an exception here instead.
                self.encryption_error = True

            encrypted_part.set_payload(encrypted_payload_string)

            # Pack it all into one big message
            encrypted_message = MIMEMultipart(_subtype="encrypted", protocol="application/pgp-encrypted")
            encrypted_message['Subject'] = message_dict['subject']
            encrypted_message.attach(pgp_version)
            encrypted_message.attach(encrypted_part)
        else:
            self.logger.debug('Not attempting to encrypt an empty message.')
            # TODO: Throw an exception here.

        if self.encryption_error:
            return None
        else:
            # TODO: Explain why this works and is necessary. Maybe method-level.
            return str(encrypted_message)

    # Builds the initial mulipart message to be signed and/or encrypted
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


    # TODO: Move detailed explanation to class comment.
    # Attempts to build a signed PGP/MIME email
    def _build_signed_message(self, message_dict, signing_key_fingerprint, signing_key_passphrase):
        # this will sign the message text and attachments and puts them all together
        # Make a multipart message to contain the attachments and main message text.

        signed_message = None

        # TODO: Move signature test to gpgmailer-daemon and store the result.
        signature_test = self.gpg.sign('I\'ve got a lovely bunch of coconuts', detach=True,
            keyid=signing_key_fingerprint, passphrase=signing_key_passphrase)

        if(str(signature_test).strip() == ''):
            # The library we are using contains a bug and does not actually set the
            #   status variable in the documentation. It could be caused by a few
            #   things, but usually either the key password is wrong or the key is
            #   not trusted.
            self.signature_error = True
            self.logger.error('Error during signature test.')
        else:
            self.logger.trace('Signature test passed.')

        if(self.signature_error and self.allow_expired_signing_key):
            # Prepend warning text to message body and build plaintext message

            # TODO: This should be responsibility of caller.
            # TODO: Throw exception and log.
            self.logger.error('Message could not be signed, sending unsigned message with warning.')

            message_dict['body'] = 'Warning: message is not signed. Check signing key expiration and passphrase.\n%s' \
                % message_dict['body']
            signed_message = self._build_plaintext_message(message_dict)

        elif(self.signature_error):
            # Log message and leave signed_message as None
            self.logger.error('Message could not be signed, not sending.')

        else:
            # Continue building the signature pieces

            multipart_message = self._build_plaintext_message(message_dict)
            # Removes the first line and replaces LF with CR/LF
            message_string = str(multipart_message).split('\n', 1)[1].replace('\n', '\r\n')

            # Make the signature component
            signature_result = self.gpg.sign(message_string, detach=True, keyid=signing_key_fingerprint, passphrase=signing_key_passphrase)
            signature_text = str(signature_result)

            signature_part = MIMEApplication(_data=signature_text, _subtype='pgp-signature; name="signature.asc"', _encoder=encode_7or8bit)
            signature_part['Content-Description'] = 'OpenPGP Digital Signature'
            signature_part.set_charset('us-ascii')

            # Make a box to put the message and signature in
            signed_message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
            signed_message.attach(multipart_message)
            signed_message.attach(signature_part)

        return signed_message
