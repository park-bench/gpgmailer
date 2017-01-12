
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

class GpgMailBuilder:
    def __init__(self, gpg_home, send_unsigned_messages):
        self.logger = logging.getLogger('GpgMailBuilder')
        self.gpgkeyring = gpgkeyring.GpgKeyRing(gpg_home)
        self.gpg = gnupg.GPG(gnupghome=gpg_home)
        self.send_unsigned_messages = send_unsigned_messages

        self.signature_error = False
        self.encryption_error = False

    # Formerly known as eldtdritch_crypto_magic. #NoFunAllowed
    def build_message(self, message_dict, recipient_fingerprints, signing_key_fingerprint, signing_key_password):

        # Reinitialize the error variables
        self.signature_error = False
        self.encryption_error = False
        
        encrypted_message = None

        # PGP needs a version attachment
        pgp_version = MIMEApplication("", _subtype="pgp-encrypted", _encoder=encode_7or8bit)
        pgp_version["Content-Description"] = "PGP/MIME version identification"
        pgp_version.set_payload("Version: 1\n")

        # Sign the message
        signed_message = self._build_signed_message(message_dict, signing_key_fingerprint, signing_key_password)

        # We need all encryption keys in a list
        good_fingerprints = []

        for fingerprint in recipient_fingerprints:
            if self.gpgkeyring.is_trusted(fingerprint) and not(self.gpgkeyring.is_expired(fingerprint)):
                good_fingerprints.append(fingerprint)

        if(good_fingerprints == []):
            self.logger.critical('No keys usable for encryption.')
            self.encryption_error = True

        elif signed_message:
            self.logger.debug('good fingerprints: %s' % good_fingerprints)
            # Encrypt the message
            encrypted_part = MIMEApplication("", _encoder=encode_7or8bit)
            encrypted_payload_result = self.gpg.encrypt(data=signed_message.as_string(), recipients=good_fingerprints)
            encrypted_payload = str(encrypted_payload_result)

            # This ok variable is not the status result we need. It only indicates failure.
            if(encrypted_payload_result.ok == False):
                self.logger.error('Error while encrypting message: %s.' % encrypted_payload_result.status)
                self.encryption_error = True

            encrypted_part.set_payload(encrypted_payload)

            # Pack it all into one big message
            encrypted_message = MIMEMultipart(_subtype="encrypted", protocol="application/pgp-encrypted")
            encrypted_message['Subject'] = message_dict['subject']
            encrypted_message.attach(pgp_version)
            encrypted_message.attach(encrypted_part)
        else:
            self.logger.debug('Not attempting to encrypt an empty message.')

        if self.encryption_error:
            return None
        else:
            return str(encrypted_message)

    def _build_plaintext_message(self, message_dict):
        multipart_message = MIMEMultipart(_subtype="mixed")

        # TODO: This may need an extra newline. Test with attachments.
        multipart_message.attach(MIMEText(message_dict['body']))

        # Loop over the attachments
        if('attachments' in message_dict.keys()):
            for attachment in message_dict['attachments']:
                mime_base = MIMEBase('application', 'octet-stream')
                mime_base.set_payload(base64.b64encode(attachment['data']))
                mime_base.add_header('Content-Transfer-Encoding', 'base64')
                mime_base.add_header('Content-Disposition', 'attachment', filename=attachment['filename'])
                multipart_message.attach(mime_base)

        return multipart_message


    def _build_signed_message(self, message_dict, signing_key_fingerprint, signing_key_password):
        # this will sign the message text and attachments and puts them all together
        # Make a multipart message to contain the attachments and main message text.

        signed_message = None

        signature_test = self.gpg.sign('I\'ve got a lovely bunch of coconuts', detach=True,
            keyid=signing_key_fingerprint, passphrase=signing_key_password)

        if(str(signature_test).strip() == ''):
            # The library we are using contains a bug and does not actually set the
            #   status variable in the documentation. It could be caused by a few
            #   things, but usually either the key password is wrong or the key is
            #   not trusted.
            self.signature_error = True
            self.logger.error('Error during signature test.')
        else:
            self.logger.trace('Signature test passed.')

        if(self.signature_error and self.send_unsigned_messages):
            # Prepend warning text to message body and build plaintext message

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
            signature_result = self.gpg.sign(message_string, detach=True, keyid=signing_key_fingerprint, passphrase=signing_key_password)
            signature_text = str(signature_result)

            signature_part = MIMEApplication(_data=signature_text, _subtype='pgp-signature; name="signature.asc"', _encoder=encode_7or8bit)
            signature_part['Content-Description'] = 'OpenPGP Digital Signature'
            signature_part.set_charset('us-ascii')

            # Make a box to put the message and signature in
            signed_message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
            signed_message.attach(multipart_message)
            signed_message.attach(signature_part)

        return signed_message

