#!/usr/bin/env python2

# Copyright 2015 Joel Allen Luellwitz and Andrew Klapp
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

import gnupg
import random
import smtplib
import subprocess
import time
import timber
import traceback
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.Encoders import encode_7or8bit
import base64

# TODO: Write more effective logging.
# TODO: I kinda want to review method separation and naming for the entire file.

class mailer ():
    
    def __init__(self, config):
        self.logger = timber.get_instance()
        self.config = config
        self.gpg = config['gpg']

        self.smtp = None

        self._connect()
        self.lastSentTime = time.time()

    def _connect(self):
        # TODO: Failed DNS lookups of the mail server might be eating messages. Investigate immediately.
        self.logger.info('Connecting.')
        if (self.smtp != None):
            # I originally tried to quit the existing SMTP session here, but that just slowed things down
            #   too much and usually threw an exception.
            self.smtp = None
        
        # Create a random number as our host id
        self.logger.debug('Generating random ehlo.')
        self.ehlo_id = str(random.SystemRandom().random()).split( '.', 1)[1]
        self.logger.debug('Random ehlo generated.')
        connected = False
        while not(connected):
	    try:
                self.smtp = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'], self.ehlo_id, int(self.config['smtp_sending_timeout']))
                self.logger.debug('starttls.')
                self.smtp.starttls()
                self.logger.debug('smtp.login.')
                self.smtp.login(self.config['smtp_user'], self.config['smtp_pass'])
                self.logger.info('Connected!')
                connected = True
            except smtplib.SMTPAuthenticationError, e:
                # TODO: Decide how to handle authentication errors
                self.logger.error('Failed to connect. Authentication error. Exception %s:%s' % (type(e).__name__, e.message))
                # TODO: Make this configurable?
                time.sleep(.1)
            except smtplib.SMTPDataError, e:
                # TODO: Backoff strategy
                self.logger.error('Failed to connect. Invalid response from server. Exception %s:%s' % (type(e).__name__, e.message))
                # TODO: Make this configurable?
                time.sleep(.1)
            except Exception, e:
                self.logger.error('Failed to connect. Waiting to try again. Exception %s:%s' % (type(e).__name__, e.message))
                # TODO: Make this configurable?
                time.sleep(.1)

    def _build_signed_message(self, message_dict):
        # this will sign the message text and attachments and puts them all together
        # Make a multipart message to contain the attachments and main message text.
        multipart_message = MIMEMultipart(_subtype="mixed")
        multipart_message.attach(MIMEText("%s\n" % message_dict['body']))

        # Loop over the attachments
        if('attachments' in message_dict.keys()):
            for attachment in message_dict['attachments']:
                mime_base = MIMEBase('application', 'octet-stream')
                mime_base.set_payload(base64.b64encode(attachment['data']))
                mime_base.add_header('Content-Transfer-Encoding', 'base64')
                mime_base.add_header('Content-Disposition', 'attachment', filename=attachment['filename'])
                multipart_message.attach(mime_base)

        # Removes the first line and replaces LF with CR/LF
        message_string = str(multipart_message).split('\n', 1)[1].replace('\n', '\r\n')

        # Make the signature component
        signature_text = str(self.gpg.sign(message_string, detach=True, keyid=self.config['sender']['fingerprint'], passphrase=self.config['sender']['key_password']))

        signature_part = MIMEApplication(_data=signature_text, _subtype='pgp-signature; name="signature.asc"', _encoder=encode_7or8bit)
        signature_part['Content-Description'] = 'OpenPGP Digital Signature'
        signature_part.set_charset('us-ascii')

        # Make a box to put the message and signature in
        signed_message = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
        signed_message.attach(multipart_message)
        signed_message.attach(signature_part)

        return signed_message

    # TODO: We should probably name this appropriately.
    def _eldtritch_crypto_magic(self, message_dict):

        # PGP needs a version attachment
        pgp_version = MIMEApplication("", _subtype="pgp-encrypted", _encoder=encode_7or8bit)
        pgp_version["Content-Description"] = "PGP/MIME version identification"
        pgp_version.set_payload("Version: 1\n")

        # Sign the message
        signed_message = self._build_signed_message(message_dict)

        # We need all encryption keys in a list
        fingerprint_list = []
        for recipient in self.config['recipients']:
            fingerprint_list.append(recipient['fingerprint'])
        # Encrypt the message
        encrypted_part = MIMEApplication("", _encoder=encode_7or8bit)
        # TODO: encrypt() can return empty if a recipient's key is not signed. We should handle this
        #   with a proper exception.
        encrypted_part.set_payload(str(self.gpg.encrypt(signed_message.as_string(), fingerprint_list)))

        # Pack it all into one big message
        encrypted_message = MIMEMultipart(_subtype="encrypted", protocol="application/pgp-encrypted")
        encrypted_message['Subject'] = message_dict['subject']
        encrypted_message.attach(pgp_version)
        encrypted_message.attach(encrypted_part)

        return encrypted_message

    def sendmail(self, message_dict):
        # Use our magic
        encrypted_message_string = str(self._eldtritch_crypto_magic(message_dict))

        # Get a list of recipients from config
        recipients = []
        for recipient in self.config['recipients']:
            recipients.append(recipient['email'])
            self.logger.trace(recipient['email'])

        # Mail servers will probably deauth you after a fixed period of inactivity.
        # TODO: There is probably also a hard session limit too.
        if (time.time() - self.lastSentTime) > self.config['smtp_max_idle']:
            self.logger.info("Assuming the connection is dead.")
            self._connect()

        try:
            self.smtp.sendmail(self.config['sender']['email'], recipients, encrypted_message_string)
        except Exception as e:
            self.logger.error("Failed to send: %s: %s\n" % (type(e).__name__, e.message))
            self.logger.debug(traceback.format_exc())

            # Try reconnecting and resending
            self._connect()
            self.smtp.sendmail(self.config['sender']['email'], recipients, encrypted_message_string)
        self.lastSentTime = time.time()
