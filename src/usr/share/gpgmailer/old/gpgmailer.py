#!/usr/bin/env python2

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

import gnupg
import gpgkey
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
        self.last_key_database_reload = time.time()

    def _connect(self):
        # TODO: Failed DNS lookups of the mail server might be eating messages. Investigate immediately.
        self.logger.info('Connecting.')
        if (self.smtp != None):
            # I originally tried to quit the existing SMTP session here, but that just slowed things down
            #   too much and usually threw an exception.
            self.smtp = None
        
        # Create a random number as our host id
        self.logger.debug('Generating random ehlo.')
        self.ehlo_id = str(random.SystemRandom().random()).split('.', 1)[1]
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

    # TODO: Put key business in a separate file.
    # Checks each key in use for expiration, then compiles a helpful message to
    #   be inserted into every email sent.
    def _build_key_expiration_message(self):
        # This will put together a message that lists any keys that are either
        #   expired or expiring soon.
        expired_messages = []
        expiring_soon_messages = []

        # Build a list of keys.
        # The sender is last here so they will end up first in the printed message.
        keys_to_check = list(self.config['recipients'])
        if self.config['sender'] not in keys_to_check:
            keys_to_check.append(self.config['sender'])

        # check each key
        for key in keys_to_check:
            self.logger.debug('Checking if key <%s> (%s) with expiration date <%s> has expired.' % (key.fingerprint, key.email, key.expires))
            key_status = key.get_key_expiration_status()
            if (key_status == 'expired'):
                message = 'Key <%s> (%s) is expired!' % (key.fingerprint, key.email)
                expired_messages.append(message)
                self.logger.warn(message)

            elif (key_status == 'expiring_soon'):
                pretty_expiration_date = time.strftime('%Y-%m-%d %H:%M:%S', key.expires)
                message = 'Key <%s> (%s) will be expiring on date <%s>!' % (key.fingerprint, key.email, pretty_expiration_date)
                expiring_soon_messages.append(message)
                self.logger.warn(message)

        joined_expired_messages = '\n'.join(expired_messages)
        joined_expiring_soon_messages = '\n'.join(expiring_soon_messages)
        full_message = '%s\n%s\n' % (joined_expired_messages, joined_expiring_soon_messages)

        return full_message

    def _build_signed_message(self, message_dict):
        # this will sign the message text and attachments and puts them all together
        # Make a multipart message to contain the attachments and main message text.

        multipart_message = MIMEMultipart(_subtype="mixed")

        # TODO: This may need an extra newline. Test with attachments.
        multipart_message.attach(MIMEText(message_dict['message']))

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
        sender = self.config['sender']
        signature_result = self.gpg.sign(message_string, detach=True, keyid=sender.fingerprint, passphrase=sender.password)
        signature_text = str(signature_result)

        if(signature_text == ''):
            # The library we are using contains a bug and does not actually set the
            #   status variable in the documentation. It could be caused by a few
            #   things, but usually either the key password is wrong or the key is
            #   not trusted.
            # TODO: In this case, build an unsigned message with a warning prepended to the body.
            self.logger.error('Error while signing message.')

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
        # Build the key expiration message
        if((time.time() - self.last_key_database_reload) >= self.config['key_database_reload_interval']):
            self.logger.info('last_key_database_reload: %s, delta: %s\nReloading database.' % (self.last_key_database_reload, \
                (time.time() - self.last_key_database_reload)))
            self.last_key_database_reload = time.time()
        else:
            self.logger.trace('Not checking keys.')

        key_expiration_message = self._build_key_expiration_message()
        message_dict['message'] = '%s%s\n' % (key_expiration_message, message_dict['message'])

        # PGP needs a version attachment
        pgp_version = MIMEApplication("", _subtype="pgp-encrypted", _encoder=encode_7or8bit)
        pgp_version["Content-Description"] = "PGP/MIME version identification"
        pgp_version.set_payload("Version: 1\n")

        # Sign the message
        signed_message = self._build_signed_message(message_dict)

        # We need all encryption keys in a list
        fingerprint_list = []
        encryption_error = False

        for recipient in self.config['recipients']:
            if recipient.valid == True:
                fingerprint_list.append(recipient.fingerprint)

        # Encrypt the message
        encrypted_part = MIMEApplication("", _encoder=encode_7or8bit)
        encrypted_payload_result = self.gpg.encrypt(signed_message.as_string(), fingerprint_list)
        encrypted_payload = str(encrypted_payload_result)

        # This ok variable is not the status result we need. It only indicates failure.
        if(encrypted_payload_result.ok == False):
            # TODO: Handle this error properly. Do not send or delete the message.
            self.logger.error('Error while encrypting message: %s.' % encrypted_payload_result.status)
            encryption_error = True

        encrypted_part.set_payload(encrypted_payload)

        # Pack it all into one big message
        encrypted_message = MIMEMultipart(_subtype="encrypted", protocol="application/pgp-encrypted")
        encrypted_message['Subject'] = message_dict['subject']
        encrypted_message.attach(pgp_version)
        encrypted_message.attach(encrypted_part)

        if encryption_error:
            return None
        else:
            return encrypted_message

    def sendmail(self, message_dict):
        sent_successfully = False
        # Use our magic
        encrypted_message = self._eldtritch_crypto_magic(message_dict)
        encrypted_message_string = str(encrypted_message)

        # Get a list of recipients from config
        recipients = []
        for recipient in self.config['recipients']:
            recipients.append(recipient.email)

        # Mail servers will probably deauth you after a fixed period of inactivity.
        # TODO: There is probably also a hard session limit too.
        if (time.time() - self.lastSentTime) > self.config['smtp_max_idle']:
            self.logger.info("Assuming the connection is dead.")
            self._connect()


        if not(encrypted_message == None):
            try:
                self.smtp.sendmail(self.config['sender'].email, recipients, encrypted_message_string)
                sent_successfully = True
            except Exception as e:
                self.logger.error("Failed to send: %s: %s\n" % (type(e).__name__, e.message))
                self.logger.error(traceback.format_exc())

                # Try reconnecting and resending
                self._connect()
                self.smtp.sendmail(self.config['sender'].email, recipients, encrypted_message_string)
                sent_successfully = True
            self.lastSentTime = time.time()
        else:
            self.logger.error('Message is empty, encryption or signing failed, not sending.')

        return sent_successfully
