# Copyright 2015-2019 Joel Allen Luellwitz and Emily Frost
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

__all__ = ['GpgMailer']
__author__ = 'Joel Luellwitz, Emily Frost, and Brittney Scaccia'
__version__ = '0.8'

import base64
import json
import logging
import os
import subprocess
import time
import traceback
from parkbenchcommon import broadcastconsumer
import gpgkeyverifier
import gpgmailbuilder

# The number of seconds to wait after a broadcast to get another broadcast.
BROADCAST_NETCHECK_GATEWAY_CHANGED_DELAY = 5
BROADCAST_NETCHECK_GATEWAY_CHANGED_NAME = 'gateway-changed'

class SendmailException(Exception):
    """This exception is raised when sendmail returns an error code indicating that it failed
    to queue a message.
    """

class GpgMailer():
    """Contains high level program business logic.  Monitors the outbox directory, manages
    keys, and coordinates sending e-mail.
    """

    def __init__(self, config, gpgkeyring, gpgkeyverifier, outbox_path):
        """Constructs an instance of the class including creating local instances of
        mailsender and gpgmailbuilder.

        config: The config dictionary read from the program configuration file.
        gpgkeyring: The GpgKeyring object containing information on all the GPG keys in the
          program's keyring.
        gpgkeyverifier: The GpgKeyVerifier object managing key expiration for all sender and
          recipient GPG keys keys.
        outbox_path: The directory to monitor for outgoing mail (in our custom JSON format).
        """
        self.logger = logging.getLogger('GpgMailer')
        self.logger.info('Initializing gpgmailer module.')

        self.config = config
        self.gpgkeyring = gpgkeyring
        self.gpgkeyverifier = gpgkeyverifier
        self.gpgmailbuilder = gpgmailbuilder.GpgMailBuilder(
            self.gpgkeyring, self.config['main_loop_duration'])

        self.outbox_path = outbox_path

        self.netcheck_broadcast = broadcastconsumer.BroadcastConsumer(
            'netcheck', BROADCAST_NETCHECK_GATEWAY_CHANGED_NAME,
            BROADCAST_NETCHECK_GATEWAY_CHANGED_DELAY)

        # Set this here so that the string equality check in
        #   _update_expiration_warning_message evaluates to equal on the initial loop.
        self.expiration_warning_message = \
            gpgkeyverifier.get_expiration_warning_message(time.time())

        self.logger.info('Done initializing gpgmailer module.')

    def start_monitoring(self):
        """GpgMailer's main program loop.  Reads the spool directory and then calls other
        modules to build and send e-mail.  Also sends warnings about GPG key expirations.
        """
        while True:
            try:

                loop_start_time = time.time()

                self.valid_recipient_emails = self.gpgkeyverifier.get_valid_recipient_emails(
                    loop_start_time)
                self.valid_key_fingerprints = self.gpgkeyverifier.get_valid_key_fingerprints(
                    loop_start_time)

                self._update_expiration_warnings(loop_start_time)

                # Return a list of non-directory files in the outbox directory.
                #   The first element of os.walk is the full path, the second is a
                #   list of directories, and the third is a list of non-directory
                #   files.
                for file_name in sorted(next(os.walk(self.outbox_path))[2]):
                    self.logger.info('Found queued e-mail in file %s.', file_name)
                    self._read_and_send_message(file_name, loop_start_time)

                if self.netcheck_broadcast.check():
                    self.logger.info('Received a gateway change broadcast. Flushing sendmail'
                                     ' queue.')
                    subprocess.call(['sendmail', '-q'])

                time.sleep(self.config['main_loop_delay'])

            except gpgkeyverifier.NoUsableKeysException as exception:
                self.logger.critical('No keys available for encryption. Exiting. %s: %s',
                                     type(exception).__name__, str(exception))
                raise exception
            except gpgkeyverifier.SenderKeyExpiredException as exception:
                self.logger.critical(
                    'Sender key has expired and sending unsigned e-mails is not allowed. '
                    'Exiting. %s: %s', type(exception).__name__, str(exception))
                raise exception
            except Exception as exception:
                self.logger.error('Exception %s: %s.', type(exception).__name__,
                                  str(exception))
                self.logger.error(traceback.format_exc())

    def _read_and_send_message(self, file_name, loop_start_time):
        """Attempts to build a message and send it. Handles all exceptions so that no one
        problematic message holds up the processing of other messages.

        file_name: The name of the message file in the outbox directory. Not a full path.
        loop_start_time: The time associated with the current program loop from which all PGP
          key expiration checks are based.
        """
        try:
            message_dict = self._read_message_file(file_name)

            # Set default subject if the queued message does not have one.
            if message_dict['subject'] is None:
                message_dict['subject'] = self.config['default_subject']

            encrypted_message = self._build_encrypted_message(
                message_dict, loop_start_time)

            self._send_mail(mime_message=encrypted_message,
                            recipients=self.valid_recipient_emails)
            self.logger.info('Message %s sent successfully.', file_name)

            os.remove(os.path.join(self.outbox_path, file_name))

        except gpgkeyverifier.NoUsableKeysException as no_usable_keys:
            # This exception should abort the program, so we just re-raise it.
            raise no_usable_keys

        except gpgkeyverifier.SenderKeyExpiredException as sender_key_expired:
            # This exception should abort the program, so we just re-raise it.
            raise sender_key_expired

        except Exception as exception:
            self.logger.error('Exception %s: %s.', type(exception).__name__,
                              str(exception))
            self.logger.error(traceback.format_exc())

    def _read_message_file(self, file_name):
        """Reads a message file from the outbox directory and builds a dictionary
        representing the message appropriate for gpgmailbuilder.

        file_name: The name of the message file in the outbox directory. Not a full path.
        Returns a dictionary that represents an e-mail message.
        """
        self.logger.trace('Reading message file %s.' % file_name)
        fullpath = os.path.join(self.outbox_path, file_name)

        message_dict = {}

        with open(fullpath, 'r') as file_handle:
            message_dict = json.loads(file_handle.read())

        for attachment in message_dict['attachments']:
            # Attachment data is assumed to be encoded in base64.
            attachment['data'] = base64.b64decode(attachment['data'])

        self.logger.trace('Message file %s read.' % file_name)

        return message_dict

    def _update_expiration_warnings(self, loop_start_time):
        """Periodically checks whether the expiration warning message has changed and if it
        has, start including the new expiration warning message at the top of every e-mail
        and send an e-mail immediately with the updated warning.

        loop_start_time: The time associated with the current program loop from which all PGP
          key expiration checks are based.
        """
        new_expiration_warning_message = \
            self.gpgkeyverifier.get_expiration_warning_message(loop_start_time)

        # TODO: Eventually, change this so it isn't a string comparison. (issue 35)
        if self.expiration_warning_message != new_expiration_warning_message:
            self.logger.info(
                'The expiration status of one or more keys have changed. Sending an '
                'expiration warning e-mail and updating expiration warning message.')
            self.expiration_warning_message = new_expiration_warning_message

            # Actually send the warning e-mail.
            message_dict = {
                'subject': self.config['default_subject'],
                'body': 'The expiration status of one or more keys have changed.'}
            encrypted_message = self._build_encrypted_message(message_dict, loop_start_time)
            self._send_mail(mime_message=encrypted_message,
                            recipients=self.valid_recipient_emails)

    def _build_encrypted_message(self, message_dict, loop_start_time):
        """Builds an encrypted e-mail string with a signature if possible.

        message_dict: A dictionary containing the body, subject, and attachments of a
          message.
        loop_start_time: The time associated with the current program loop from which all
          PGP key expiration checks are based.
        Returns a PGP/MIME encrypted e-mail message.
        """
        # See if the sender key has expired. (We exit the program elsewhere if the sender key
        #   expired and we don't allow sending unsigned e-mails.)
        sender_key_is_current = self.config[
            'sender']['fingerprint'] in self.valid_key_fingerprints

        if self.expiration_warning_message is not None:
            message_dict['body'] = '%s\n\n%s' % (
                self.expiration_warning_message, message_dict['body'])

        if not sender_key_is_current or not self.config['sender']['can_sign']:
            message = self.gpgmailbuilder.build_encrypted_message(
                message_dict=message_dict,
                # Intentionally includes sender key so we can read sent e-mails.
                # TODO: We should eventually make it an option to not include the sender key.
                #   (issue 36)
                encryption_keys=self.valid_key_fingerprints,
                loop_current_time=loop_start_time)

        else:
            message = self.gpgmailbuilder.build_signed_encrypted_message(
                message_dict=message_dict,
                # Intentionally includes sender key so we can read sent e-mails.
                # TODO: We should eventually make it an option to not include the sender key.
                #   (issue 36)
                encryption_keys=self.valid_key_fingerprints,
                signing_key_fingerprint=self.config['sender']['fingerprint'],
                signing_key_passphrase=self.config['sender']['password'],
                loop_current_time=loop_start_time)

        return message

    def _send_mail(self, mime_message, recipients):
        """Adds From and To headers to the message object, then passes the message to
        sendmail to be queued by the local MTA.

        mime_message: A MIMEMultipart message object describing the e-mail to send.
        recipients:     A list of e-mail addresses to send the e-mail to.
        """
        self.logger.info('Sending message via sendmail.')

        recipients_string = ', '.join(recipients)

        mime_message['From'] = self.config['sender']['email']
        mime_message['To'] = recipients_string

        sendmail_process = subprocess.Popen(['sendmail', '-t'], stdin=subprocess.PIPE)
        sendmail_process.communicate(str(mime_message))
        sendmail_process.stdin.close()
        sendmail_process.wait()

        if sendmail_process.returncode >= 64:
            raise SendmailException('Message was not queued. Sendmail returned error code ' \
                    '%s.' % sendmail_process.returncode)

        self.logger.debug('Message queued successfully.')
