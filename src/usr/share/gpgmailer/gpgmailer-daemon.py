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

import confighelper
import ConfigParser
import daemon
import gnupg
import gpgkeyring
import gpgmailer
import gpgmailmessage
import logging
import os
from daemon import pidlockfile
import signal
import sys
import traceback

PID_FILE = '/run/gpgmailer.pid'

# After first commit
# TODO: Clean up logging
# TODO: More helper methods, program should mostly be helper methods.
# TODO: Evaluate error conditions first.

# Adds a key to the key ring and returns the key's data as a dictionary.
def build_key_dict(key_config_string, gpgkeyring):
    key_dict = {}
    key_split = key_config_string.split(':')

    # TODO: Support multiple addresses for the same fingerprint.
    email = key_split[0].strip()
    fingerprint = key_split[1].strip()

    if not(gpgkeyring.is_trusted(fingerprint)):
        logger.critical("Key with fingerprint %s is not trusted. Exiting." % fingerprint)
        sys.exit(1)
    
    key_dict = { 'fingerprint': fingerprint,
        'email': email }

    # TODO: Move this function to gpgkeyverifier.
    gpgkeyring.set_key_email(fingerprint, email)

    return key_dict

# Quit when SIGTERM is received
def sig_term_handler(signal, stack_frame):
    logger.info("Quitting.")
    sys.exit(0)

print('Loading configuration.')
config_file = ConfigParser.RawConfigParser()
config_file.read('/etc/gpgmailer/gpgmailer.conf')

# Figure out the logging options so that can start before anything else.
print('Verifying configuration.')
config_helper = confighelper.ConfigHelper()
log_file = config_helper.verify_string_exists_prelogging(config_file, 'log_file')
log_level = config_helper.verify_string_exists_prelogging(config_file, 'log_level')

config_helper.configure_logger(log_file, log_level)

logger = logging.getLogger()

logger.info('Verifying non-logging config')
config = {}

config['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
config['smtp_user'] = config_helper.verify_string_exists(config_file, 'smtp_user')
config['smtp_pass'] = config_helper.verify_password_exists(config_file, 'smtp_pass')  # Note this is a password!
config['smtp_server'] = config_helper.verify_string_exists(config_file, 'smtp_server')
config['smtp_port'] = config_helper.verify_string_exists(config_file, 'smtp_port')
config['smtp_max_idle'] = config_helper.verify_string_exists(config_file, 'smtp_max_idle')
config['smtp_sending_timeout'] = config_helper.verify_string_exists(config_file, 'smtp_sending_timeout')

# Convert the key expiration threshold into seconds because expiry dates are
#   stored in unix time.
config['expiration_warning_threshold'] = config_helper.verify_number_exists(config_file, 'expiration_warning_threshold') * 86400

config['main_loop_delay'] = config_helper.verify_number_exists(config_file, 'main_loop_delay')
config['main_loop_duration'] = config_helper.verify_number_exists(config_file, 'main_loop_duration')

if(config_helper.verify_string_exists(config_file, 'allow_expired_signing_key').lower() == 'true'):
    config['allow_expired_signing_key'] = True
else:
    config['allow_expired_signing_key'] = False

config['default_subject'] = config_helper.get_string_if_exists(config_file, 'default_subject')

# init gnupg so we can verify keys
config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')

# TODO: Close config file.

# Parse and check keys.

gpgkeyring = gpgkeyring.GpgKeyRing(config['gpg_dir'])

# parse sender config.  <email>:<key fingerprint>
sender_key_string = config_helper.verify_string_exists(config_file, 'sender')
sender_key_password = config_helper.verify_password_exists(config_file, 'signing_key_passphrase')

sender_key = build_key_dict(sender_key_string, gpgkeyring)

# TODO: Evaluate error conditions first, first block does not need conditional.
if not(sender_key == {}):
    logger.info('Using sender %s' % sender_key['email'])
    sender_key['password'] = sender_key_password
    config['sender'] = sender_key
else:
    logger.critical('Sender key not defined or not in keyring. Exiting.')
    sys.exit(1)

# The signing key should always be present and trusted.
if not(gpgkeyring.is_trusted(sender_key['fingerprint'])):
    logger.critical('Signing key is not trusted. Exiting.');
    sys.exit(1)

if not config['allow_expired_signing_key']:
    # Check signing key
    logger.info('allow_expired_signing_key is not enabled, checking signing key.')

    if gpgkeyring.is_expired(sender_key['fingerprint']):
        # Log critical error and quit
        logger.critical('Sender key expired. Exiting.')
        sys.exit(1)


# TODO: Check for trust here and crash if any recipients are not trusted.
# parse recipient config. Comma-delimited list of recipents, formatted similarly to sender.
# <email>:<key fingerprint>,<email>:<key fingerprint>
config['recipients'] = []
recipients_raw_string = config_helper.verify_string_exists(config_file, 'recipients')
recipients_raw_list = recipients_raw_string.split(',')
for recipient in recipients_raw_list:
    recipient_key = build_key_dict(recipient, gpgkeyring)
    if recipient_key:
        logger.info('Adding recipient key for %s.' % recipient_key['email'])
        config['recipients'].append(recipient_key)
    else:
        logger.error('Recipient key for %s not available or invalid.' % recipient)
        expiration_message = gpgmailmessage.GpgMailMessage()
        expiration_message.set_body('The encryption key for %s is not available or is invalid.' % recipient_key['email'])
        expiration_message.queue_for_sending()


if config['recipients'] == []:
    logger.critical('No valid recipients. Exiting.')
    sys.exit(1)
    
logger.info('Verification complete')


# TODO: Work out a permissions setup for gpgmailer so that it doesn't run as root.
daemon_context = daemon.DaemonContext(
    working_directory = '/',
    pidfile = pidlockfile.PIDLockFile(PID_FILE),
    umask = 0
    )

# TODO: Make a real cleanup method for this.
daemon_context.signal_map = {
    signal.SIGTERM : sig_term_handler
    }

# TODO: Might cause an undetected conflict. Look for a copy of this line when merging
#   with master.
daemon_context.files_preserve = [config_helper.get_log_file_handle()]

logger.info('Daemonizing...')
with daemon_context:
    try:
        logger.debug('Initializing GpgMailer.')
        the_watcher = gpgmailer.GpgMailer(config, gpgkeyring)
        the_watcher.start_monitoring()

    except Exception as e:
        logger.critical("Fatal %s: %s\n%s" % (type(e).__name__, e.message, traceback.format_exc()))
        sys.exit(1)
