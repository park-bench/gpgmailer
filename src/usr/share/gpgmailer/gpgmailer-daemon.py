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
import time
import traceback

PID_FILE = '/run/gpgmailer.pid'

# After first commit
# TODO: Clean up logging
# TODO: More helper methods, program should mostly be helper methods.
# TODO: Evaluate error conditions first.

logger = None

# Parses the email:fingerprint format for keys in the config file.
def parse_key_config(key_config_string):
    key_dict = {}

    key_split = key_config_string.split(':')

    # TODO: Verify email format?

    key_dict = {'email': key_split[0].strip(),
        'fingerprint': key_split[1].strip()}

    return key_dict

# Read the config file, only performing the basic verification done in ConfigHelper,
#   and return it.
def build_config_dict():

    print('Loading configuration.')
    config_file = ConfigParser.RawConfigParser()
    config_file.read('/etc/gpgmailer/gpgmailer.conf')

    config_helper = confighelper.ConfigHelper()

    # Figure out the logging options so that can start before anything else.
    print('Configuring logger')
    log_file = config_helper.verify_string_exists_prelogging(config_file, 'log_file')
    log_level = config_helper.verify_string_exists_prelogging(config_file, 'log_level')

    config_helper.configure_logger(log_file, log_level)

    global logger
    logger = logging.getLogger()

    config_dict = {}

    # Read SMTP configuration
    config_dict['smtp_user'] = config_helper.verify_string_exists(config_file, 'smtp_user')
    config_dict['smtp_pass'] = config_helper.verify_password_exists(config_file, 'smtp_pass')  # Note this is a password!
    config_dict['smtp_server'] = config_helper.verify_string_exists(config_file, 'smtp_server')
    config_dict['smtp_port'] = config_helper.verify_string_exists(config_file, 'smtp_port')
    config_dict['smtp_max_idle'] = config_helper.verify_string_exists(config_file, 'smtp_max_idle')
    config_dict['smtp_sending_timeout'] = config_helper.verify_string_exists(config_file, 'smtp_sending_timeout')

    # Parse sender config.
    sender_key_string = config_helper.verify_string_exists(config_file, 'sender')
    sender_key_password = config_helper.verify_password_exists(config_file, 'signing_key_passphrase')

    sender_key = parse_key_config(sender_key_string)
    sender_key['password'] = sender_key_password

    config_dict['sender'] = sender_key

    # parse recipient config. Comma-delimited list of recipents.
    recipient_list = []
    recipients_raw_string = config_helper.verify_string_exists(config_file, 'recipients')
    recipients_raw_list = recipients_raw_string.split(',')

    for recipient in recipients_raw_list:
        recipient_list.append(parse_key_config(recipient))

    config_dict['recipients'] = recipient_list


    config_dict['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
    config_dict['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')

    # Convert the key expiration threshold into seconds because expiry dates are
    #   stored in unix time.
    config_dict['expiration_warning_threshold'] = config_helper.verify_number_exists(config_file, 'expiration_warning_threshold') * 86400

    config_dict['main_loop_delay'] = config_helper.verify_number_exists(config_file, 'main_loop_delay')
    config_dict['main_loop_duration'] = config_helper.verify_number_exists(config_file, 'main_loop_duration')
    config_dict['key_check_interval'] = config_helper.verify_number_exists(config_file, 'key_check_interval')

    config_dict['default_subject'] = config_helper.get_string_if_exists(config_file, 'default_subject')

    log_file_handle = config_helper.get_log_file_handle()

    return config_dict, log_file_handle

# Checks an individual key. Crashes if it is not trusted or not in keyring.
#   Returns False if key will expire within the configured time for the first
#   loop, otherwise returns True.
def key_is_usable(fingerprint, gpgkeyring):
    usable = False

    if not(gpgkeyring.is_trusted(fingerprint)):
        logger.critical('Key with fingerprint %s is not trusted. Exiting' % fingerprint)
        sys.exit(1)

    # TODO: Check expiration, too.
    else:
        logger.debug('Key with fingerprint %s is usable.' % fingerprint)
        usable = True

    return usable

def send_warning_email(message_body):
    pass

# Checks every key in the config file and crashes if necessary. Also checks and
#   stores whether the sender key can be used to sign.
def check_all_keys(config_dict, gpgkeyring):
    logger.info('Starting initial key check')

    if not(key_is_usable(config['sender']['fingerprint'], gpgkeyring)):
        # TODO: Queue warning email.
        logger.warn('Sender key is expired.')

    if not(gpgkeyring.signature_test(config['sender']['fingerprint'], config['sender']['password'])):
        logger.warn('Sender key failed signature test.')
        config['sender']['can_sign'] = False

    else:
        logger.debug('Sender key passed signature test.')
        config['sender']['can_sign'] = True

    valid_recipients = []

    for recipient in config['recipients']:
        if(key_is_usable(recipient['fingerprint'], gpgkeyring)):
            valid_recipients.append(recipient)
        
    logger.debug('Finished initial key check.')

    if(valid_recipients == []):
        logger.critical('No recipients are valid. Exiting.')
        sys.exit(1)

    else:
        config['recipients'] = valid_recipients


def set_send_unsigned_email(config_dict):
    pass

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

    return key_dict

# Reads and checks the sender key configuration, exiting during appropriate conditions,
#   and returns a dictionary of sender information.
def parse_sender_config(config_file, gpgkeyring):
    # parse sender config.  <email>:<key fingerprint>
    sender_key_string = config_helper.verify_string_exists(config_file, 'sender')
    sender_key_password = config_helper.verify_password_exists(config_file, 'signing_key_passphrase')

    sender_key = build_key_dict(sender_key_string, gpgkeyring)

    if not(sender_key):
        logger.critical('Sender key not defined or not in keyring. Exiting.')
        sys.exit(1)

    # The signing key should always be present and trusted.
    if not(gpgkeyring.is_trusted(sender_key['fingerprint'])):
        logger.critical('Signing key is not trusted. Exiting.');
        sys.exit(1)

    sender_key['password'] = sender_key_password

    return sender_key
    
# Reads and checks recipient key information, and returns a dict of valid
#   recipients. If a recipient's fingerprint is invalid or unavailable, a warning
#   email is queued. If no recipients are valid, the program exits.
def parse_recipient_config(config_file, gpgkeyring):
    # parse recipient config. Comma-delimited list of recipents, formatted similarly to sender.
    # <email>:<key fingerprint>,<email>:<key fingerprint>
    recipient_list = []
    recipients_raw_string = config_helper.verify_string_exists(config_file, 'recipients')
    recipients_raw_list = recipients_raw_string.split(',')
    for recipient in recipients_raw_list:
        recipient_key = build_key_dict(recipient, gpgkeyring)
        if recipient_key:
            logger.info('Adding recipient key for %s.' % recipient_key['email'])
            recipient_list.append(recipient_key)
        else:
            logger.error('Recipient key for %s not available or invalid.' % recipient)
            expiration_message = gpgmailmessage.GpgMailMessage()
            expiration_message.set_body('The encryption key for %s is not available or is invalid.' % recipient_key['email'])
            expiration_message.queue_for_sending()

    if recipient_list == []:
        logger.critical('No valid recipients. Exiting.')
        sys.exit(1)

    return recipient_list


# Quit when SIGTERM is received
def sig_term_handler(signal, stack_frame):
    logger.info("Quitting.")
    sys.exit(0)

print('Verifying configuration.')

config, log_file_handle = build_config_dict()

gpgkeyring = gpgkeyring.GpgKeyRing(config['gpg_dir'])
check_all_keys(config, gpgkeyring)

set_send_unsigned_email(config)

# TODO: Check directory existence and permissions.


# TODO: This should be a helper method
# Determine whether unsigned email must be sent.

'''
if(config_helper.verify_string_exists(config_file, 'allow_expired_signing_key').lower() == 'true'):
    allow_expired_signing_key = True
else:
    allow_expired_signing_key = False

config['send_unsigned_email'] = False

sender_key_can_sign = gpgkeyring.signature_test(config['sender']['fingerprint'],
    config['sender']['password'])

expiration_date = time.time() + config['main_loop_delay'] + config['main_loop_duration'] + config['key_check_interval']
sender_key_is_current = gpgkeyring.is_current(config['sender']['fingerprint'], expiration_date)

if not allow_expired_signing_key:
    # Check signing key
    logger.info('allow_expired_signing_key is not enabled, checking signing key.')

    if not(sender_key_is_current):
        # Log critical error and quit
        logger.critical('Sender key expired. Exiting.')
        sys.exit(1)

    elif not(sender_key_can_sign):
        logger.critical('Sender key failed a signature test. Exiting.')
        sys.exit(1)

else:
    if not(sender_key_is_current):
        logger.warn('Sender key is expired, will send unsigned email.')
        config['send_unsigned_email'] = True

    elif not(sender_key_can_sign):
        logger.warn('Sender key failed a signature test, will send unsigned email.')
        config['send_unsigned_email'] = True

    else:
        logger.debug('Sending signed email.')
'''



logger.info('Verification complete')


# TODO: Either warn or crash when the config file is readable by everyone.
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
daemon_context.files_preserve = [log_file_handle]

# TODO: Delete this line after organizing the init code. It's just for testing.
sys.exit(0)

logger.info('Daemonizing...')
with daemon_context:
    try:
        logger.debug('Initializing GpgMailer.')
        the_watcher = gpgmailer.GpgMailer(config, gpgkeyring)
        the_watcher.start_monitoring()

    except Exception as e:
        logger.critical("Fatal %s: %s\n%s" % (type(e).__name__, e.message, traceback.format_exc()))
        sys.exit(1)
