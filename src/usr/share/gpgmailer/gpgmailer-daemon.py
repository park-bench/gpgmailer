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
import gpgkeyverifier
import gpgmailer
import gpgmailmessage
import logging
import os
from daemon import pidlockfile
import signal
import sys
import time
import traceback

pid_file = '/run/gpgmailer.pid'
config_pathname = '/etc/gpgmailer/gpgmailer.conf'

logger = None

# Parses the email:fingerprint format for keys in the config file.
#
# key_config_string: the string to parse
def parse_key_config_string(key_config_string):
    key_dict = {}

    key_split = key_config_string.split(':')

    # TODO: Eventually verify email format.

    key_dict = {'email': key_split[0].strip(),
        'fingerprint': key_split[1].strip()}

    return key_dict


# Read the config file, only performing the basic verification done in ConfigHelper,
#   and return it.
def build_config_dict():

    # TODO: Some config numbers must be positive, add a verify_positive_number method
    #   to confighelper for this, or verify_number_greater_than.

    print('Reading %s...' % config_pathname)
    config_file = ConfigParser.RawConfigParser()
    config_file.read(config_pathname)

    config_helper = confighelper.ConfigHelper()

    # Figure out the logging options so that can start before anything else.
    print('Configuring logger')
    log_file = config_helper.verify_string_exists_prelogging(config_file, 'log_file')
    log_level = config_helper.verify_string_exists_prelogging(config_file, 'log_level')

    config_helper.configure_logger(log_file, log_level)

    global logger
    logger = logging.getLogger('GpgMailer-Daemon')

    config_dict = {}

    # Read SMTP configuration
    config_dict['smtp_domain'] = config_helper.verify_string_exists(config_file, 'smtp_domain')
    config_dict['smtp_port'] = config_helper.verify_string_exists(config_file, 'smtp_port')
    config_dict['smtp_username'] = config_helper.verify_string_exists(config_file, 'smtp_username')
    config_dict['smtp_password'] = config_helper.verify_password_exists(config_file, 'smtp_password')  # Note this is a password!
    config_dict['smtp_max_idle'] = config_helper.verify_string_exists(config_file, 'smtp_max_idle')
    config_dict['smtp_sending_timeout'] = config_helper.verify_string_exists(config_file, 'smtp_sending_timeout') # in seconds

    # Read key configuration
    config_dict['sender_string'] = config_helper.verify_string_exists(config_file, 'sender')
    config_dict['sender'] = {}
    config_dict['sender']['password'] = config_helper.verify_password_exists(config_file, 'signing_key_passphrase')
    config_dict['recipients_string'] = config_helper.verify_string_exists(config_file, 'recipients')

    config_dict['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
    config_dict['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')

    # Convert the key expiration threshold into seconds because expiry dates are
    #   stored in unix time. The config value should be days.
    config_dict['expiration_warning_threshold'] = config_helper.verify_number_exists(config_file, 'expiration_warning_threshold') * 86400

    config_dict['main_loop_delay'] = config_helper.verify_number_exists(config_file, 'main_loop_delay') # In seconds
    config_dict['main_loop_duration'] = config_helper.verify_number_exists(config_file, 'main_loop_duration') # in seconds
    config_dict['key_check_interval'] = config_helper.verify_number_exists(config_file, 'key_check_interval') # in seconds

    config_dict['default_subject'] = config_helper.get_string_if_exists(config_file, 'default_subject')

    config_dict['allow_expired_signing_key'] = (config_helper.verify_string_exists(config_file, 'allow_expired_signing_key').lower() == 'true')

    log_file_handle = config_helper.get_log_file_handle()

    return config_dict, log_file_handle

# Parses all of the key configurations in the given config dictionary
#
# config_dict: the config dictionary to read from
def parse_key_config(config_dict):
    sender_key_data = parse_key_config_string(config_dict['sender_string'])
    config_dict['sender']['fingerprint'] = sender_key_data['fingerprint']
    config_dict['sender']['email'] = sender_key_data['email']

    recipients_config_list = config_dict['recipients_string'].split(',')
    recipients = []

    for recipient_config in recipients_config_list:
        recipients.append(parse_key_config_string(recipient_config))

    config_dict['recipients'] = recipients


# Determines whether an individual key is trusted. If it is not a valid
#   fingerprint string, not in the key store, or not trusted, the program will
#   exit.
#
# fingerprint: the fingerprint of the key to check
# gpg_keyring: the GpgKeyring object containing the key
def key_is_usable(fingerprint, gpg_keyring):

    if not(gpg_keyring.is_trusted(fingerprint)):
        logger.critical('Key with fingerprint %s is not trusted. Exiting.' % fingerprint)
        sys.exit(1)

    else:
        logger.debug('Key with fingerprint %s is trusted.' % fingerprint)


# Attempt to sign an arbitrary string. Returns True if there are no errors, False
#   otherwise.
#
# fingerprint: the fingerprint of the key to attempt signing with
# passphrase: the passphrase for this key
# gpg_home: the gnupg directory to read keys from
def signature_test(fingerprint, passphrase, gpg_home):
    success = False
    gpg = gnupg.GPG(gnupghome=gpg_home)

    signature_test_result = gpg.sign('I\'ve got a lovely bunch of coconuts.',
        detach=True, keyid=fingerprint, passphrase=passphrase)

    if(str(signature_test_result).strip() == ''):
        logger.warn('Signature test failed.')
    else:
        logger.trace('Signature test passed.')
        success = True

    return success


# Checks every key in the config file and exits if any of them are missing,
#   untrusted, or are not 40-character hex strings. Also checks and stores
#    whether the sender key can be used to sign or is expired.
#
# config_dict: the dict to read key configuration from
# gpg_keyring: the GpgKeyring object in which to look for keys
def check_all_keys(config_dict, gpg_keyring):
    logger.info('Checking all keys for trust and expiration.')

    expiration_date = time.time() + config['main_loop_duration'] + config['main_loop_delay']

    key_is_usable(config['sender']['fingerprint'], gpg_keyring)

    if not(gpg_keyring.is_current(config['sender']['fingerprint'], expiration_date)):
        sender_key_expiration_date = gpg_keyring.get_key_expiration_date(config['sender']['fingerprint'], date_format='%Y-%m-%d %H:%M:%S')
        logger.warn('Sender key expired on %s.' % sender_key_expiration_date)

    if not(signature_test(config['sender']['fingerprint'], config['sender']['password'], config['gpg_dir'])):
        logger.warn('Sender key failed signature test.')
        config['sender']['can_sign'] = False

    else:
        logger.debug('Sender key passed signature test.')
        config['sender']['can_sign'] = True

    for recipient in config['recipients']:
        key_is_usable(recipient['fingerprint'], gpg_keyring)

    global gpg_key_verifier
    gpg_key_verifier = gpgkeyverifier.GpgKeyVerifier(gpg_keyring, config)

    expiration_message = gpg_key_verifier.get_expiration_message(time.time())

    if expiration_message:
        message = 'Gpgmailer has just restarted. \n\n%s' % expiration_message
        mail_message = gpgmailmessage.GpgMailMessage()
        mail_message.set_subject(config['default_subject'])
        mail_message.set_body(message)
        mail_message.queue_for_sending()
        
    logger.debug('Finished initial key check.')


# Checks the sending key and configuration to determine if sending unsigned email
#   is allowed. Crashes if the sending key cannot sign and sending unsigned email
#   is disabled.
#
# config_dict: the dict to read key configuration from
def verify_signing_config(config_dict):
    if(not(config_dict['allow_expired_signing_key']) and not(config_dict['sender']['can_sign'])):
        logger.critical('The sender key with fingerprint %s can not sign and \
            unsigned email is not allowed. Exiting.' % config_dict['sender']['fingerprint'])
        sys.exit(1)

    elif not(config_dict['sender']['can_sign']):
        logger.warn('The sending key is unable to sign. It may be expired or the password may be incorrect. Gpgmailer will send unsigned messages.')

    else:
        logger.debug('Outgoing emails will be signed.')


# Quit when SIGTERM is received.
def sig_term_handler(signal, stack_frame):
    logger.info("Quitting.")
    sys.exit(0)


config, log_file_handle = build_config_dict()
parse_key_config(config)

gpg_keyring = gpgkeyring.GpgKeyRing(config['gpg_dir'])
check_all_keys(config, gpg_keyring)

verify_signing_config(config)

# TODO: Eventually, check directory existence and permissions.
# TODO: Eventually, move default outbox directory to /var/spool/gpgmailer

logger.info('Verification complete.')


# TODO: Eventually, either warn or crash when the config file is readable by everyone.
# TODO: Eventually, work out a permissions setup for gpgmailer so that it doesn't run as root.
daemon_context = daemon.DaemonContext(
    working_directory = '/',
    pidfile = pidlockfile.PIDLockFile(pid_file),
    umask = 0
    )

# TODO: Eventually make a real cleanup method for this.
daemon_context.signal_map = {
    signal.SIGTERM : sig_term_handler
    }

# TODO: Might cause an undetected conflict. Look for a copy of this line when merging
#   with master.
daemon_context.files_preserve = [log_file_handle]

logger.info('Daemonizing...')
with daemon_context:
    try:
        logger.debug('Initializing GpgMailer.')
        the_watcher = gpgmailer.GpgMailer(config, gpg_keyring, gpg_key_verifier)
        the_watcher.start_monitoring()

    except Exception as e:
        logger.critical("Fatal %s: %s\n%s" % (type(e).__name__, e.message, traceback.format_exc()))
        sys.exit(1)
