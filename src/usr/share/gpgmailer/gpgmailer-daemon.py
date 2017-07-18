#!/usr/bin/env python2

# Copyright 2015-2017 Joel Allen Luellwitz, Andrew Klapp and Brittney
# Scaccia.
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
import datetime
import gnupg
import gpgkeyring
import gpgkeyverifier
import gpgmailer
import gpgmailmessage
import logging
import os
from daemon import pidlockfile
import signal
import subprocess
import sys
import time
import traceback

pid_file = '/run/gpgmailer.pid'
config_pathname = '/etc/gpgmailer/gpgmailer.conf'

logger = None

# Checks if a directory is mounted as tmpfs.
def check_if_mounted_as_tmpfs(pathname):
    return 'none on {0} type tmpfs'.format(pathname) in subprocess.check_output('mount')

# Mounts the parent watch directory as a ramdisk and creates the draft and outbox subfolders.
#   Exit if any part of this method fails.
def create_watch_directories(config):

    logger.info('Creating watch directories.')

    # Method normpath reduces the path to its simplist form.
    watch_dir = os.path.normpath(config['watch_dir'])

    try:
        if os.path.isdir(watch_dir) == False:
            os.makedirs(watch_dir)
    except Exception as e:
        logger.critical('Could not create root watch directory. %s: %s\n' %
            (type(e).__name__, e.message))
        logger.error(traceback.format_exc())
        sys.exit(1)

    mounted_as_tmpfs = check_if_mounted_as_tmpfs(watch_dir)

    # If directory is not mounted as tmpfs and there is something in the directory, fail to
    #   start.
    if os.listdir(watch_dir) != [] and mounted_as_tmpfs == False:
        logger.critical('Root watch directory is not empty and not mounted as a ramdisk. ' + \
            'Startup failed.')
        sys.exit(1)

    # If the root watch directory is empty and not already mounted as tmpfs, mount it as tmpfs.
    if mounted_as_tmpfs == False:
        logger.info('Attempting to mount the root watch directory as a ramdisk.')
        subprocess.call(['mount', '-t', 'tmpfs', '-o', 'size=25%', 'none', watch_dir])

    if check_if_mounted_as_tmpfs(watch_dir) == False:
        logger.critical('Root watch directory was not mounted as a ramdisk. Startup failed.')
        sys.exit(1)

    outbox_dir = os.path.join(watch_dir, 'outbox')
    draft_dir = os.path.join(watch_dir, 'draft')

    try:
        if not os.path.isdir(outbox_dir):
            os.makedirs(outbox_dir)
        if not os.path.isdir(draft_dir):
            os.makedirs(draft_dir)
    except Exception as e:
        logger.critical('Could not create required watch sub-directories. %s: %s\n' %
            (type(e).__name__, e.message))
        logger.error(traceback.format_exc())
        sys.exit(1)

# Parses the e-mail:fingerprint format used in the application config file to specify e-mail/GPG
#   key pairs.
#
# key_config_string: The formatted string to parse.
def parse_key_config_string(key_config_string):

    key_split = key_config_string.split(':')

    # TODO: Eventually verify e-mail format.
    key_dict = {'email': key_split[0].strip(),
        'fingerprint': key_split[1].strip()}

    return key_dict


# Reads the application config file performing only the basic verifications done in ConfigHelper
#   and returns the config as a dictionary.
def build_config_dict():

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

    config = {}

    # Reads the SMTP configuration.
    config['smtp_domain'] = config_helper.verify_string_exists(config_file, 'smtp_domain')
    config['smtp_port'] = config_helper.verify_integer_within_range(config_file, 'smtp_port', lower_bound=1, upper_bound=65536)
    config['smtp_username'] = config_helper.verify_string_exists(config_file, 'smtp_username')
    config['smtp_password'] = config_helper.verify_password_exists(config_file, 'smtp_password')  # Note this is a password!
    config['smtp_max_idle'] = config_helper.verify_integer_within_range(config_file, 'smtp_max_idle', lower_bound=1)
    config['smtp_sending_timeout'] = config_helper.verify_integer_within_range(config_file, 'smtp_sending_timeout', lower_bound=1)  # In seconds.

    # Reads the key configuration.
    config['sender_string'] = config_helper.verify_string_exists(config_file, 'sender')
    config['sender'] = {}
    config['sender']['password'] = config_helper.verify_password_exists(config_file, 'signing_key_passphrase')
    config['recipients_string'] = config_helper.verify_string_exists(config_file, 'recipients')

    config['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
    config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')

    # Convert the key expiration threshold into seconds because expiry dates are
    #   stored in unix time. The config value should be days.
    expiration_warning_threshold_days = config_helper.verify_integer_within_range(config_file, 'expiration_warning_threshold', lower_bound=1)
    config['expiration_warning_threshold'] = expiration_warning_threshold_days * 86400

    config['main_loop_delay'] = config_helper.verify_number_within_range(config_file, 'main_loop_delay', lower_bound=0)  # In seconds.
    config['main_loop_duration'] = config_helper.verify_number_within_range(config_file, 'main_loop_duration', lower_bound=0)  # In seconds.
    config['key_check_interval'] = config_helper.verify_number_within_range(config_file, 'key_check_interval', lower_bound=0)  # In seconds.

    config['default_subject'] = config_helper.get_string_if_exists(config_file, 'default_subject')

    config['allow_expired_signing_key'] = (config_helper.verify_string_exists(config_file, 'allow_expired_signing_key').lower() == 'true')

    log_file_handle = config_helper.get_log_file_handle()

    return config, log_file_handle


# Does further processing on the config dictionary to parse and store GPG key information.
#
# config: The config dictionary to process.
def parse_key_config(config):

    sender_key_data = parse_key_config_string(config['sender_string'])
    config['sender']['fingerprint'] = sender_key_data['fingerprint']
    config['sender']['email'] = sender_key_data['email']

    recipients_config_list = config['recipients_string'].split(',')
    recipients = []

    for recipient_config in recipients_config_list:
        recipients.append(parse_key_config_string(recipient_config))

    config['recipients'] = recipients


# Determines whether an individual GPG key is usable. Usable is defined as a valid hexadecimal string,
#   in the GPG keyring, and trusted. If the key is not usable, the program will exit.
#
# gpg_keyring: The GpgKeyring object that should contain the specified GPG key.
# fingerprint: The fingerprint of the GPG key to check.
def key_is_usable(gpg_keyring, fingerprint):

    if not gpg_keyring.is_trusted(fingerprint):
        logger.critical('Key with fingerprint %s is not trusted. Exiting.' % fingerprint)
        sys.exit(1)

    else:
        logger.debug('Key with fingerprint %s is trusted.' % fingerprint)


# Tests if it is possible for a GPG key to sign an arbitrary string.
#
# gpg_home: The GnuPG directory to read keys from.
# fingerprint: The fingerprint of the key used to sign.
# passphrase: The passphrase for the signing key.
# Returns True if there are no signing errors. False otherwise.
def signature_test(gpg_home, fingerprint, passphrase):

    success = False
    gpg = gnupg.GPG(gnupghome=gpg_home)

    signature_test_result = gpg.sign('I\'ve got a lovely bunch of coconuts.',
        detach=True, keyid=fingerprint, passphrase=passphrase)

    if str(signature_test_result).strip() == '':
        logger.info('Signature test for %s failed.' % fingerprint)
    else:
        logger.info('Signature test for %s passed.' % fingerprint)
        success = True

    return success


# Checks every GPG key in the config file and exits if any of them are missing from the key ring,
#   untrusted, or are not 40-character hex strings. Also checks and stores
#   whether the sender key can be used to sign messages.
#
# gpg_keyring: The GpgKeyring object in which to look for GPG keys.
# config: The config dict to read sender and recipient GPG key information from.
# Returns a GpgKeyVerifier object initalized with gpg_keyring and config.
def check_all_keys(gpg_keyring, config):
    logger.info('Checking all keys for trust and expiration.')

    # Make sure the sender key isn't going to expire during the first loop iteration.
    expiration_date = time.time() + config['main_loop_duration']

    key_is_usable(gpg_keyring, config['sender']['fingerprint'])

    if not gpg_keyring.is_current(config['sender']['fingerprint'], expiration_date):
        formatted_expiration_date = datetime.datetime.fromtimestamp(
            gpg_keyring.get_key_expiration_date(config['sender']['fingerprint']).strftime('%Y-%m-%d %H:%M:%S'))
        logger.warn('Sender key expired on %s.' % formatted_expiration_date)

    if not signature_test(config['gpg_dir'], config['sender']['fingerprint'], config['sender']['password']):
        logger.warn('Sender key failed signature test.')
        config['sender']['can_sign'] = False

    else:
        logger.debug('Sender key passed signature test.')
        config['sender']['can_sign'] = True

    for recipient in config['recipients']:
        key_is_usable(gpg_keyring, recipient['fingerprint'])

    # We do this here because we don't want to queue an e-mail if a configuraiton setting can
    #   cause the program to crash later. (verify_signing_config was originally called after this
    #   method.) This is to avoid a lot of identical queued warning e-mails.
    verify_signing_config(config)

    gpg_key_verifier = gpgkeyverifier.GpgKeyVerifier(gpg_keyring, config)

    expiration_warning_message = gpg_key_verifier.get_expiration_warning_message(expiration_date)

    if expiration_warning_message is not None:
        message = 'Gpgmailer has just restarted.\n\n%s' % expiration_warning_message
        gpgmailmessage.GpgMailMessage.configure()
        mail_message = gpgmailmessage.GpgMailMessage()
        mail_message.set_subject(config['default_subject'])
        mail_message.set_body(message)
        mail_message.queue_for_sending()
        
    logger.debug('Finished initial key check.')

    return gpg_key_verifier


# Checks the sending GPG key and the program configuration to determine if sending unsigned e-mail
#   is allowed. Crashes if the sending key cannot sign and sending unsigned e-mail is disabled.
#
# config: The program config dictionary to read the key configuration from.
def verify_signing_config(config):

    if not config['allow_expired_signing_key'] and not config['sender']['can_sign']:
        logger.critical('The sender key with fingerprint %s can not sign and ' +
            'unsigned e-mail is not allowed. Exiting.' % config['sender']['fingerprint'])
        sys.exit(1)

    elif not config['sender']['can_sign']:
        logger.warn('The sending key is unable to sign. It may be expired or the password may be ' +
            'incorrect. Gpgmailer will send unsigned messages.')

    else:
        logger.debug('Outgoing e-mails will be signed.')


# Signal handler for SIGTERM. Quits when SIGTERM is received.
#
# signal: Object representing the signal thrown.
# stack_frame: Represents the stack frame.
def sig_term_handler(signal, stack_frame):
    logger.info("Quitting.")
    sys.exit(0)


config, log_file_handle = build_config_dict()
parse_key_config(config)

create_watch_directories(config)

gpg_keyring = gpgkeyring.GpgKeyRing(config['gpg_dir'])
gpg_key_verifier = check_all_keys(gpg_keyring, config)

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

daemon_context.signal_map = {
    signal.SIGTERM : sig_term_handler
    }

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
