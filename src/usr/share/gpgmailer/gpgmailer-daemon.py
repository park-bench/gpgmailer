#!/usr/bin/env python2

# Copyright 2015-2018 Joel Allen Luellwitz and Emily Frost
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

__author__ = 'Joel Luellwitz, Emily Frost, and Brittney Scaccia'
__version__ = '0.8'

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
# TODO: Remove try/except when we drop support for Ubuntu 14.04 LTS.
try:
    from lockfile import pidlockfile
except ImportError:
    from daemon import pidlockfile
import signal
import subprocess
import sys
import time
import traceback

# TODO: Target Ubuntu 18.04 instead of 14.04 (issue 8)

PID_FILE = '/run/gpgmailer.pid'
CONFIG_PATHNAME = '/etc/gpgmailer/gpgmailer.conf'

logger = None


class InitializationException(Exception):
    """Indicates an expected fatal error occurred during gpgmailer's initialization.
    Initialization is implied to mean, before daemonization.
    """


def check_if_mounted_as_tmpfs(pathname):
    """Checks if a directory is mounted as tmpfs."""
    return 'none on {0} type tmpfs'.format(pathname) in subprocess.check_output('mount')


def create_watch_directories(config):
    """Mounts the parent watch directory as a ramdisk and creates the draft and outbox
    subfolders. Exit if any part of this method fails.
    """
    logger.info('Creating watch directories.')

    # Method normpath reduces the path to its simplist form.
    watch_dir = os.path.normpath(config['watch_dir'])

    try:
        if os.path.isdir(watch_dir) is False:
            os.makedirs(watch_dir)
    except Exception as e:
        message = 'Could not create root watch directory. %s: %s' % (
            type(e).__name__, e.message)
        logger.critical(message)
        logger.critical(traceback.format_exc())
        raise InitializationException(message)

    mounted_as_tmpfs = check_if_mounted_as_tmpfs(watch_dir)

    # If directory is not mounted as tmpfs and there is something in the directory, fail to
    #   start.
    if os.listdir(watch_dir) != [] and mounted_as_tmpfs is False:
        message = 'Root watch directory is not empty and not mounted as a ramdisk. ' \
                  'Startup failed.'
        logger.critical(message)
        raise InitializationException(message)

    # If the root watch directory is empty and not already mounted as tmpfs, mount it as
    #   tmpfs.
    if mounted_as_tmpfs is False:
        logger.info('Attempting to mount the root watch directory as a ramdisk.')
        subprocess.call(['mount', '-t', 'tmpfs', '-o', 'size=25%', 'none', watch_dir])

    if check_if_mounted_as_tmpfs(watch_dir) is False:
        message = 'Root watch directory was not mounted as a ramdisk. Startup failed.'
        logger.critical(message)
        raise InitializationException(message)

    outbox_dir = os.path.join(watch_dir, 'outbox')
    draft_dir = os.path.join(watch_dir, 'draft')

    try:
        if not os.path.isdir(outbox_dir):
            os.makedirs(outbox_dir)
        if not os.path.isdir(draft_dir):
            os.makedirs(draft_dir)
    except Exception as e:
        message = 'Could not create required watch sub-directories. %s: %s' % (
            type(e).__name__, e.message)
        logger.critical(message)
        logger.critical(traceback.format_exc())
        raise InitializationException(message)


def parse_key_config_string(configuration_option, key_config_string):
    """Parses the e-mail:fingerprint format used in the application config file to specify
    e-mail/GPG key pairs.

    configuration_option: The name of the configuration option being parsed.
    key_config_string: The formatted string to parse.
    """
    key_split = key_config_string.split(':')

    if len(key_split) is not 2:
        message = 'Key config %s for %s is does not contain a colon or is malformed.' % (
            key_config_string, configuration_option)
        logger.critical(message)
        raise InitializationException(message)

    if not key_split[0]:
        message = 'Key config %s for %s is missing an e-mail address.' % (
            key_config_string, configuration_option)
        logger.critical(message)
        raise InitializationException(message)

    if not key_split[1]:
        message = 'Key config %s for %s is missing a key fingerprint.' % (
            key_config_string, configuration_option)
        logger.critical(message)
        raise InitializationException(message)

    # TODO: Eventually verify e-mail format.
    key_dict = {'email': key_split[0].strip(),
                'fingerprint': key_split[1].strip()}

    return key_dict


def build_config_dict():
    """Reads the application config file performing only the basic verifications done in
    ConfigHelper and returns the config as a dictionary.
    """
    print('Reading %s...' % CONFIG_PATHNAME)

    if not os.path.isfile(CONFIG_PATHNAME):
        raise InitializationException(
            'Configuration file %s does not exist. Quitting.' % CONFIG_PATHNAME)

    config_file = ConfigParser.RawConfigParser()
    config_file.read(CONFIG_PATHNAME)

    config_helper = confighelper.ConfigHelper()

    # Figure out the logging options so that can start before anything else.
    print('Configuring logger.')
    log_file = config_helper.verify_string_exists(config_file, 'log_file')
    # TODO: Eventually add a verify_string_list method.
    log_level = config_helper.verify_string_exists(config_file, 'log_level')

    config_helper.configure_logger(log_file, log_level)

    global logger
    logger = logging.getLogger('GpgMailer-Daemon')

    config = {}

    # Reads the key configuration.
    config['sender_string'] = config_helper.verify_string_exists(config_file, 'sender')
    config['sender'] = {}
    config['sender']['password'] = config_helper.verify_password_exists(
        config_file, 'signing_key_passphrase')
    config['recipients_string'] = config_helper.verify_string_exists(
        config_file, 'recipients')

    config['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
    config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')

    # Convert the key expiration threshold into seconds because expiry dates are
    #   stored in unix time. The config value should be days.
    expiration_warning_threshold_days = config_helper.verify_integer_within_range(
        config_file, 'expiration_warning_threshold', lower_bound=1)
    config['expiration_warning_threshold'] = expiration_warning_threshold_days * 86400

    config['main_loop_delay'] = config_helper.verify_number_within_range(
        config_file, 'main_loop_delay', lower_bound=0.000001)  # In seconds.
    config['main_loop_duration'] = config_helper.verify_number_within_range(
        config_file, 'main_loop_duration', lower_bound=0.000001)  # In seconds.
    config['key_check_interval'] = config_helper.verify_number_within_range(
        config_file, 'key_check_interval', lower_bound=0.000001)  # In seconds.

    config['default_subject'] = config_helper.get_string_if_exists(
        config_file, 'default_subject')

    # TODO: Eventually add verify_boolean_exists.
    config['allow_expired_signing_key'] = (config_helper.verify_string_exists(
        config_file, 'allow_expired_signing_key').lower() == 'true')

    log_file_handle = config_helper.get_log_file_handle()

    return config, log_file_handle


def parse_key_config(config):
    """Does further processing on the config dictionary to parse and store GPG key
    information.

    config: The config dictionary to process.
    """
    sender_key_data = parse_key_config_string('sender', config['sender_string'])
    config['sender']['fingerprint'] = sender_key_data['fingerprint']
    config['sender']['email'] = sender_key_data['email']

    recipients_config_list = config['recipients_string'].split(',')
    recipients = []

    for recipient_config in recipients_config_list:
        recipients.append(parse_key_config_string('recipients', recipient_config))

    config['recipients'] = recipients


def signature_test(gpg_home, fingerprint, passphrase):
    """Tests if it is possible for a GPG key to sign an arbitrary string.

    gpg_home: The GnuPG directory to read keys from.
    fingerprint: The fingerprint of the key used to sign.
    passphrase: The passphrase for the signing key.
    Returns True if there are no signing errors. False otherwise.
    """
    # TODO: Eventually, parse gpg output to notify that the password was wrong.
    success = False
    gpg = gnupg.GPG(gnupghome=gpg_home)

    signature_test_result = gpg.sign(
        "I've got a lovely bunch of coconuts.", detach=True, keyid=fingerprint,
        passphrase=passphrase)

    if str(signature_test_result).strip() == '':
        logger.debug('Signature test for %s failed. Check the sender key\'s passphrase.' %
                     fingerprint)
    else:
        logger.info('Signature test for %s passed.' % fingerprint)
        success = True

    return success


def check_sender_key(gpg_keyring, config, expiration_date):
    """Checks the sender GPG key in the config file and exits if it is missing from the key
    ring, untrusted, unsigned, or is not a 40-character hex string. Also checks and stores
    whether the sender key can be used to sign messages.

    gpg_keyring: The GpgKeyring object in which to look for GPG keys.
    config: The config dict to read the sender GPG key information from.
    expiration_date: The date the singing key is validated to not expire through.
    """
    logger.info('Checking sender key for validity and expiration.')

    if not gpg_keyring.is_trusted(config['sender']['fingerprint']):
        message = 'Signing key is not ultimately trusted. Exiting.'
        logger.critical(message)
        raise InitializationException(message)

    elif not gpg_keyring.is_signed(config['sender']['fingerprint']):
        message = 'Signing key is not signed. Exiting.'
        logger.critical(message)
        raise InitializationException(message)

    elif not gpg_keyring.is_current(config['sender']['fingerprint'], expiration_date):
        formatted_expiration_date = datetime.datetime.fromtimestamp(
            gpg_keyring.get_key_expiration_date(
                config['sender']['fingerprint'])).strftime('%Y-%m-%d %H:%M:%S')
        logger.warn('Sender key expired on %s.' % formatted_expiration_date)
        config['sender']['can_sign'] = False

    elif not signature_test(
            config['gpg_dir'], config['sender']['fingerprint'],
            config['sender']['password']):
        message = 'Sender key failed the signature test and the key is not expired. ' \
                  "Check the sender key's passphrase."
        logger.critical(message)
        raise InitializationException(message)

    else:
        logger.debug('Sender key passed signature test.')
        config['sender']['can_sign'] = True


def check_all_recipient_keys(gpg_keyring, config):
    """Checks every recipient GPG key in the config file and exits if any of them are missing
    from the key ring, untrusted and unsigned, or are not 40-character hex strings.

    gpg_keyring: The GpgKeyring object in which to look for GPG keys.
    config: The config dict to read recipient GPG key information from.
    """
    logger.info('Checking recipient keys for validity and expiration.')

    for recipient in config['recipients']:
        if (not gpg_keyring.is_trusted(recipient['fingerprint']) and
                not gpg_keyring.is_signed(recipient['fingerprint'])):
            message = 'Key with fingerprint %s is not signed (and not sufficiently ' \
                'trusted). Exiting.' % recipient['fingerprint']
            logger.critical(message)
            raise InitializationException(message)
        else:
            logger.debug('Recipient key with fingerprint %s is signed or ultimately '
                         'trusted.' % recipient['fingerprint'])


def verify_signing_config(config):
    """Checks the sending GPG key and the program configuration to determine if sending
    unsigned e-mail is allowed.  Crashes if the sending key cannot sign and sending unsigned
    e-mail is disabled.

    config: The program config dictionary to read the key configuration from.
    """
    if not config['allow_expired_signing_key'] and not config['sender']['can_sign']:
        message = 'The sender key with fingerprint %s can not sign and ' \
            'unsigned e-mail is not allowed. Exiting.' % config['sender']['fingerprint']
        logger.critical(message)
        raise InitializationException(message)

    elif not config['sender']['can_sign']:
        logger.warn('The sender key is unable to sign because it has probably expired. '
            'Gpgmailer will send unsigned messages.')

    else:
        logger.debug('Outgoing e-mails will be signed.')


def send_expiration_warning_message(gpg_keyring, config, expiration_date):
    """If needed, queues a warning message about keys that have expired or will be expiring
    soon.

    gpg_keyring: The GpgKeyring object in which to look for GPG keys.
    config: The config dict to read sender and recipient GPG key information from.
    expiration_date: The date the singing key was validated to not expire through.
    Returns a GpgKeyVerifier object initalized with gpg_keyring and config. This is used
      later.
    """
    gpg_key_verifier = gpgkeyverifier.GpgKeyVerifier(gpg_keyring, config)
    expiration_warning_message = gpg_key_verifier.get_expiration_warning_message(
        expiration_date)

    if expiration_warning_message is not None:
        logger.warn('Sending expiration warning message email.')
        message = 'Gpgmailer has just restarted.'
        gpgmailmessage.GpgMailMessage.configure()
        mail_message = gpgmailmessage.GpgMailMessage()
        mail_message.set_subject(config['default_subject'])
        mail_message.set_body(message)
        mail_message.queue_for_sending()

    logger.debug('Finished initial key check.')

    return gpg_key_verifier


def sig_term_handler(signal, stack_frame):
    """Signal handler for SIGTERM. Quits when SIGTERM is received.

    signal: Object representing the signal thrown.
    stack_frame: Represents the stack frame.
    """
    logger.info("SIGTERM received. Quitting.")
    sys.exit(0)


config, log_file_handle = build_config_dict()
try:
    parse_key_config(config)

    create_watch_directories(config)

    # Make sure the sender key isn't going to expire during the first loop iteration.
    expiration_date = time.time() + config['main_loop_duration']

    gpg_keyring = gpgkeyring.GpgKeyRing(config['gpg_dir'])
    check_sender_key(gpg_keyring, config, expiration_date)
    check_all_recipient_keys(gpg_keyring, config)
    # We do this here because we don't want to queue an e-mail if a configuraiton setting
    #   can cause the program to crash later. This is to avoid a lot of identical queued
    #   warning e-mails.
    verify_signing_config(config)
    gpg_key_verifier = send_expiration_warning_message(gpg_keyring, config, expiration_date)

    # TODO: Check directory existence and permissions. (issue 9)
    # TODO: Eventually, move default outbox directory to /var/spool/gpgmailer

    logger.info('Verification complete.')


    # TODO: Either warn or crash when the config file is readable by everyone. (issue 9)
    # TODO: Work out a permissions setup for gpgmailer so that it doesn't run as root.
    #   (issue 9)
    daemon_context = daemon.DaemonContext(
        working_directory='/',
        pidfile=pidlockfile.PIDLockFile(PID_FILE),
        umask=0
        )

    daemon_context.signal_map = {
        signal.SIGTERM: sig_term_handler
        }

    daemon_context.files_preserve = [log_file_handle]

    logger.info('Daemonizing...')
    with daemon_context:
        logger.debug('Initializing GpgMailer.')
        the_watcher = gpgmailer.GpgMailer(config, gpg_keyring, gpg_key_verifier)
        the_watcher.start_monitoring()

except Exception as exception:
    logger.critical("Fatal %s: %s\n%s" % (type(exception).__name__, exception.message,
                    traceback.format_exc()))
    raise exception
