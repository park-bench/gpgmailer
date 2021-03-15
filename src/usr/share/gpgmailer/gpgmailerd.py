#!/usr/bin/python3

# Copyright 2015-2021 Joel Allen Luellwitz and Emily Frost
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

"""Daemon for sending PGP encrypted e-mail."""

# TODO: Eventually consider running in a chroot or jail. (gpgmailer issue 17)

__author__ = 'Joel Luellwitz, Emily Frost, and Brittney Scaccia'
__version__ = '0.8'

import datetime
import grp
import logging
import os
import pwd
import signal
import stat
import subprocess
import sys
import time
import traceback
import configparser
import daemon
from lockfile import pidlockfile
import psutil
import gnupg
from parkbenchcommon import confighelper
import gpgkeyring
import gpgkeyverifier
import gpgmailer
import gpgmailmessage

# Constants
PROGRAM_NAME = 'gpgmailer'
CONFIGURATION_PATHNAME = os.path.join('/etc', PROGRAM_NAME, '%s.conf' % PROGRAM_NAME)
SYSTEM_PID_DIR = '/run'
PROGRAM_PID_DIRS = PROGRAM_NAME
PID_FILE = '%s.pid' % PROGRAM_NAME
LOG_DIR = os.path.join('/var/log', PROGRAM_NAME)
LOG_FILE = '%s.log' % PROGRAM_NAME
SYSTEM_SPOOL_DIR = '/var/spool'
PARTIAL_DIR = 'partial'
OUTBOX_DIR = 'outbox'
OUTBOX_PATHNAME = os.path.join(SYSTEM_SPOOL_DIR, PROGRAM_NAME, OUTBOX_DIR)
PROCESS_USERNAME = PROGRAM_NAME
PROCESS_GROUP_NAME = PROGRAM_NAME
PROGRAM_UMASK = 0o027  # -rw-r----- and drwxr-x---


class InitializationException(Exception):
    """Indicates an expected fatal error occurred during program initialization.
    Initialization is implied to mean, before daemonization.
    """


def get_user_and_group_ids():
    """Get user and group information for dropping privileges.

    Returns the user and group IDs that the program should eventually run as.
    """
    try:
        program_user = pwd.getpwnam(PROCESS_USERNAME)
    except KeyError as key_error:
        message = 'User %s does not exist.' % PROCESS_USERNAME
        raise InitializationException(message) from key_error
    try:
        program_group = grp.getgrnam(PROCESS_GROUP_NAME)
    except KeyError as key_error:
        message = 'Group %s does not exist.' % PROCESS_GROUP_NAME
        raise InitializationException(message) from key_error

    return program_user.pw_uid, program_group.gr_gid


def read_configuration_and_create_logger(program_uid, program_gid):
    """Reads the configuration file and creates the application logger. This is done in the
    same function because part of the logger creation is dependent upon reading the
    configuration file.

    program_uid: The system user ID this program should drop to before daemonization.
    program_gid: The system group ID this program should drop to before daemonization.
    Returns the read system config, a confighelper instance, and a logger instance.
    """
    print('Reading %s...' % CONFIGURATION_PATHNAME)

    if not os.path.isfile(CONFIGURATION_PATHNAME):
        raise InitializationException(
            'Configuration file %s does not exist. Quitting.' % CONFIGURATION_PATHNAME)

    config_file = configparser.RawConfigParser()
    config_file.read(CONFIGURATION_PATHNAME)

    config = {}
    config_helper = confighelper.ConfigHelper()
    # Figure out the logging options so that can start before anything else.
    # TODO: Eventually add a verify_string_list method. (issue 20)
    config['log_level'] = config_helper.verify_string_exists(config_file, 'log_level')

    # Create logging directory.  drwxr-x--- gpgmailer gpgmailer
    log_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP
    # TODO: Look into defaulting the logging to the console until the program gets more
    #   bootstrapped. (issue 18)
    print('Creating logging directory %s.' % LOG_DIR)
    if not os.path.isdir(LOG_DIR):
        # Will throw exception if directory cannot be created.
        os.makedirs(LOG_DIR, log_mode)
    os.chown(LOG_DIR, program_uid, program_gid)
    os.chmod(LOG_DIR, log_mode)

    # Temporarily drop permissions and create the handle to the logger.
    print('Configuring logger.')
    os.setegid(program_gid)
    os.seteuid(program_uid)
    config_helper.configure_logger(os.path.join(LOG_DIR, LOG_FILE), config['log_level'])

    logger = logging.getLogger(__name__)

    logger.info('Verifying non-logging configuration.')

    config['use_ramdisk_spool'] = config_helper.verify_boolean_exists(
        config_file, 'use_ramdisk_spool')

    # Reads the key configuration.
    config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')
    config['sender_string'] = config_helper.verify_string_exists(config_file, 'sender')
    config['sender'] = {}
    config['sender']['password'] = config_helper.verify_password_exists(
        config_file, 'signing_key_passphrase')
    config['recipients_string'] = config_helper.verify_string_exists(
        config_file, 'recipients')

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

    # TODO: Eventually add verify_boolean_exists. (issue 19)
    config['allow_expired_signing_key'] = (config_helper.verify_string_exists(
        config_file, 'allow_expired_signing_key').lower() == 'true')

    return config, config_helper, logger


def raise_exception(exception):
    """Raises an exception.

    exception: Any exception.
    """
    # TODO: Add custom error message and chain this exception when we move to Python 3.
    #   (issue 15)
    raise exception


# TODO: Consider checking ACLs. (issue 22)
def verify_safe_file_permissions(config, program_uid):
    """Crashes the application if unsafe file and directory permissions exist on application
    configuration files.

    config: The program config dictionary to read the application GPG keyring location from.
    program_uid: The system user ID that should own the GPG keyring.
    """
    # The configuration file should be owned by root.
    config_file_stat = os.stat(CONFIGURATION_PATHNAME)
    if config_file_stat.st_uid != 0:
        raise InitializationException(
            'File %s must be owned by root.' % CONFIGURATION_PATHNAME)
    if bool(config_file_stat.st_mode & stat.S_IWGRP):
        raise InitializationException(
            "File %s cannot be writable via the group access permission."
            % CONFIGURATION_PATHNAME)
    if bool(config_file_stat.st_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)):
        raise InitializationException(
            "File %s cannot have 'other user' access permissions set."
            % CONFIGURATION_PATHNAME)

    if not os.path.isdir(config['gpg_dir']):
        raise InitializationException('GPG keyring %s does not exist.' % config['gpg_dir'])

    logger.debug('Recursively checking %s for correct permissions.', config['gpg_dir'])
    for directory, subdirectories, files in os.walk(
            config['gpg_dir'], onerror=raise_exception, followlinks=True):

        for index, filename in enumerate(files):
            files[index] = os.path.join(directory, filename)

        for inode in [directory] + files:
            gpg_dir_stat = os.stat(inode)
            if gpg_dir_stat.st_uid != program_uid:
                raise InitializationException(
                    'Directory %s and all its contents must be owned by %s.' % (
                        config['gpg_dir'], PROGRAM_NAME))

    if bool(os.stat(config['gpg_dir']).st_mode & (
            stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)):
        raise InitializationException(
            "Directory %s cannot have 'other user' access permissions set." %
            config['gpg_dir'])


def parse_key_config_string(configuration_option, key_config_string):
    """Parses the e-mail:fingerprint format used in the application config file to specify
    e-mail/GPG key pairs.

    configuration_option: The name of the configuration option being parsed.
    key_config_string: The formatted string to parse.
    """
    key_split = key_config_string.split(':')

    if len(key_split) != 2:
        raise InitializationException(
            'Key config %s for %s does not contain a colon or is malformed.' %
            (key_config_string, configuration_option))

    if not key_split[0]:
        raise InitializationException(
            'Key config %s for %s is missing an e-mail address.' %
            (key_config_string, configuration_option))

    if not key_split[1]:
        raise InitializationException(
            'Key config %s for %s is missing a key fingerprint.' %
            (key_config_string, configuration_option))

    # TODO: Eventually verify e-mail format. (issue 34)
    key_dict = {'email': key_split[0].strip(),
                'fingerprint': key_split[1].strip()}

    return key_dict


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
    Returns True if there are no signing errors.  False otherwise.
    """
    # Clear the GPG agent cache so we can be sure that the supplied passphrase is the correct
    #   passphrase.
    clear_gpg_agent_cache()

    # TODO: Eventually, parse gpg output to notify that the password was wrong. (issue 47)
    success = False
    gpg = gnupg.GPG(gnupghome=gpg_home)

    signature_test_result = gpg.sign(
        "I've got a lovely bunch of coconuts.", detach=True, keyid=fingerprint,
        passphrase=passphrase)

    if str(signature_test_result).strip() == '':
        logger.debug("Signature test for %s failed. Check the sender key's passphrase.",
                     fingerprint)
    else:
        logger.info('Signature test for %s passed.', fingerprint)
        success = True

    return success


def clear_gpg_agent_cache():
    """ Clears the gpg-agent cache. """
    for process in psutil.process_iter(['create_time', 'name', 'pid', 'username']):
        if process.name() == 'gpg-agent' and process.username() == PROCESS_USERNAME:
            process.send_signal(signal.SIGHUP)


def check_sender_key(gpg_keyring, config, expiration_date):
    """Checks the sender GPG key in the config file and exits if it is missing from the key
    ring, untrusted, unsigned, or is not a 40-character hex string.  Also checks and stores
    whether the sender key can be used to sign messages.

    gpg_keyring: The GpgKeyring object in which to look for GPG keys.
    config: The config dict to read the sender GPG key information from.
    expiration_date: The date the singing key is validated to not expire through.
    """
    logger.info('Checking sender key for validity and expiration.')

    if not gpg_keyring.is_trusted(config['sender']['fingerprint']):
        raise InitializationException('Signing key is not ultimately trusted. Exiting.')

    elif not gpg_keyring.is_signed(config['sender']['fingerprint']):
        raise InitializationException('Signing key is not signed. Exiting.')

    elif not gpg_keyring.is_current(config['sender']['fingerprint'], expiration_date):
        formatted_expiration_date = datetime.datetime.fromtimestamp(
            gpg_keyring.get_key_expiration_date(
                config['sender']['fingerprint'])).strftime('%Y-%m-%d %H:%M:%S')
        logger.warning('Sender key expired on %s.', formatted_expiration_date)
        config['sender']['can_sign'] = False

    elif not signature_test(
            config['gpg_dir'], config['sender']['fingerprint'],
            config['sender']['password']):
        raise InitializationException('Sender key failed the signature test and the key is '
                                      "not expired. Check the sender key's passphrase.")

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
            raise InitializationException(
                'Key with fingerprint %s is not signed (and not sufficiently trusted). '
                'Exiting.' % recipient['fingerprint'])
        else:
            logger.debug('Recipient key with fingerprint %s is signed or ultimately '
                         'trusted.', recipient['fingerprint'])


def verify_signing_config(config):
    """Checks the sending GPG key and the program configuration to determine if sending
    unsigned e-mail is allowed.  Crashes if the sending key cannot sign and sending unsigned
    e-mail is disabled.

    config: The program config dictionary to read the key configuration from.
    """
    if not config['allow_expired_signing_key'] and not config['sender']['can_sign']:
        raise InitializationException(
            'The sender key with fingerprint %s can not sign and unsigned e-mail is not '
            'allowed. Exiting.' % config['sender']['fingerprint'])

    elif not config['sender']['can_sign']:
        logger.warning('The sender key is unable to sign because it has probably expired. '
                    'Gpgmailer will send unsigned messages.')

    else:
        logger.debug('Outgoing e-mails will be signed.')


def create_directory(system_path, program_dirs, uid, gid, mode):
    """Creates directories if they do not exist and sets the specified ownership and
    permissions.

    system_path: The system path that the directories should be created under. These are
      assumed to already exist. The ownership and permissions on these directories are not
      modified.
    program_dirs: A string representing additional directories that should be created under
      the system path that should take on the following ownership and permissions.
    uid: The system user ID that should own the directory.
    gid: The system group ID that should be associated with the directory.
    mode: The unix standard 'mode bits' that should be associated with the directory.
    """
    logger.info('Creating directory %s.', os.path.join(system_path, program_dirs))

    path = system_path
    for directory in program_dirs.strip('/').split('/'):
        path = os.path.join(path, directory)
        if not os.path.isdir(path):
            # Will throw exception if file cannot be created.
            os.makedirs(path, mode)
        os.chown(path, uid, gid)
        os.chmod(path, mode)


def check_if_mounted_as_ramdisk(pathname):
    """Checks if a directory is mounted as a ramdisk.

    pathname: The directory to check.
    Returns true if the directory is mounted as a ramdisk.  False otherwise.
    """
    return 'none on {0} type tmpfs'.format(pathname) in str(subprocess.check_output('mount'))


def create_spool_directories(use_ramdisk, program_uid, program_gid):
    """Mounts the program spool directory as a ramdisk and creates the partial and outbox
    subfolders. Exit if any part of this method fails.

    use_ramdisk: A boolean indicating whether to mount the spool directory as a ramdisk.
    program_uid: The system user ID that should own all the spool directories.
    program_gid: The system group ID that should be assigned to all the spool directories.
    """
    logger.info('Creating spool directories.')

    try:
        create_directory(
            SYSTEM_SPOOL_DIR, PROGRAM_NAME, program_uid, program_gid,
            # drwx--x--- gpgmailer gpgmailer
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IXGRP)
    except Exception as exception:
        logger.critical('Could not create program spool directory. %s: %s',
                        type(exception).__name__, str(exception))
        raise exception

    spool_dir = os.path.join(SYSTEM_SPOOL_DIR, PROGRAM_NAME)

    # TODO: Log a warning when use_ramdisk_spool is false and ramdisk exists. (issue 56)
    if use_ramdisk:
        # TODO: Use parkbenchcommon.ramdisk here. (issue 51)
        mounted_as_ramdisk = check_if_mounted_as_ramdisk(spool_dir)

        # If directory is not mounted as a ramdisk and there is something in the directory,
        #   log a warning.
        if os.listdir(spool_dir) != [] and not mounted_as_ramdisk:
            logger.warning('Program spool directory %s is configured to be a ramdisk, but '
                           'the directory is not empty and not already mounted as a '
                           'ramdisk.', spool_dir)

        # If the program spool directory is not already mounted as a ramdisk, mount it as a
        #   ramdisk.
        if not mounted_as_ramdisk:
            logger.info('Attempting to mount the program spool directory as a ramdisk.')
            subprocess.call(['mount', '-t', 'tmpfs', '-o', 'size=25%', 'none', spool_dir])

        if not check_if_mounted_as_ramdisk(spool_dir):
            raise InitializationException(
                'Program spool directory could not be mounted as a ramdisk. Startup failed.')

    try:
        # TODO: File Permissions Alone Should Be Enough to Protect Files In
        #   'partial' and 'outbox'. (issue 26)
        create_directory(
            spool_dir, PARTIAL_DIR, program_uid, program_gid,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP |
            stat.S_ISGID | stat.S_ISVTX)  # drwx-ws--T gpgmailer gpgmailer
        create_directory(
            spool_dir, OUTBOX_DIR, program_uid, program_gid,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP |
            stat.S_ISGID | stat.S_ISVTX)  # drwx-ws--T gpgmailer gpgmailer
    except Exception as exception:
        logger.critical('Could not create required spool sub-directories. %s: %s',
                        type(exception).__name__, str(exception))
        raise exception


def drop_permissions_forever(uid, gid):
    """Drops escalated permissions forever to the specified user and group.

    uid: The system user ID to drop to.
    gid: The system group ID to drop to.
    """
    logger.info('Dropping permissions for user %s.', PROCESS_USERNAME)
    os.initgroups(PROCESS_USERNAME, gid)
    os.setgid(gid)
    os.setuid(uid)


def send_expiration_warning_message(gpg_keyring, config, expiration_date):
    """If needed, queues a warning message about keys that have expired or will be expiring
    soon.

    gpg_keyring: The GpgKeyring object in which to look for GPG keys.
    config: The config dict to read sender and recipient GPG key information from.
    expiration_date: The date the singing key was validated to not expire through.
    Returns a GpgKeyVerifier object initalized with gpg_keyring and config.  This is used
      later.
    """
    gpg_key_verifier = gpgkeyverifier.GpgKeyVerifier(gpg_keyring, config)
    expiration_warning_message = gpg_key_verifier.get_expiration_warning_message(
        expiration_date)

    if expiration_warning_message is not None:
        logger.warning('Sending expiration warning message email.')
        # gpgmailer.py will prepend the actual warning message.
        message = 'Gpgmailer has just restarted.'
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
    logger.info('SIGTERM received. Quitting.')
    sys.exit(0)


def setup_daemon_context(log_file_handle, program_uid, program_gid):
    """Creates the daemon context. Specifies daemon permissions, PID file information, and
    the signal handler.

    log_file_handle: The file handle to the log file.
    program_uid: The system user ID that should own the daemon process.
    program_gid: The system group ID that should be assigned to the daemon process.
    Returns the daemon context.
    """
    daemon_context = daemon.DaemonContext(
        working_directory='/',
        pidfile=pidlockfile.PIDLockFile(
            os.path.join(SYSTEM_PID_DIR, PROGRAM_PID_DIRS, PID_FILE)),
        umask=PROGRAM_UMASK,
    )

    daemon_context.signal_map = {
        signal.SIGTERM: sig_term_handler,
    }

    daemon_context.files_preserve = [log_file_handle]

    # Set the UID and GID to 'gpgmailer' user and group.
    daemon_context.uid = program_uid
    daemon_context.gid = program_gid

    return daemon_context


def main():
    """The parent function for the entire program. It loads and verifies configuration,
    daemonizes, and starts the main program loop.
    """
    os.umask(PROGRAM_UMASK)
    program_uid, program_gid = get_user_and_group_ids()
    global logger
    config, config_helper, logger = read_configuration_and_create_logger(
        program_uid, program_gid)

    try:
        verify_safe_file_permissions(config, program_uid)

        parse_key_config(config)

        # Re-establish root permissions to create required directories.
        os.seteuid(os.getuid())
        os.setegid(os.getgid())

        # Non-root users cannot create files in /run, so create a directory that can be
        #   written to. Full access to user only.  drwx------ gpgmailer gpgmailer
        create_directory(SYSTEM_PID_DIR, PROGRAM_PID_DIRS, program_uid, program_gid,
                         stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # Do this relatively last because gpgmailmessage assumes the daemon has started if
        #   these directories exist.
        create_spool_directories(config['use_ramdisk_spool'], program_uid, program_gid)

        # Configuration has been read and directories setup. Now drop permissions forever.
        drop_permissions_forever(program_uid, program_gid)

        # Make sure the sender key isn't going to expire during the first loop iteration.
        expiration_date = time.time() + config['main_loop_duration']

        gpg_keyring = gpgkeyring.GpgKeyRing(config['gpg_dir'])
        check_sender_key(gpg_keyring, config, expiration_date)
        check_all_recipient_keys(gpg_keyring, config)
        verify_signing_config(config)

        # We do this here because we don't want to queue an e-mail if a configuration setting
        #   can cause the program to crash later. This is to avoid a lot of identical queued
        #   warning e-mails.
        gpg_key_verifier = send_expiration_warning_message(
            gpg_keyring, config, expiration_date)

        logger.info('Verification complete.')

        daemon_context = setup_daemon_context(
            config_helper.get_log_file_handle(), program_uid, program_gid)

        logger.debug('Initializing GpgMailer.')
        gpg_mailer = gpgmailer.GpgMailer(
            config, gpg_keyring, gpg_key_verifier, OUTBOX_PATHNAME)

        logger.info('Daemonizing...')
        with daemon_context:
            gpg_mailer.start_monitoring()

    except BaseException as exception:

        if isinstance(exception, Exception):
            logger.critical('Fatal %s: %s\n%s', type(exception).__name__, str(exception),
                            traceback.format_exc())

        # Kill the gpg-agent owned by gpgmailer because otherwise systemd will think
        #   gpgmailer is still running because gpg-agent is keeping the CGroup alive.
        for process in psutil.process_iter(['create_time', 'name', 'pid', 'username']):
            if process.name() == 'gpg-agent' and process.username() == PROCESS_USERNAME:
                process.kill()

        raise exception

if __name__ == "__main__":
    main()
