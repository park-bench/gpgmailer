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
import logging
import os
from daemon import pidlockfile
import signal
import sys
import traceback

PID_FILE = '/run/gpgmailer.pid'

# After first commit
# TODO: Clean up logging

def build_key_dict(key_config_string, gpgkeyring):
    final_key_dict = None
    key_config_list = key_config_string.split(':')

    key_dict = {}
    key_dict['fingerprint'] = key_config_list[1].strip()
    key_dict['email'] = key_config_list[0].strip()

    if not gpgkeyring.set_key_email(key_dict['fingerprint'], key_dict['email']):
        key_dict = {}

    return key_dict

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

config['key_database_reload_interval'] = config_helper.verify_number_exists(config_file, 'key_database_reload_interval')

if(config_helper.verify_string_exists(config_file, 'send_unsigned_messages').lower() == 'true'):
    config['send_unsigned_messages'] = True
else:
    config['send_unsigned_messages'] = False

# init gnupg so we can verify keys
config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')

# Parse and check keys.

gpgkeyring = gpgkeyring.GpgKeyRing(config['gpg_dir'])

# parse sender config.  <email>:<key fingerprint>
sender_key_string = config_helper.verify_string_exists(config_file, 'sender')
sender_key_password = config_helper.verify_password_exists(config_file, 'signing_key_password')

sender_key = build_key_dict(sender_key_string, gpgkeyring)

if not(sender_key == {}):
    logger.info('Using sender %s' % sender_key['email'])
    sender_key['password'] = sender_key_password
    config['sender'] = sender_key
else:
    logger.critical('Sender key not defined or not in keyring. Exiting.')
    sys.exit(1)

# The signing key should always be present and trusted.
if not(gpgkeyring.is_trusted(sender_key['fingerprint']):
    logger.critical('Signing key is not trusted. Exiting.');
    sys.exit(1)

if not(gpgkeyring.is_expired(sender_key['fingerprint'])):
    signing_key_expired = False

if not config['send_unsigned_messages']:
    # Check signing key
    logger.info('send_unsigned_messages is not enabled, checking signing key.')

    if signing_key_expired:
        # Log critical error and quit
        logger.critical('Sender key expired. Exiting.')
        sys.exit(1)


# parse recipient config.  Comma-delimited list of objects like sender
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
        # TODO: The remaining users should be notified of this via e-mail if this occurs.
        logger.error('Recipient key for %s not available or invalid.' % recipient)


if config['recipients'] == []:
    logger.critical('No valid recipients. Exiting.')
    sys.exit(1)
    
logger.info('Verification complete')

# Quit when SIGTERM is received
def sig_term_handler(signal, stack_frame):
    logger.info("Quitting.")
    sys.exit(0)

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

daemon_context.files_preserve = [config_helper.get_log_file_handle()]

logger.debug('Daemonizing')
with daemon_context:
    try:
        logger.info('Starting GpgMailer.')
        the_watcher = gpgmailer.GpgMailer(config, gpgkeyring)
        the_watcher.start_monitoring(config['watch_dir'])

    except Exception as e:
        logger.critical("Fatal %s: %s\n%s" % (type(e).__name__, e.message, traceback.format_exc()))
        sys.exit(1)
