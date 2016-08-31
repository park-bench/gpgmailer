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
import gpgkey
import lockfile
import mailermonitor
import os
import signal
import sys
import timber
import traceback

PID_FILE = '/var/opt/run/gpgmailer.pid'

# After first commit
# TODO: Clean up logging
# TODO: Clean up method names
# TODO: Consider making this a class somehow.

print('Loading configuration.')
config_file = ConfigParser.RawConfigParser()
config_file.read('/etc/opt/gpgmailer/gpgmailer.conf')

# Figure out the logging options so that can start before anything else.
print('Verifying configuration.')
config_helper = confighelper.ConfigHelper()
log_file = config_helper.verify_string_exists_prelogging(config_file, 'log_file')
log_level = config_helper.verify_string_exists_prelogging(config_file, 'log_level')

logger = timber.get_instance_with_filename(log_file, log_level)

logger.info('Verifying non-logging config')
config = {}

config['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
config['smtp_user'] = config_helper.verify_string_exists(config_file, 'smtp_user')
config['smtp_pass'] = config_helper.verify_password_exists(config_file, 'smtp_pass')  # Note this is a password!
config['smtp_server'] = config_helper.verify_string_exists(config_file, 'smtp_server')
config['smtp_port'] = config_helper.verify_string_exists(config_file, 'smtp_port')
config['smtp_max_idle'] = config_helper.verify_string_exists(config_file, 'smtp_max_idle')
config['smtp_sending_timeout'] = config_helper.verify_string_exists(config_file, 'smtp_sending_timeout')
# Convert the key expiration threshhold into seconds because expiry dates are
#   stored in unix time.
config['expiration_warning_threshold'] = config_helper.verify_number_exists(config_file, 'expiration_warning_threshold') * 86400

config['key_checking_interval'] = config_helper.verify_number_exists(config_file, 'key_checking_interval')

# init gnupg so we can verify keys
gpg_dir = config_helper.verify_string_exists(config_file, 'gpg_dir')
config['gpg'] = gnupg.GPG(gnupghome=gpg_dir)
keylist = gpgkey.build_key_hash_dict(config['gpg'].list_keys())

# parse sender config.  <email>:<key fingerprint>
sender_key_string = config_helper.verify_string_exists(config_file, 'sender')
sender_key_password = config_helper.verify_password_exists(config_file, 'signing_key_password')
sender_key = gpgkey.GpgKey(keylist, sender_key_string, config['expiration_warning_threshold'], password=sender_key_password)
if sender_key.valid:
    logger.info('Using sender %s' % sender_key.email)
    config['sender'] = sender_key
else:
    logger.fatal('Sender key not available or invalid. Exiting.')
    sys.exit(1)

# parse recipient config.  Comma-delimited list of objects like sender
# <email>:<key fingerprint>,<email>:<key fingerprint>
config['recipients'] = []
recipients_raw_string = config_helper.verify_string_exists(config_file, 'recipients')
recipients_raw_list = recipients_raw_string.split(',')
for recipient in recipients_raw_list:
    recipient_key = gpgkey.GpgKey(keylist, recipient, config['expiration_warning_threshold'])
    if recipient_key.fingerprint:
        logger.info('Adding recipient key for %s.' % recipient_key.email)
        config['recipients'].append(recipient_key)
    else:
        # TODO: The remaining users should be notified of this via e-mail if this occurs.
        logger.error('Recipient key for %s not available.' % recipient)

if config['recipients'] == []:
    logger.fatal('No valid recipients. Exiting.')
    sys.exit(1)
    
logger.info('Verification complete')

# Quit when SIGTERM is received
def sig_term_handler(signal, stack_frame):
    logger.info("Quitting.")
    sys.exit(0)

# TODO: Work out a permissions setup for gpgmailer so that it doesn't run as root.
daemon_context = daemon.DaemonContext(
    working_directory = '/',
    pidfile = lockfile.FileLock(PID_FILE),
    umask = 0
    )

# TODO: Make a real cleanup method for this.
daemon_context.signal_map = {
    signal.SIGTERM : sig_term_handler
    }

with daemon_context:
    try:
        the_watcher = mailermonitor.mailer_monitor(config)
        the_watcher.start_monitoring()

    except Exception as e:
        logger.fatal("Fatal %s: %s\n%s" % (type(e).__name__, e.message, traceback.format_exc()))
        sys.exit(1)
