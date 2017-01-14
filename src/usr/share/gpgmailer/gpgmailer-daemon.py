#!/usr/bin/env python2

# Copyright 2015 Joel Allen Luellwitz and Andrew Klapp
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
import logging
import mailermonitor
import os
from daemon import pidlockfile
import signal
import subprocess
import sys
import traceback

PID_FILE = '/run/gpgmailer.pid'

# After first commit
# TODO: Clean up logging
# TODO: Clean up method names
# TODO: Consider making this a class somehow.

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

config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')
config['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
config['smtp_user'] = config_helper.verify_string_exists(config_file, 'smtp_user')
config['smtp_pass'] = config_helper.verify_password_exists(config_file, 'smtp_pass')  # Note this is a password!
config['smtp_server'] = config_helper.verify_string_exists(config_file, 'smtp_server')
config['smtp_port'] = config_helper.verify_string_exists(config_file, 'smtp_port')
config['smtp_max_idle'] = config_helper.verify_string_exists(config_file, 'smtp_max_idle')
config['smtp_sending_timeout'] = config_helper.verify_string_exists(config_file, 'smtp_sending_timeout')

# Mount the parent watch directory as a ramdisk and create the draft and outbox subfolders.
# Exit if any part of this operation fails.
pathname = os.path.normpath(config['watch_dir'])

def check_if_mounted(path):
   return 'none on {0} type tmpfs'.format(path) in subprocess.check_output('mount')

if os.path.isdir(pathname) == False:
   os.makedirs(pathname)

if os.listdir(pathname) == [] and check_if_mounted(pathname) == False:
   logger.info("Attempting to mount the path as a ramdisk.")
   subprocess.call(['mount', '-t', 'tmpfs', '-o', 'size=25%', 'none', pathname])

if check_if_mounted(pathname) == False:
   logger.critical("Path was not mounted as a ramdisk. Startup failed.")
   sys.exit(1)

if os.path.isdir(os.path.join(pathname, 'outbox')) == False:
   os.makedirs(os.path.join(pathname, 'outbox'))
if os.path.isdir(os.path.join(pathname, 'draft')) == False:
   os.makedirs(os.path.join(pathname, 'draft'))

if os.path.isdir(os.path.join(pathname, 'outbox')) == False or os.path.isdir(os.path.join(pathname, 'draft')) == False:
   logger.critical("Could not create required sub-directories. Startup failed.")
   sys.exit(1)

# init gnupg so we can verify keys
config['gpg'] = gnupg.GPG(gnupghome=config['gpg_dir'])
keylist = config['gpg'].list_keys()

def gpg_fingerprint_exists(gpg_keyring, fingerprint_string):
    # gpg_keyring needs to be a list of dicts from the gnupg module's list_keys method
    # fingerprint_string must be a full 40 char fingerprint
    for key in gpg_keyring:
        if(key['fingerprint'] == fingerprint_string):
            return True
    return False

# parse sender config.  <email>:<key fingerprint>
sender_raw = config_helper.verify_string_exists(config_file, 'sender')
sender_split = sender_raw.split(':')
if( len(sender_split[1]) != 40 ):
    logger.critical('Sender key fingerprint is invalid')
    sys.exit(1)
else:
    if(gpg_fingerprint_exists(keylist, sender_split[1].strip())):
        signing_key_password = config_helper.verify_password_exists(config_file, 'signing_key_password')
        config['sender'] = { 'email' : sender_split[0], 'fingerprint' : sender_split[1],
        'key_password' : signing_key_password }
    else:
        logger.critical('Sender key not found in keyring.')
        sys.exit(1)

# parse recipient config.  Comma-delimited list of objects like sender
# <email>:<key fingerprint>,<email>:<key fingerprint>
config['recipients'] = []

recipients_raw = config_helper.verify_string_exists(config_file, 'recipients')
recipients_split = recipients_raw.split(',')
for r in recipients_split:
    r_split = r.split(':')
    if( len(r_split[1].strip()) != 40 ):
        logger.critical('Recipient key fingerprint for %s is invalid.' % r_split[0])
        sys.exit(1)
    else:
        if(gpg_fingerprint_exists(keylist, r_split[1].strip())):
            r_dict = { 'email' : r_split[0].strip(), 'fingerprint' : r_split[1].strip() }
            config['recipients'].append(r_dict)
        else:
            logger.critical('Recipient key fingerprint for %s not in keyring.' % r_split[0])
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

with daemon_context:
    try:
        the_watcher = mailermonitor.mailer_monitor(config)
        the_watcher.start_monitoring()

    except Exception as e:
        logger.critical("Fatal %s: %s\n" % (type(e).__name__, e.message))
        logger.error(traceback.format_exc())
        sys.exit(1)
