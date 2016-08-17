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
import gnupg
import mailermonitor
import os
import re
import signal
import sys
import timber
import traceback

PID_FILE = '/var/opt/run/gpgmailer.pid'

key_fingerprint_regex = re.compile('^[0-9a-fA-F]{40}$')

# After first commit
# TODO: Make daemonize() a library
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

config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')
config['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
config['smtp_user'] = config_helper.verify_string_exists(config_file, 'smtp_user')
config['smtp_pass'] = config_helper.verify_password_exists(config_file, 'smtp_pass')  # Note this is a password!
config['smtp_server'] = config_helper.verify_string_exists(config_file, 'smtp_server')
config['smtp_port'] = config_helper.verify_string_exists(config_file, 'smtp_port')
config['smtp_max_idle'] = config_helper.verify_string_exists(config_file, 'smtp_max_idle')
config['smtp_sending_timeout'] = config_helper.verify_string_exists(config_file, 'smtp_sending_timeout')
# Convert the key expiration threshhold into seconds because expiry dates are
#   stored in epoch time.
config['key_expiration_threshhold'] = config_helper.verify_number_exists(config_file, 'key_expiration_threshhold') * 86400

# init gnupg so we can verify keys
config['gpg'] = gnupg.GPG(gnupghome=config['gpg_dir'])
keylist = {}

for key in config['gpg'].list_keys():
    keylist[key['fingerprint']] = key['expires']

# Returns a dict containing the fingerprint and expiration date of a single key
#   by searching for its' fingerprint in the keyring.
def get_gpg_key_data(gpg_keyring, fingerprint_string):
    # Check that fingerprint_string is exactly 40 characters
    key_data = None
    if key_fingerprint_regex.match(fingerprint_string):
        if fingerprint_string in keylist:
            key_data = { 'fingerprint': fingerprint_string,
                'expires': keylist[fingerprint_string] }
        else:
            logger.error('Fingerprint %s not found in keyring.' % fingerprint_string)
    else:
        logger.error('Fingerprint %s is invalid.' % fingerprint_string)

    return key_data

# Parses the key strings from the config file. They should be formatted this way:
#   <email><:key fingerprint>
#   Also checks key validity.
def parse_key_config_data(key_config_string):
    key_data = None
    key_config_string_split = key_config_string.split(':')
    key_data = get_gpg_key_data(keylist, key_config_string_split[1].strip())
    if key_data:
        key_data['email'] = key_config_string_split[0].strip()

    return key_data

# parse sender config.  <email>:<key fingerprint>
sender_key_data = parse_key_config_data(config_helper.verify_string_exists(config_file, 'sender'))
if sender_key_data != None:
    logger.info('Using sender %s' % sender_key_data['email'])
    sender_key_data['key_password'] = config_helper.verify_password_exists(config_file, 'signing_key_password')
    config['sender'] = sender_key_data
else:
    logger.fatal('Sender key not available. Exiting.')
    sys.exit(1)

# parse recipient config.  Comma-delimited list of objects like sender
# <email>:<key fingerprint>,<email>:<key fingerprint>
config['recipients'] = []
recipients_raw_string = config_helper.verify_string_exists(config_file, 'recipients')
recipients_raw_list = recipients_raw_string.split(',')
for recipient in recipients_raw_list:
    recipient_key_data = parse_key_config_data(recipient)
    if recipient_key_data != None:
        logger.info('Adding recipient key for %s.' % recipient_key_data['email'])
        config['recipients'].append(recipient_key_data)
    else:
        # TODO: The remaining users should be notified of this via e-mail if this occurs.
        logger.error('Recipient key for %s not available.' % email_string)

if config['recipients'] == []:
    logger.fatal('No valid recipients. Exiting.')
    sys.exit(1)
    
logger.info('Verification complete')

def daemonize():
    # Fork the first time to make init our parent.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e: 
        logger.fatal("Failed to make parent process init: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    os.chdir("/")  # Change the working directory
    os.setsid()  # Create a new process session.
    os.umask(0)

    # Fork the second time to make sure the process is not a session leader. 
    #   This apparently prevents us from taking control of a TTY.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        logger.fatal("Failed to give up session leadership: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, sys.stdin.fileno())
    os.dup2(devnull, sys.stdout.fileno())
    os.dup2(devnull, sys.stderr.fileno())
    os.close(devnull)

    pid = str(os.getpid())
    pidFile = file(PID_FILE,'w')
    pidFile.write("%s\n" % pid)
    pidFile.close()

daemonize()

# Quit when SIGTERM is received
def sig_term_handler(signal, stack_frame):
    logger.info("Quitting.")
    sys.exit(0)

signal.signal(signal.SIGTERM, sig_term_handler)

try:
    the_watcher = mailermonitor.mailer_monitor(config)
    the_watcher.start_monitoring()  

except Exception as e:
    logger.fatal("Fatal %s: %s\n" % (type(e).__name__, e.message))
    logger.error(traceback.format_exc())
    sys.exit(1)
