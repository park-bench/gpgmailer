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
import mailermonitor
import os
import signal
import sys
import timber
import traceback

PID_FILE = '/var/opt/run/gpgmailer.pid'

# After first commit
# TODO: Make daemonize() a library
# TODO: Clean up logging
# TODO: Clean up method names
# TODO: Add a password to secret key and a config option for it

print('Loading configuration.')
config_file = ConfigParser.SafeConfigParser()
config_file.read('/etc/opt/gpgmailer/gpgmailer.conf')

# Figure out the logging options so that can start before anything else.
print('Verifying configuration.')
config_helper = confighelper.ConfigHelper()
log_file = config_helper.verify_string_exists_prelogging(config_file, 'log_file')
log_level = config_helper.verify_string_exists_prelogging(config_file, 'log_level')

logger = timber.get_instance_with_filename(log_file, log_level)

logger.trace('Verifying non-logging config')
config = {}

config['gpg_dir'] = config_helper.verify_string_exists(config_file, 'gpg_dir')
config['watch_dir'] = config_helper.verify_string_exists(config_file, 'watch_dir')
config['smtp_user'] = config_helper.verify_string_exists(config_file, 'smtp_user')
config['smtp_pass'] = config_helper.verify_password_exists(config_file, 'smtp_pass')  # Note this is a password!
config['smtp_server'] = config_helper.verify_string_exists(config_file, 'smtp_server')
config['smtp_port'] = config_helper.verify_string_exists(config_file, 'smtp_port')
config['smtp_max_idle'] = config_helper.verify_string_exists(config_file, 'smtp_max_idle')
config['smtp_sending_timeout'] = config_helper.verify_string_exists(config_file, 'smtp_sending_timeout')

# TODO: Verify that keys actually exist becuase the gpg module will fail silently
# 	if they do not.
# parse sender config.  <email>:<key fingerprint>
sender_raw = config_helper.verify_string_exists(config_file, 'sender')
sender_split = sender_raw.split(':')
if( len(sender_split[1]) != 40 ):
    logger.fatal('Sender key fingerprint is invalid')
    sys.exit(1)
else:
    config['sender'] = { 'email' : sender_split[0], 'fingerprint' : sender_split[1] }

# parse recipient config.  Comma-delimited list of objects like sender
# <email>:<key fingerprint>,<email>:<key fingerprint>
config['recipients'] = []

recipients_raw = config_helper.verify_string_exists(config_file, 'recipients')
recipients_split = recipients_raw.split(',')
for r in recipients_split:
    r_split = r.split(':')
    if( len(r_split[1].strip()) != 40 ):
        logger.fatal('Recipient key fingerprint for %s is invalid.' % r_split[0] )
        sys.exit(1)
    else:
        r_dict = { 'email' : r_split[0].strip(), 'fingerprint' : r_split[1].strip() }
        config['recipients'].append(r_dict)

logger.info('Verification complete')

def daemonize():
    # Fork the first time to make init our parent.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e: 
        logger.trace("Failed to make parent process init: %d (%s)" % (e.errno, e.strerror))
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
        logger.trace("Failed to give up session leadership: %d (%s)" % (e.errno, e.strerror))
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
    logger.trace("Quitting.")
    sys.exit(0)

signal.signal(signal.SIGTERM, sig_term_handler)

try:
    the_watcher = mailermonitor.mailer_monitor(config)
    the_watcher.start_monitoring()  

except Exception as e:
    logger.trace("Fatal %s: %s\n" % (type(e).__name__, e.message))
    logger.trace(traceback.format_exc())
    sys.exit(1)
