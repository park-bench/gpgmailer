# gpgmailer

_gpgmailer_ is a daemon that sends mail signed and encrypted using GnuPG.  It reads mail from files containing JSON objects and handles arbitrary attachments.

gpgmailer is licensed under the GNU GPLv3.

Bug fixes are welcome!

## Prerequisites

This software is currently only supported on Ubuntu 14.04 and may not be ready for use in a production environment.

The only current method of installation for our software is building and installing your own debian package. We make the following assumptions:

* You are already familiar with using a Linux terminal.
* You already know how to use GnuPG.
* You are already somewhat familiar with using debuild.
* `build-essential` is installed.
* `devscripts` is installed.
* An MTA that replaces `sendmail` is installed and configured. If you don't have
a preference, we have a short, basic guide for Postfix
[here](./postfix.md).

## Parkbench Dependencies

_gpgmailer_ depends on one other piece of the Parkbench project, which must be installed first:

* [_confighelper_](https://github.com/park-bench/confighelper)

## Steps to Build and Install

1.   Clone the latest release tag. (Do not clone the master branch. `master` may not be stable.)
2.   Use `debuild` in the project root directory to build the package.
3.   Use `dpkg -i` to install the package.
4.   Use `apt-get -f install` to resolve any missing dependencies. The daemon will attempt to start and fail. (This is expected.)
5.   Locate the example configuration file at `/etc/gpgmailer/gpgmailer.conf.example`. Copy or rename this file to `gpgmailer.conf` in the same directory. Edit this file to change any configuration details.
6.   Create a keyring at the location specified in gpgmailer.conf. It will be read from and written to by root, so DO NOT use your home directory's keyring.
7.   Use `gpg` with the option `--homedir` set to the location of your new keyring. Import a sender and all recipient keys and set them all to at least marginal trust.
8.   Restart the daemon with `service gpgmailer restart`. If the configuration file and keyring are set up correctly, the service will now start successfully.

## Updates

Updates may change configuration file options, so if you have a configuration file already, check that it has all of the required options in the current example file.

## Known Errors and Limitations

* No support for checking GPG subkey expiration. All subkeys are assumed to expire at the same time as their parent keys.
* No exponential backoff while attempting to connect to the e-mail server.
