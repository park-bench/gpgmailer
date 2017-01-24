# gpgmailer

gpgmailer is a daemon that sends mail signed and encrypted using GnuPG.  It
reads mail from files containing JSON objects and handles arbitrary
attachments.

Depends on our ConfigHelper library which can be found at
https://github.com/park-bench/confighelper

gpgmailer is licensed under the GNU GPLv3.

Bug fixes are welcome.

This software is currently only supported on Ubuntu 14.04 and may not be ready
for use in a production environment.

The only current method of installation for our software is building ad
installing your own package. We make the following assumptions:
* You are already familiar with using a Linux terminal.
* You already know how to use GnuPG.
* You are already somewhat familiar with using debuild.

Clone the latest *release tag*, not the `master` branch, as `master` may not be
stable.  Build the package with `debuild` from the project directory and
install with `dpkg -i`. Resolve any missing dependencies with `apt-get -f
install`. The daemon will attempt to start and fail.

Updates may change configuration file options, so if you have a configuration
file already, check that it has all of the required options in the current 
example file.

## Post-install 
Copy the example configuration file in /etc/gpgmailer to 
/etc/gpgmailer/gpgmailer.conf and make any necessary changes to it.

Create a keyring at the location specified in gpgmailer.conf. It will be
read from and written to by root, so don't use your home directory's keyring.

Use `gnupg` with the shell variable `GNUPGHOME` set to the location of your new
keyring and import a sender and all recipient keys and set them all to at least
marginal trust.
