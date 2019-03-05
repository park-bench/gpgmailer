# gpgmailer

_gpgmailer_ is a daemon that sends GnuPG signed and encrypted e-mails. E-mails are queued via
an included Python API.

gpgmailer is licensed under the GNU GPLv3.

This software is still in _beta_ and may not be ready for use in a production environment.

Bug fixes are welcome!

## Prerequisites
This software is currently only supported in Ubuntu 18.04.

The only current method of installation for our software is building and installing your own
debian package. We make the following assumptions:

*   You are familiar with using a Linux terminal.
*   You are somewhat familiar with using `debuild`.
*   `debhelper` is installed.
*   You are familiar with GnuPG.

## Parkbench Dependencies

_gpgmailer_ depends on one other Parkbench project which must be installed first:

1.  [_confighelper_](https://github.com/park-bench/confighelper)

## Steps to Build and Install

1.  Clone the repository and checkout the latest release tag. (Do not build against the
    `master` branch. The `master` branch might not be stable.)
2.  Use `debuild` in the project root directory to build the package.
3.  Use `dpkg -i` to install the package.
4.  Run `apt-get -f install` to resolve any missing dependencies. The daemon will attempt to
    start and fail. (This is expected.)

## Post-install configuration

### GnuPG configuration
1.  Create a GPG keyring at the location specified in `gpgmailer.conf`. (Run `gpg` with the
    `--homedir` option.) It is recommended that you __do not__ use the GPG keyring in your
    home directory.
2.  Import or generate a sender PGP key. This key must have a verified signature and be
    ultimately trusted.
3.  Import the PGP public keys of all the recipients.

### Configuration file

1.  Copy or rename the example configuration file `/etc/gpgmailer/gpgmailer.conf.example` to
    `/etc/gpgmailer/gpgmailer.conf`. Edit this file to enter the SMTP server, sender, and
    recipient information and GPG passphrase. Other settings can also be modified.
2.  Change the ownership and permissions of the configuration file:
```
chown root:gpgmailer /etc/gpgmailer/gpgmailer.conf
chmod u=rw,g=r,o= /etc/gpgmailer/gpgmailer.conf
```

3.  __Recursively__ change the ownership and permissions of the GPG keyring. In this example,
the keyring is at `/etc/gpgmailer/gnupg`:
```
chown -R root:gpgmailer /etc/gpgmailer/gnupg
chmod -R u=rw,g=r,o= /etc/gpgmailer/gpgmailer.conf
```
4. To ease system maintenance, add `gpgmailer` as a supplemental group to administrative
    users. Doing this will allow these users to view gpgmailer log files.
5. Restart the daemon with `systemctl restart gpgmailer`. If the configuration file and GPG
    keyring are valid, named correctly, and have the correct file permissions, the service
    will start successfully.

## Updates

Updates may change configuration file options. So if you have a configuration file already,
check the current example file to make sure it has all the required options.

## Known Errors and Limitations

*   No support for checking GPG subkey expiration. All subkeys are assumed to expire at the
    same time as their parent keys.
*   No exponential backoff while failing to connect to the SMTP server.
