# gpgmailer

_gpgmailer_ is a daemon that sends GnuPG signed and encrypted e-mails. E-mails are queued via
an included Python API.

gpgmailer is licensed under the GNU GPLv3.

This software is still in _beta_ and may not be ready for use in a production environment.

Bug fixes are welcome!

## Prerequisites

This software is currently only supported on Ubuntu 18.04.

Currently, the only supported method for installation of this project is building and
installing a Debian package. The rest of these instructions make the following assumptions:

*   You are familiar with using a Linux terminal.
*   You are somewhat familiar with using `debuild`.
*   You are familiar with using `git` and GitHub.
*   `debhelper` and `devscripts` are installed on your build server.
*   You are familiar with GnuPG.
*   A local MTA is installed that provides `mail-transfer-agent`, as the majority of them do.
    If you don't have a preference, we have a short, basic guide for Postfix
    [here](./postfix.md).

## Parkbench Dependencies

gpgmailer depends on one other Parkbench package, which must be installed first:

*   [parkbench-common](https://github.com/park-bench/parkbench-common)

## Steps to Build and Install

1.  Clone the repository and checkout the latest release tag. (Do not build against the
    `master` branch. The `master` branch might not be stable.)
2.  Run `debuild` in the project root directory to build the package.
3.  Run `apt install /path/to/package.deb` to install the package. The daemon will attempt to
    start and fail. (This is expected.)
4.  Copy or rename the example configuration file `/etc/gpgmailer/gpgmailer.conf.example` to
    `/etc/gpgmailer/gpgmailer.conf`.
5.  Change the ownership and permissions of the configuration file:
```
chown root:gpgmailer /etc/gpgmailer/gpgmailer.conf
chmod u=rw,g=r,o= /etc/gpgmailer/gpgmailer.conf
```
6.  Create a GPG keyring at the location specified in
    `/etc/gpgmailer/gpgmailer.conf`. (Run `gpg` with the `--homedir` option.) It is
    recommended that you __do not__ use the GPG keyring in your home directory.
7.  Import or generate a sender PGP key. This key must have a verified signature and be
    ultimately trusted.
8.  __Recursively__ change the ownership and permissions of the GPG keyring:
```
chown -R gpgmailer:gpgmailer /path/to/gpg/keyring
chmod -R u=rwX,g=rX,o= /path/to/gpg/keyring
```
9.  Edit the `/etc/gpgmailer/gpgmailer.conf` file to enter the sender and recipient
    information and the sender GPG passphrase. Other settings can also be modified.
10. To ease system maintenance, add `gpgmailer` as a supplemental group to administrative
    users. Doing this will allow these users to view gpgmailer log files.
11. Restart the daemon with `systemctl restart gpgmailer`. If the configuration file and GPG
    keyring are valid, named correctly, and have the correct file permissions, the service
    will start successfully.

## Updates

Updates may change configuration file options. If a configuration file already exists, check
that it has all of the required options from the current example file.

## Known Errors and Limitations

*   No support for checking GPG subkey expiration. All subkeys are assumed to expire at the
    same time as their parent keys.
