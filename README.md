# gpgmailer

_gpgmailer_ is a daemon that sends GnuPG signed and encrypted e-mails. E-mails are queued via
an included Python API.

gpgmailer is licensed under the GNU GPLv3.

This is software is still in _beta_ and may not be ready for use in a production environment.

Bug fixes are welcome!

## Prerequisites

Currently, the only supported method for installation of this project is building and
installing a Debian package. The rest of these instructions make the following assumptions:

*   Your server is running Ubuntu 18.04 LTS. (Other operating systems may work, but are not
    supported.)
*   `build-essential` is installed on your build server.
*   `devscripts` is installed on your build server.
*   You are already familiar with using a Linux terminal.
*   You are familiar with using `git` and GitHub.
*   You already know how to use GnuPG.
*   You are already somewhat familiar with using `debuild`.
*   A local MTA is installed that provides `mail-transfer-agent`, as the majority of them do.
    If you don't have a preference, we have a short, basic guide for Postfix
    [here](./postfix.md).

## Parkbench Dependencies

_gpgmailer_ depends on one other Parkbench project which must be installed first:
* [_parkbench-common_](https://github.com/park-bench/confighelper)

## Steps to Build and Install

1.  Clone the repository and checkout the latest release tag. (Do not build against the
    `master` branch. The `master` branch might not be stable.)
2.  Use `debuild` in the project root directory to build the package.
3.  Run `apt install /path/to/package.deb` to install the package. The daemon will attempt to
    start and fail. (This is expected.)
4.  Create a GPG keyring at the location specified in
    `/etc/gpgmailer/gpgmailer.conf.example`. (Run `gpg` with the `--homedir` option.) It is
    recommended that you __do not__ use the GPG keyring in your home directory.
5.  Import or generate a sender PGP key. This key must have a verified signature and be
    ultimately trusted.
6.  Import and sign the PGP public keys of all the recipients. (If you did this out of order
    or need to sign keys later, you may have to use the option `--pinentry-mode=loopback`.)
7.  Copy or rename the example configuration file `/etc/gpgmailer/gpgmailer.conf.example` to
    `/etc/gpgmailer/gpgmailer.conf`. Edit this file to enter the sender and recipient
    information and the sender GPG passphrase. Other settings can also be modified.
8.  Use `chown` to __recurrsively__ change the ownership of the GPG keyring to the
    `gpgmailer` user.
9.  Use `chmod` to clear the _other user_ permissions bits of `gpgmailer.conf` and the GPG
    keyring directory. Namely, remove read, write, and execute permissions for _other_.
10. To ease system maintenance, add `gpgmailer` as a supplemental group to administrative
    users. Doing this will allow these users to view gpgmailer log files.
11. Restart the daemon with `systemctl restart gpgmailer`. If the configuration file and GPG
    keyring are valid, named correctly, and have the correct file permissions, the service
    will start successfully.

## Updates

Updates may change configuration file options. So if you have a configuration file already,
check the current example file to make sure it has all the required options.

## Known Errors and Limitations

*   No support for checking GPG subkey expiration. All subkeys are assumed to expire at the
    same time as their parent keys.
