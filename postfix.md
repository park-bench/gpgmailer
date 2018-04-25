# Configuring postfix as a simple SMTP relay

## Installation
You will need to make sure the following packages are installed:
* libsasl2-2
* libsasl2-modules
* mailutils
`sudo apt install libsasl2-2 libsasl2-modules mailutils`

Install the `postfix` package with apt: `sudo apt install postfix`.

If it is already installed, reconfigure it with `sudo dpkg-reconfigure postfix`.

There will be several prompts for configuration options. The first is a general
configuration category, choose `Sattelite system`. It will also ask for an SMTP relay host
name, which should be your provider's server.


## Configuration
