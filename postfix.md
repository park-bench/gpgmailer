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
name, which should be your provider's server. In this example, we will be using Gmail.


## Configuration
First, write the authentication details in a file. create the file`/etc/postfix/sasl_passwd`
and add this line:
`[smtp.gmail.com]:587 <username>:<password>`

Make that file only readable to root:
`sudo chmod 400 /etc/postfix/sasl_passwd`

Then tell postfix to use it:
`sudo postmap /etc/postfix/sasl_passwd`

Copy an appropriate CA cert to `/etc/postfix/cacert.pem`:
`sudo cp /etc/ssl/certs/thawte_Primary_Root_CA.pem /etc/postfix/cacert.pem`

Add the following lines to `/etc/postfix/main.cf`:
```
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/postfix/cacert.pem
smtp_use_tls = yes
```
`relayhost` may already exist.

Restart the Postfix daemon and then test it.
`sudo systemctl restart postfix`
`echo "test email body" | mail -s "test subject" <recipient email>`

TODO: This is for a default Postfix setup. We want to disable using the `mail` command and
use plaintext SMTP authentication on only the loopback interface.
