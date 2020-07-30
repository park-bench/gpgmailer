# Configuring Postfix as a simple SMTP relay

This guide is for new postfix users. If you know what you are doing, please feel free to
supply your own values.

## Installation
Install the `postfix` and `libsasl2-modules` packages with apt: `sudo apt install postfix
libsasl2-modules`.

If Postfix is already installed, reconfigure it with `sudo dpkg-reconfigure postfix`.

There will be several prompts for configuration options. When asked for a general
configuration category, choose `Sattelite system`. Leave the rest of the values as
their defaults.

## Configuration
First, create the authentication credentials file:
`touch /etc/postfix/sasl_passwd`

Make the sasl_passwd file only accessible to root:
`sudo chmod u=rw,g=,o= /etc/postfix/sasl_passwd`

Add your authentication credentials to the `/etc/postfix/sasl_passwd` file. Replace
smtp.gmail.com and 587 with your mailserver's connection information:
`[smtp.gmail.com]:587 <username>:<password>`

Tell postfix to use the credentials file:
`sudo postmap /etc/postfix/sasl_passwd`

Add the following lines to `/etc/postfix/main.cf`. Remove the existing `relayhost` option.
Replace smtp.gmail.com and 587 with your mailserver's SMTP connection information. Also,
change the root certificate to one that will work with your mailserver:
```
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/thawte_Primary_Root_CA.pem
smtp_use_tls = yes
```

To test your configuration, run the following replacing "sender address" and "recipient
address". Sender address probably has to match the e-mail account being used to send mail.:
`sudo systemctl restart postfix`
`echo "testing" | sendmail -f '<sender address>' -v '<recipient address>'`

After verifying that you received the e-mail, postfix should be secured against unauthorized
users by changing which users can send via `sendmail` or `mail`. To block all users except
root and gpgmailer, edit `/etc/postfix/main.cf` and add the line:
```
authorized_submit_users = root,gpgmailer
```

If you do not want to leak your system's hostname, replace the default in
`/etc/postfix/main.cf`:
```
myhostname = desired-hostname
```

Postfix has configuration options for exponential backoff to prevent from being flagged as a
malicious client. Speed is of the utmost importance to Parkbench users, so we recommend the
following `/etc/postfix/main.cf` backoff configuration:
```
queue_run_delay=1s
minimal_backoff_time=1s
maximal_backoff_time=10m
maximal_queue_lifetime=8640000s
```

After you are done making configuraton changes, restart postfix one more time:
`sudo systemctl restart postfix`
