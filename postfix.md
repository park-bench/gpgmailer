# Configuring Postfix as a simple SMTP relay

## Installation
Install the `postfix` and `libsasl2-modules` packages with apt: `sudo apt install postfix libsasl2-modules`.

If Postfix is already installed, reconfigure it with `sudo dpkg-reconfigure postfix`.

There will be several prompts for configuration options. The first is a general
configuration category, choose `Sattelite system`. It will also ask for an SMTP relay host
name, which should be your provider's server. In this example, we will be using Gmail.


## Configuration
First, write the authentication details in a file. Create the file `/etc/postfix/sasl_passwd`
and add this line:
`[smtp.gmail.com]:587 <username>:<password>`

Make the sasl_passwd file only readable to root:
`sudo chmod 400 /etc/postfix/sasl_passwd`

Then tell Postfix to use it:
`sudo postmap /etc/postfix/sasl_passwd`

Copy a CA certificate that can be used to verify your SMTP host's SSL certificate to
`/etc/postfix/cacert.pem`:

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
`relayhost` should already exist.

Restart the Postfix daemon and then test it.
`sudo systemctl restart postfix`
`echo "test email body" | mail -s "test subject" <recipient email>`

After verifying that Postfix works, it should be secured against unauthorized users by
changing which users can send via `sendmail` or `mail`. To block all users but root, edit
`/etc/postfix/main.cf` and add the line:
```
authorized_submit_users = root
```

If you do not want to leak your system's hostname, you can set one in `main.cf`.
```
myhostname = desired_hostname
```

Postfix has configuration options for exponential backoff to prevent being treated as spam.
This project prioritizes speed, and recommends overriding some of the default options in
`main.cf`:
```
queue_run_delay=1s
minimal_backoff_time=1s
maximal_backoff_time=10m
maximal_queue_lifetime=520w
```
