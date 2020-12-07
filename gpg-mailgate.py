#!/usr/bin/python3

import email
import email.message
import smtplib
import sys
import syslog
from configparser import RawConfigParser
from email.mime.base import MIMEBase

import GnuPG

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()

for sect in _cfg.sections():
    cfg[sect] = dict()
    for (name, value) in _cfg.items(sect):
        cfg[sect][name] = value


def log(msg):
    if 'logging' in cfg and 'file' in cfg['logging']:
        if cfg['logging']['file'] == 'syslog':
            syslog.syslog(syslog.LOG_INFO | syslog.LOG_MAIL, msg)
        else:
            logfile = open(cfg['logging']['file'], 'a')
            logfile.write(msg + '\n')
            logfile.close()


verbose = ('logging' in cfg and 'verbose' in cfg['logging'] and cfg['logging']['verbose'] == 'yes')

if verbose:
    log('Config: %s' % cfg)

# Read e-mail from stdin
raw = sys.stdin.read()
raw_message = email.message_from_string(raw)
from_addr = raw_message['From']
to_addrs = sys.argv[1:]


def send_msg(message, recipients=None):
    if recipients is None:
        recipients = to_addrs

    log('Sending email to: <%s>' % '> <'.join(recipients))
    relay = (cfg['relay']['host'], int(cfg['relay']['port']))
    smtp = smtplib.SMTP(relay[0], relay[1])
    smtp.sendmail(from_addr, recipients, message.as_string())


def encrypt_payload(payload):
    raw_payload = payload.get_payload()

    if ('-----BEGIN PGP MESSAGE-----' in raw_payload and '-----END PGP MESSAGE-----' in raw_payload):
        return payload

    gpg = GnuPG.GPGEncryptor(cfg['gpg']['keyhome'], gpg_to_cmdline, payload.get_content_charset())
    gpg.update(raw_payload)
    payload.set_payload(gpg.encrypt()[0])

    is_attachment = (payload.get_param('attachment', None, 'Content-Disposition') is not None)

    if is_attachment:
        filename = payload.get_filename()

        if filename:
            gpg_filename = filename + '.gpg'

            if payload.get('Content-Disposition') is not None:
                payload.set_param('filename', gpg_filename, 'Content-Disposition')

            if payload.get('Content-Type') is not None:
                if payload.get_param('name') is not None:
                    payload.set_param('name', gpg_filename)

    if payload.get('Content-Transfer-Encoding') is not None:
        payload.replace_header('Content-Transfer-Encoding', '7bit')

    return payload


def encrypt_all_payloads(message):
    encrypted_payloads = list()

    if isinstance(message.get_payload(), str):
        return encrypt_payload(message).get_payload()

    for payload in message.get_payload():
        if isinstance(payload.get_payload(), list):
            encrypted_payloads.extend(encrypt_all_payloads(payload))
        else:
            encrypted_payloads.append(encrypt_payload(payload))

    return encrypted_payloads


def get_msg(message):
    if not message.is_multipart():
        return message.get_payload()
    return '\n\n'.join([str(m) for m in message.get_payload()])


keys = GnuPG.public_keys(cfg['gpg']['keyhome'])
gpg_to = list()
ungpg_to = list()

if raw_message.is_multipart():
    # If email is a multipart email like multipart/alternative do not encrypt the
    # email as the email cannot not be decrypted anymore.
    log('Not encrypting multipart messages')
    send_msg(raw_message)
    sys.exit()

for to in to_addrs:
    if to in keys and not ('keymap_only' in cfg['default'] and cfg['default']['keymap_only'] == 'yes'):
        gpg_to.append((to, to))
    elif 'keymap' in cfg and to in cfg['keymap']:
        gpg_to.append((to, cfg['keymap'][to]))
    else:
        if verbose:
            log('Recipient (%s) not in domain list.' % to)
        ungpg_to.append(to)

if gpg_to == list():
    # Setting a header may be usefull for debugging purposes.
    if ('add_header' in cfg['default'] and cfg['default']['add_header'] == 'yes'):
        raw_message['X-GPG-Mailgate'] = 'Not encrypted, public key not found'

    if verbose:
        log('No encrypted recipients.')

    send_msg(raw_message)
    sys.exit()

if ungpg_to != list():
    send_msg(raw_message, ungpg_to)

log('Encrypting email to: %s' % ' '.join(map(lambda x: x[0], gpg_to)))

if ('add_header' in cfg['default'] and cfg['default']['add_header'] == 'yes'):
    raw_message['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

gpg_to_cmdline = list()
gpg_to_smtp = list()

for rcpt in gpg_to:
    gpg_to_smtp.append(rcpt[0])
    gpg_to_cmdline.extend(rcpt[1].split(','))

raw_message.set_payload(encrypt_all_payloads(raw_message))
send_msg(raw_message, gpg_to_smtp)
