import os
import subprocess


def public_keys(keyhome):
    cmd = [
        '/usr/bin/gpg',
        '--homedir',
        keyhome,
        '--list-keys',
        '--with-colons',
    ]
    with subprocess.Popen(
            cmd,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
    ) as p:
        p.wait()
        keys = list()

        for line in p.stdout.readlines():
            if line[0:3] == 'uid' or line[0:3] == 'pub':
                if ('<' not in line or '>' not in line):
                    continue
                key = line.split('<')[1].split('>')[0]
                if keys.count(key) == 0:
                    keys.append(key)

    return keys


class GPGEncryptor:

    def __init__(self, keyhome, recipients=None, charset=None):
        self._keyhome = keyhome
        self._message = ''
        self._recipients = list()
        self._charset = charset
        if recipients is not None:
            self._recipients.extend(recipients)

    def update(self, message):
        self._message += message

    def encrypt(self):
        with subprocess.Popen(
                self._command(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
        ) as p:
            encdata = p.communicate(input=self._message.encode())[0]
        return encdata

    def _command(self):
        cmd = [
            "/usr/bin/gpg",
            "--trust-model",
            "-a",
            "-e",
            "always",
            "--homedir",
            self._keyhome,
            "--batch",
            "--yes",
            "--pgp7",
            "--no-secmem-warning",
        ]

        # add recipients
        for recipient in self._recipients:
            cmd.append("-r")
            cmd.append(recipient)

        # add on the charset, if set
        if self._charset:
            cmd.append("--comment")
            cmd.append('Charset: ' + self._charset)

        return cmd
