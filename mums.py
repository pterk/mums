#!/usr/bin/env python3
"""Simple encrypted enviroment variables

Inspired by ansible's vault but simpler and with fewer dependencies
(though not as featureful), mums encrypts environment variables to a
file that you can store in your repository. The only thing you *have
to* keep a secret ("mum's the word") is the keyfile.

A keyfile can be any kind of textfile, its content is used as a
(hashed) password. By default is uses ~/.ssh/id_rsa but that is not
advisable in a team environment. Whatever it is though, don't store it
in the repository.

I like to keep the confs in a directory, in this case I called it .mums:

    $ mkdir .mums
    $ mums .mums/prod store DATABASE_URK "postgres://username:password@hostname:5432/dbname"
    $ mums .mums/prod show
    DATABASE_URK=postgres://username:password@hostname:5432/dbname
    $ mums .mums/prod run -- env | grep DATABASE
    DATABASE_URK=postgres://username:password@hostname:5432/dbname

Look like I made a typo. Let's add another key:

    $ mums .mums/prod store DATABASE_URL "postgres://username:password@hostname:5432/dbname"
    $ mums .mums/prod run -- env | grep DATABASE
    DATABASE_URK=postgres://username:password@hostname:5432/dbname
    DATABASE_URL=postgres://username:password@hostname:5432/dbname

Verify that is not in the environment by default:

    $ env | grep DATABASE # shows no output

Let's remove that typo:

    $ mums .mums/prod remove DATABASE_URK
    $ mums .mums/prod show
    DATABASE_URL=postgres://username:password@hostname:5432/dbname

To avoid typing too much I create a little shell-script 'prod' (or 'dev'):

    #!/usr/bin/env bash
    if [ $# -eq 0 ]
       then
       echo "No arguments supplied";
       exit 1;
    fi
    mums .mums/prod run -- "$@"

Then prefix any command with the desired environment name

    $ chmod 755 prod
    $ ./prod env | grep DATABASE

"""
import getpass
import hashlib
import io
import json
import os
import random
import struct
import subprocess
import sys

from Crypto.Cipher import AES
from Crypto import Random

import click


class Config(object):
    def __init__(self):
        self.path = None
        self.key = get_key(os.path.expanduser("~/.ssh/id_rsa"))

pass_config = click.make_pass_decorator(Config, ensure=True)


@click.group()
@pass_config
@click.option('--key-file', type=click.File("r"))
@click.argument('mumfile')
def cli(config, key_file, mumfile):
    config.path = mumfile
    if key_file:
        f = open(key_file.name, 'r')
        config.key = f.read()
        f.close()


def get_key(keyfile):
    return open(keyfile).read()
    #return getpass.getpass("Password: ")


def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


def check_please(iv, plaintext):
    return hashlib.sha256(
        (
            str(iv) + hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
        ).encode("utf-8")
    ).digest()


# The encryption / decryption idea come from this blogpost:
# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
def encrypt_file(key, plaintext, out_filename, chunksize=24*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        plaintext:
            The data to be encrypted

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    key = hashlib.sha256(key.encode("utf-8")).digest()
    iv = Random.new().read(16)
    check = check_please(iv, plaintext)

    encryptor = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    filesize = len(plaintext)

    with open(out_filename, 'wb') as outfile:
        # The header: the filesize, the 'vector', 
        # a hash of the 'vector' and the hash of the content
        outfile.write(struct.pack('<Q', filesize))
        outfile.write(iv)
        outfile.write(check)

        for chunk in chunkstring(plaintext, chunksize):
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += ' ' * (16 - len(chunk) % 16)
            outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    key = hashlib.sha256(key.encode("utf-8")).digest()
    out = io.BytesIO()
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        check = infile.read(32)
        decryptor = AES.new(key, mode=AES.MODE_CBC, IV=iv)
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            out.write(decryptor.decrypt(chunk))
        out.truncate(origsize)
        out.seek(0)

    plaintext = out.read().decode("utf-8")
    if check != check_please(iv, plaintext):
        raise Exception("Content not equal")
    return plaintext


def test():
    import shutil
    import tempfile
    d = {
        "Key1": "Value1",
        "Key2": "Value2",
        "Key3": "Value3",
        "Key4": "Value4",
        "Key5": ["12345", "67890"],
        "Key6": ["AAAAA", "BBBBB"],
    }
    tempdir = tempfile.mkdtemp()
    tempfilename = os.path.join(tempdir, "test-vault.enc")
    encrypt_file(
        "TEST",
        json.dumps(d),
        tempfilename)
    result = decrypt_file(
        "TEST",
        tempfilename)
    shutil.rmtree(tempdir)
    assert(json.loads(result) == d)


def _load(config):
    if os.path.exists(config.path):
        try:
            data = json.loads(decrypt_file(config.key, config.path))
        except UnicodeDecodeError:
            raise Exception("Failed to load from vault")
    else:
        data = {}
    return data


@cli.command()
@pass_config
def show(config):
    """Show the name, value pairs stored in the environment"""
    data =_load(config)
    for k,v in data.items():
        click.echo("{}={}".format(k, v))


@cli.command()
@click.argument("name")
@click.argument("value")
@pass_config
def store(config, name, value):
    """NAME VALUE Store the name, value in the environment"""
    data = _load(config)
    data[name] = value
    encrypt_file(config.key, json.dumps(data), config.path)


@cli.command()
@click.argument('name')
@pass_config
def remove(config, name):
    """NAME \t Remove the variable with the given name from the environment"""
    data = _load(config)
    data.pop(name)
    encrypt_file(config.key, json.dumps(data), config.path)


@cli.command()
@click.argument('args', nargs=-1)
@pass_config
def run(config, args):
    """-- CMD [OPTIONS] [ARGUMENTS] run the command with the given environment"""
    data =_load(config)
    for k, v in data.items():
        os.environ[k] = v
    subprocess.call(args, env=os.environ)


"""
if __name__ == '__main__':
    if sys.argv[1] == 'test':
        test()

    if sys.argv[1] == 'store':
        path = sys.argv[2]
        name = sys.argv[3]
        value = sys.argv[4]
        store(path, name, value)

    if sys.argv[1] == 'env':
        path = sys.argv[2]
        env(path)

    if sys.argv[1] == 'remove':
        path = sys.argv[2]
        name = sys.argv[3]
        remove(path, name)

    if sys.argv[1] == 'load':
        path = sys.argv[2]
        args = sys.argv[3:]
        load(path, args)
"""
