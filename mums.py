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
import argparse
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


def get_key(keyfile):
    key = None
    with open(keyfile, 'r') as f:
        key = f.read()
    return key
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


def _load(args):
    if os.path.exists(args.path):
        try:
            data = json.loads(decrypt_file(get_key(args.key_file), args.path))
        except UnicodeDecodeError:
            raise Exception("Failed to load from vault")
    else:
        data = {}
    return data


def show(args):
    """Show the name, value pairs stored in the environment"""
    data =_load(args)
    for k,v in data.items():
        print("{}={}".format(k, v))


def store(args):
    """NAME VALUE Store the name, value in the environment"""
    data = _load(args)
    data[args.name] = args.value
    encrypt_file(get_key(args.key_file), json.dumps(data), args.path)


def remove(args):
    """NAME \t Remove the variable with the given name from the environment"""
    data = _load(args)
    data.pop(args.name)
    encrypt_file(get_key(args.key_file), json.dumps(data), args.path)


def run(args):
    """-- CMD [OPTIONS] [ARGUMENTS] run the command with the given environment"""
    data =_load(args)
    for k, v in data.items():
        os.environ[k] = v
    cmd = args.cmd
    if cmd[0] == '--':
        cmd = cmd[1:]
    subprocess.call(cmd, env=os.environ)


parser = argparse.ArgumentParser()
parser.add_argument('path')
parser.add_argument('--key-file', default=os.path.expanduser("~/.ssh/id_rsa"))
subparsers = parser.add_subparsers()

show_parser = subparsers.add_parser('show')
show_parser.set_defaults(func=show)

store_parser = subparsers.add_parser('store')
store_parser.add_argument('name')
store_parser.add_argument('value')
store_parser.set_defaults(func=store)

remove_parser = subparsers.add_parser('remove')
remove_parser.add_argument('name')
remove_parser.set_defaults(func=remove)

run_parser = subparsers.add_parser('run')
run_parser.add_argument('cmd', nargs=argparse.REMAINDER)
run_parser.set_defaults(func=run)


def mums():
    try:
        args = parser.parse_args()
        args.func(args)  # call the default function
    except (AttributeError, IndexError):
        parser.print_usage()
        sys.exit(1)


if __name__ == '__main__':
    mums()
