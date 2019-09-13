import argparse
import gnupg
import os
import hashlib


def get_fname_gpg(fname):
    return fname+".gpg"

def get_fname_md5(fname):
    return fname+".md5"

def calculate_md5(fname):
    if not os.path.exists(fname): raise Exception("Specified file '{}' does not exist".format(fname))
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    md5sum_ = hash_md5.hexdigest()
    md5_file = open(get_fname_md5(fname),"w")
    md5_file.write(md5sum_)
    md5_file.close()


parser = argparse.ArgumentParser(description='Encrypt files with the EGA public key.')
parser.add_argument('--files', nargs='+', help='specify the files to be encrypted.')

args = parser.parse_args()

gpg = gnupg.GPG(homedir="./")
key_data = open('ega.asc', 'rb').read()
import_result = gpg.import_keys(key_data)
public_keys = gpg.list_keys()
fingerprint = public_keys[0]['fingerprint']

paths = getattr(args,'files')

for path in paths:
    print('Processing file : ' + path)
    calculate_md5(path)

    encryptedpath = get_fname_gpg(path)

    with open(path, 'r') as f:
        newfile = f.read()

    status = gpg.encrypt(newfile, fingerprint, output=encryptedpath)

    print('status.ok : ' + str(status.ok))
    print('status.status : ' + str(status.status))

    calculate_md5(encryptedpath)
