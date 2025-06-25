import os
import hashlib

def get_file_extension(filepath):
    return os.path.splitext(filepath)[1].lower()

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest() 