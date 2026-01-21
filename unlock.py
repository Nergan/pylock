from sys import argv
from hashlib import sha256
from base64 import urlsafe_b64encode
from os import system
from os.path import isdir

from cryptography.fernet import Fernet, InvalidToken

from mylib import aniinp, aniprint


# strip > encode > sha256 > urlsafe_b64encode > digest > [:32]
def format_key(key_string: str) -> Fernet:
    key_bytes = key_string.strip().encode()
    key_hash = sha256(key_bytes).digest()[:32]
    fernet_key = urlsafe_b64encode(key_hash)
    return Fernet(fernet_key)


def processfile(filename: str, key: Fernet) -> None:
    system(f'attrib -h -s -r {filename}')
    system(f'attrib -h -s -r {__file__}')
            
    with open(filename, encoding='utf-8') as file:
        txt = file.read().encode()
    decrypt = key.decrypt(txt).decode() # decryption itself
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(decrypt)
    aniprint(f'the contents of the file {filename} are successfully decrypted...')
    
    system(filename)
    
    with open(filename, encoding='utf-8') as file:
        txt = file.read().encode()
    encrypt = key.encrypt(txt).decode() # encryption itself
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(encrypt)
    aniprint('...and encrypted back')
    
    system(f'attrib +h +s +r {filename}')
    system(f'attrib +h +s +r {__file__}')


def main():
    isoneuse = False
    if len(argv) > 1:
        if len(argv) !=  3:
            aniprint('error: invalid argument input')
            aniprint('example: <file> <key>')
            return
        else:
            isoneuse = True
    
    while True:
        try:
            filename = argv[1] if isoneuse else aniinp('filename: ')
            key = format_key(argv[2] if isoneuse else aniinp('key: '))
            processfile(filename, key)
        except FileNotFoundError:
            aniprint(f'error: file {filename} not found')
        except PermissionError:
            if isdir(filename):
                aniprint(f'error: {filename} is a folder, not a file')
            else:
                aniprint(f'error: no access rights to {filename}')
        except InvalidToken:
            aniprint(f'error: invalid key for file {filename}')
        except UnicodeError:
            aniprint(f'error: could not read file encoding {filename}')
        except KeyboardInterrupt:
            aniprint('\nquit...')
            return
        
        if isoneuse:
            return
        
        print()
    
    
if __name__ == '__main__':
    main()