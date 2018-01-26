# pwcrypt project

This project is less intended to be a wrapper for gpg, and more about learning how logging, command-line arguments, and functions work in python.

TESTED ON: osx 10.13.2 using python 3.6

## Requirements:

You must have gpg installed and configured on your local machine

## Configuration

To set the pwcrypt home directory, edit line 181:

   *pwcryptHome = os.path.abspath('**</path/to/pwcrypt home directory>**')*  


The initial directory structure will be created the first time you run the script:

- **bin** - Location of the pwcrypt script

- **backups** - Location of encrypted backup files. By default, retention is set to keep the last two backups

- **logs** - Location of log files. Optional verbose logging can be set.

- **vaults** - Optional location to store encrypted files.


NOTE: The script expects to be located in a bin directory, and checks that it exists in one. By design, the other directories are generated relative to that bin directory:
	i.e. ~/pwcrypt/bin

## Usage
```
usage: pwcrypt [-h] [-d] [-e] [-f FILE] [-o OUTPUT] [-r RECIPIENT] [-v] [-V]

pwcrypt manages a gpg encrypted password file, logs activity, backups
encrypted file

optional arguments:
  -h, --help            show this help message and exit
  -d, --decrypt         Decrypt password file
  -e, --encrypt         Encrypt password file
  -f FILE, --file FILE  Designate a file to encrypt/decrypt
  -o OUTPUT, --output OUTPUT
                        Designate an output file
  -r RECIPIENT, --recipient RECIPIENT
                        Designate a recipient for gpg
  -v, --version         Show current version
  -V, --verbose         Set logging level to debug
```
