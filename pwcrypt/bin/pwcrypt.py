#!/usr/local/bin/python3
#=======================================#
# pwcrypt.py version 1.0
# Written By: penguingeek
#=======================================#
import argparse
import time
import os
import sys
import string
import logging

def verify_pwcrypt_dir(pwcryptHome, pwcryptBin, pwcryptLog, pwcryptBackup, pwcryptVaults):
    # Check if .pwcrypt directory structure exists
    # If a directory doesn't exist, create it
    print('Checking .pwcrypt directory structure...')
    dirs = [pwcryptHome, pwcryptBin, pwcryptLog, pwcryptBackup, pwcryptVaults]
    for d in dirs:
        try:
            os.stat(d)
        except:
            os.mkdir(d)

def checkUnencrypted(unencryptedFile, rawUnencrypted):
    # verify file exists
    if os.path.exists(unencryptedFile) == True:
        logging.getLogger("cryptLog.verified").debug('    - Exists')
        # Verify file is not empty
        if os.stat(unencryptedFile).st_size > 0:
            print(rawUnencrypted + ' exists and is not empty')
            logging.getLogger("cryptLog.verified").debug('    - Not empty')
            unencryptedVerified_status = 'True'
            return unencryptedVerified_status
        else:
            print('ERROR: ' + rawUnencrypted + ' is an empty file')
            logging.getLogger("cryptLog.verified").error('    - ERROR: ' + rawUnencrypted + ' is an empty file')
            sys.exit()
    else:
        print(unencryptedFile + ' does not exist')
        logging.getLogger("cryptLog.verified").debug('    - Does not exist')
        unencryptedVerified_status = 'False'
        return unencryptedVerified_status

def checkEncrypted(encryptedFile, rawEncrypted):
    # Verify file exists
    if  os.path.exists(encryptedFile) == True:
        logging.getLogger("cryptLog.verified").debug('    - Exists')
        # Verify file is gpg encrypted
        if encryptedFile.lower().endswith('.gpg') == True:
            print(rawEncrypted + ' is encypted')
            logging.getLogger("cryptLog.verified").debug('    - Encypted') 
            encryptedVerified_status = 'True'
            return encryptedVerified_status
        else:
            print(rawEncrypted + ' is not encrypted')
            logging.getLogger("cryptLog.verified").debug('    - Not encrypted')
            encryptedVerified_status = 'False'
            return encryptedVerified_status
    else:
        print(encryptedFile + ' does not exist')
        logging.getLogger("cryptLog.verified").debug('    - ' + encryptedFile + ' does not exist')
        encryptedVerified_status = 'False'
        return encryptedVerified_status

def delete(deleteMe):
    # Confirm user is ready to remove existing encrypted file
    rawDeleteMe = os.path.split(deleteMe)
    remove = input('Are you sure you want to delete ' + rawDeleteMe[1] + '? (y/n): ')
    if remove == 'y':
        logging.getLogger("cryptLog.delete").info('  DELETING EXISTING ENCRYPTED FILE: ' + rawDeleteMe[1])
        os.system('rm -rf ' + deleteMe)
        logging.getLogger("cryptLog.delete").debug('   - ' + rawDeleteMe[1] + ' successfully deleted')
    elif remove == 'n':
        logging.getLogger("cryptLog.delete").info('  User exited without deleting')
        sys.exit()
    else:
        print('Please answer y or n.')
        delete(deleteMe)

def sorted_ls(pwcryptBackup):
    mtime = lambda f: os.stat(os.path.join(pwcryptBackup, f)).st_mtime
    return list(sorted(os.listdir(pwcryptBackup), key=mtime))

def archiver(encryptedFile, rawEncrypted, pwcryptHome, pwcryptBackup):
    logging.getLogger("cryptLog.encryptor").info('  ARCHIVING EXISTING ENCRYPTED FILE: ' + rawEncrypted)
    # Backup existing encrypted file with current date
    timestr = time.strftime("%Y%m%d-%H%M%S")
    filename = os.path.split(encryptedFile)
    backupName = filename[1] + '_' + timestr
    logging.getLogger("cryptLog.backup").info('    - Archive File: ' + backupName)
    os.system('cp ' + encryptedFile + ' ' + pwcryptBackup + backupName)

    # remove old backups (keep last 2)
    max_Files = 2

    logging.getLogger("cryptLog.backups").debug('    - Rotating backup files')    
    del_list = sorted_ls(pwcryptBackup)[0:(len(sorted_ls(pwcryptBackup))-max_Files)]
    for dfile in del_list:
        os.remove(pwcryptBackup + dfile)

    return backupName

def decryptMe(unencryptedFile, encryptedFile, rawEncrypted):
    decrypt = input('Do you want to decrypt ' + rawEncrypted + '? (y/n): ')
    if decrypt == 'y':
        logging.getLogger("cryptLog.decryptMe").info('  DECRYPTING: ' + rawEncrypted)
        os.system("gpg --output " + unencryptedFile + " --decrypt " + encryptedFile)
        print(unencryptedFile + ' is ready for editing')
        logging.getLogger("cryptLog.decryptMe").debug('    - ' + rawEncrypted + ' successfully decrypted')
        sys.exit()
    elif decrypt == 'n':
        logging.getLogger("cryptLog.decryptMe").info('  User exited without decrypting')
        sys.exit()
    else:
        print('Please answer y or n.')
        decryptMe(unencryptedFile, encryptedFile, rawEncrypted)

def encryptMe(unencryptedFile, rawUnencrypted, encryptedFile, rawEncrypted, recipient, pwcryptHome, pwcryptBackup):
    # Confirm user is ready to encrypt file
    encrypt = input('Are you ready to encrypt ' + rawUnencrypted + '? (y/n): ')
    if encrypt == 'y':
        logging.getLogger("cryptLog.encryptor").info('  ENCRYPTING FILE: ' + rawUnencrypted)
        os.system('gpg --output ' + encryptedFile + ' --encrypt --recipient ' + recipient + ' ' + unencryptedFile)
        print(unencryptedFile + ' successfully encrypted')
        logging.getLogger("cryptLog.encryptor").debug('    - ' + rawUnencrypted + ' successfully encrypted')
        logging.getLogger("cryptLog.encryptor").info('  DELETING UNENCRYPTED FILE: ' + rawUnencrypted)
        os.system('rm -rf ' + unencryptedFile)
        logging.getLogger("cryptLog.encryptor").debug('    - ' + rawUnencrypted + ' successfully deleted')
    elif encrypt == 'n':
        logging.getLogger("cryptLog.encryptor").info('  User exited without encrypting')
        sys.exit()
    else:
        print('Please answer y or n.')
        encryptMe(unencryptedFile, rawUnencrypted, encryptedFile, rawEncrypted, recipient, pwcryptHome, pwcryptBackup)

def pwDecryptor(unencryptedFile, rawUnencrypted, encryptedFile, rawEncrypted, pwcryptHome):
    logging.getLogger("cryptLog.decryptor").info('==== DECRYPTION REQUEST ====')
    
    # Verify encrypted file status
    logging.getLogger("cryptLog.decryptor").info('  VERIFYING ENCRYPTED FILE: ' + encryptedFile)
    verifyEncrypted = checkEncrypted(encryptedFile, rawEncrypted)
    if verifyEncrypted == 'True':

        # Verify unencrytped file status
        logging.getLogger("cryptLog.decryptor").info('  VERIFYING OUTPUT FILE: ' + unencryptedFile)
        verifyUnencrypted = checkUnencrypted(unencryptedFile, rawUnencrypted)
        if str(verifyUnencrypted) == True:
            print(rawUnencrypt + ' is already decrypted!')
            logging.getLogger("cryptLog.decryptor").debug('    - ' + unencryptedFile + ' is already decrypted!')
            sys.exit()
        else:
            #decrypt = input('Do you want to decrypt ' + rawEncrypted + '? (y/n): ')
            #if decrypt == 'y':
            #    logging.getLogger("cryptLog").info('  DECRYPTING: ' + rawEncrypted)
            #    os.system("gpg --output " + unencryptedFile + " --decrypt " + encryptedFile)
            #    print(unencryptedFile + ' is ready for editing')
            #    logging.getLogger("cryptLog.decrypt").debug('    - ' + rawEncrypted + ' successfully decrypted')
            #    sys.exit()
            #elif decrypt == 'n':
            #    logging.getLogger("cryptLog.decrypt").info('  User exited without decrypting')
            #    sys.exit()
            #else:
            #    print('Please answer y or n.')

            decryptMe(unencryptedFile, encryptedFile, rawEncrypted)
    else:
        logging.getLogger("cryptLog.decrypt").debug('  ERROR: ' + rawEncrypted + ' does not exist. Maybe try restoring from latest backup?')

def pwEncryptor(unencryptedFile, rawUnencrypted, encryptedFile, rawEncrypted, recipient, pwcryptHome, pwcryptBackup):
    logging.getLogger("cryptLog.decryptor").info('==== ENCRYPTION REQUEST ====')

    # Verify unencrypted file status
    logging.getLogger("cryptLog.encryptor").info('  VERIFYING UNENCRYPTED FILE: ' + unencryptedFile)
    verifyUnencrypted = checkUnencrypted(unencryptedFile, rawUnencrypted)
    if str(verifyUnencrypted) == 'True':

        # Verify encrypted file status
        logging.getLogger("cryptLog.encryptor").info('  VERIFYING OUTPUT FILE: ' + encryptedFile)
        verifyEncrypted = checkEncrypted(encryptedFile, rawEncrypted)
        if str(verifyEncrypted) == 'True':

            # Backup existing encrypted file      
            archiver(encryptedFile, rawEncrypted, pwcryptHome, pwcryptBackup)

            # Removing existing encrypted file
            deleteMe = encryptedFile
            delete(deleteMe)

        # Confirm user is ready to encrypt file
        encryptMe(unencryptedFile, rawUnencrypted, encryptedFile, rawEncrypted, recipient, pwcryptHome, pwcryptBackup)

def main():
    # Locations
    pwcryptHome = os.path.abspath('/path/to/pwcrypt home directory')
    pwcryptBin = os.path.join(pwcryptHome, 'bin/')
    pwcryptBackup = os.path.join(pwcryptHome, 'backups/')
    pwcryptVaults = os.path.join(pwcryptHome, 'vaults/')
    pwcryptLog = os.path.join(pwcryptHome, 'logs')
    pwcryptLogfile = os.path.join(pwcryptLog, 'pwcrypt.log')

    verify_pwcrypt_dir(pwcryptHome, pwcryptBin, pwcryptLog, pwcryptBackup, pwcryptVaults)

    # Logging
    logging.getLogger("cryptLog").setLevel(logging.INFO)
    logging.basicConfig(
        filename=pwcryptLogfile,
        format="%(asctime)s:[%(levelname)-5.5s]:%(message)s"
    )

    # Arguments
    pwcrypt_description = 'pwcrypt manages a gpg encrypted password file, logs activity, backups encrypted file'

    parser = argparse.ArgumentParser(prog='pwcrypt',description=pwcrypt_description)
    parser.add_argument("-d", "--decrypt", help="Decrypt password file", action="store_true")
    parser.add_argument("-e", "--encrypt", help="Encrypt password file", action="store_true")
    parser.add_argument("-f", "--file", help="Designate a file to encrypt/decrypt", type=str)
    parser.add_argument("-o", "--output", help="Designate an output file", type=str)
    parser.add_argument("-r", "--recipient", help="Designate a recipient for gpg", type=str)
    parser.add_argument("-v", "--version", help="Show current version", action="store_true")
    parser.add_argument("-V", "--verbose", help="Set logging level to debug", action="store_true")
    args = parser.parse_args()
   
    if args.decrypt:
        encryptedFile = str(args.file)
        encryptedSplit = os.path.split(encryptedFile)
        rawEncrypted = encryptedSplit[1]
        unencryptedFile = str(args.output)
        unencryptedSplit = os.path.split(unencryptedFile)
        rawUnencrypted = unencryptedSplit[1]
        if args.verbose:
             logging.getLogger("cryptLog").setLevel(logging.DEBUG)
        pwDecryptor(unencryptedFile, rawUnencrypted, encryptedFile, rawEncrypted, pwcryptHome)
    elif args.encrypt:
        encryptedFile = str(args.output)
        encryptedSplit = os.path.split(encryptedFile)
        rawEncrypted = encryptedSplit[1]
        unencryptedFile = str(args.file)
        unencryptedSplit = os.path.split(unencryptedFile)
        rawUnencrypted = unencryptedSplit[1]
        recipient = str(args.recipient)
        if args.verbose:
             logging.getLogger("cryptLog").setLevel(logging.DEBUG)
        pwEncryptor(unencryptedFile, rawUnencrypted, encryptedFile, rawEncrypted, recipient, pwcryptHome, pwcryptBackup)
    elif args.version:
        print('pwcrypt: version 1.0')


if __name__ == "__main__":
    main()
