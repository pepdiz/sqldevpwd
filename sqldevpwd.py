#!/usr/bin/env python3
import json
import os
import argparse
import base64
import hashlib
from Cryptodome.Cipher import AES

VERSION="1.1"

def decryptpwd(encryptedpwd, decryptionkey):
    b64pwd = base64.b64decode(encryptedpwd)
    iv, pwd = b64pwd[:16], b64pwd[16:]    
    
    key = hashlib.pbkdf2_hmac("sha256", decryptionkey.encode(), b'\x06\xb6a#=h2\xb8', 5000)
    
    try:
        crypter = AES.new(key, AES.MODE_CBC, iv)
        dpwd = crypter.decrypt(pwd)
        decrypted = dpwd[:-dpwd[-1]].decode('utf-8')      
    except:
        decrypted = '**ERROR** decrypting'
    
    return decrypted


def main():
    parser = argparse.ArgumentParser(description='Prints to stdout decrypted passwords for connections in a SQL Developer 19.2+ export file in json format')
    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    parser.add_argument('--headers', action='store_true',
                help="show headers at first line of output")
    parser.add_argument('-d', '--delim', default=' ',
                help="column separator, just one character")    
    parser.add_argument("-k", dest="decryptkey", required=True,
                help="key to decrypt passwords, usually the export file encryption key or value of 'db.system.id' attribute in 'product-preferences.xml' file")
    parser.add_argument("jsonfile", 
                help="reads FILE.json and decrypt all connection passwords in it", metavar="FILE.json")
    
  
    args=parser.parse_args()
    
    try:
        fic=os.path.realpath(args.jsonfile, strict=True)
    except:
        raise SystemExit ("json file " + args.jsonfile + " does not exist or cannot be found")
        
    with open(fic, "r") as sdevconn:
        try:
            datos=json.load(sdevconn)
        except json.decoder.JSONDecodeError:
            raise SystemExit ("problems reading json file")
        
    if args.headers:
        print ('ConnName'.ljust(50)," ",'password'.ljust(30))
        print ('-'*50," ",'-'*30)
        
    for c in datos['connections']:
        print (c['info']['ConnName'].ljust(50),args.delim.ljust(1),decryptpwd(c['info']['password'], args.decryptkey).ljust(30))                      


if __name__ == "__main__" :
    main()