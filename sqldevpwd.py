#!/usr/bin/env python3
import json
import os
import re
import argparse
import base64
import hashlib
from Cryptodome.Cipher import AES

VERSION="1.3"

def con_pwd(c):
    try:
        p = c['info']['password']
    except:
        p = ''
    return p

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
    max_size_to_show_dots=30
    default_cols_width='50,30,30'
    
    parser = argparse.ArgumentParser(description='Prints to stdout decrypted passwords for connections in a SQL Developer 19.2+ export file in json format')
    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    parser.add_argument('--headers', action='store_true',
                help="show headers at first lines of output")
    parser.add_argument('--csv', action='store_true',
                help="generate a csv file rather than a table file, ignoring -s and header rule")
    parser.add_argument('-d', '--delim', default=' ',
                help="column separator, just one character")
    parser.add_argument('-s', '--size', default=default_cols_width,
                help="a comma separated list of three numbers defining column size of each colum, if only one number given applies to all three columns")        
    parser.add_argument("-f", dest='filter', required=False,
                help="Filter to apply with format key=value where key should be 'name' or 'user' and value a regexp")
    parser.add_argument("-k", dest="decryptkey", required=True,
                help="key to decrypt passwords, usually the export file encryption key or value of 'db.system.id' attribute in 'product-preferences.xml' file")
    parser.add_argument("jsonfile", 
                help="reads FILE.json and decrypt all connection passwords in it", metavar="FILE.json") 
  
    args=parser.parse_args()

    csize=(args.size if ',' in args.size else ','.join([args.size,args.size,args.size])).split(',')
    csize=default_cols_width.split(',') if len(csize) != 3 else csize
    try:
        cols_width=[ int(c) for c in csize]
    except:
        cols_width=[ int(c) for c in default_cols_width.split(',')]
    
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
        if args.csv:
            print (args.delim.join(['Name','User','Password']))
        else:
            print(args.delim.join([ a.ljust(b) for a,b in zip(['Name','User','Password'],cols_width)]))
            print(args.delim.join([ '-'*n for n in cols_width]))
        
    con = [ { 'name': x['name'], 'user': x['info']['user'], 'pwd': decryptpwd(con_pwd(x), args.decryptkey)} for x in datos['connections']]
 
    if args.filter:
        fk,fv = args.filter.split('=')
        fr = re.compile(fv)
        con = [ x for x in con if fr.match(x[fk])]
    
    for c in con:
        print(args.delim.join([ a if args.csv else (t if len(t:=a.ljust(b)) == b else (t[:(b-3)]+'...') if b>max_size_to_show_dots else t[:b] )for a,b in zip(c.values(),cols_width)]))


if __name__ == "__main__" :
    main()
