#!/usr/bin/env python3

##### IMPORTS

import argparse

from collections.abc import Callable

import bz2
import csv
from datetime import date, timedelta
from hashlib import shake_256
from multiprocessing import Pool
from uu import encode
import numpy as np
from os import cpu_count

from sys import exit, stdout

from time import time_ns
from typing import Iterator, Mapping, Optional, Union

# add any additional modules you need here
import secrets
import hashlib
import sys
import math

##### METHODS

def generate_iv( length:int ) -> bytes:
    """
    Generate an initialization vector for encryption. Must be drawn from a
       cryptographically-secure pseudo-random number generator.

    PARAMETERS
    ==========
    length: The length of the IV desired, in bytes.

    RETURNS
    =======
    A bytes object containing the IV.
    """
    assert type(length) is int
    return secrets.token_bytes(length)



def xor( a:bytes, b:bytes ) -> bytes:
    """
    Bit-wise exclusive-or two byte sequences. If the two bytes objects differ in
       length, pad with zeros.

    PARAMETERS
    ==========
    a, b: bytes objects to be XORed together.

    RETURNS
    =======
    A bytes object containing the results.
    """
    assert type(a) is bytes
    assert type(b) is bytes

 #check lenght of both a and b byte streams, who is shortest
    #length of a and b 
    bArray_a = bytearray(a)
    bArray_b = bytearray(b)

    #shorts, pad with 0 at end 
    if len(a) < len(b):
        add = len(b) - len(a)
        for x in range(add):
            bArray_a.append(0)
    if len(b) < len(a):
        add = len(a) - len(b)
        for x in range(add):
            bArray_b.append(0)
 
     #xor, byte to int and then int to byte
     #resource used for the xor computation: https://stackoverflow.com/questions/23312571/fast-xoring-bytes-in-python-3
     # 3rd answer from the post 
            
    #compute xor using two byte arrays of equal length
    input = bArray_a 
    #enumerate trough the byte array b
    for i, b in enumerate(bArray_b): 
        #compute xor computation with the corresponding index of the byte array
        input[i] = input[i] ^ b

    #convert the byte array to a sequence of bytes     
    result = bytes(input) 
    return result 


##Complete this 

def left_encode( x:int ) -> bytes:
    """
    Unambiguously encode a number into a sequence of bytes, as defined by
      NIST Special Publication 800-185. In English, the algorithm generates
      a byte encoding of the number, where the most-significant bit of the
      number is at the start of the first byte and the least-significant bit
      of the number is at the end of last byte. It then prepends the number
      of bytes in the encoding, itself encoded as a byte.

    PARAMETERS
    ==========
    x: An integer to encode. Must be positive or zero, and less than a very
      large number.

    RETURNS
    =======
    A sequence of bytes encoding the number.
    """
    assert type(x) is int
    assert 0 <= x <= (1 << 2040)

    #Determine the minimum number of bytes needed (n). 
    # Calculate n as the smallest number of bytes to represent x.
    # We add 7 because we want to round up to the nearest byte. For example,
    # if x.bit_length() is 9, adding 7 results in 16, and dividing by 8 yields 2 bytes.

    n = (x.bit_length() + 7) // 8  # Calculate n as the smallest number of bytes to represent x

    
    #special case for when x = 0, which requires a single byte to encode
    if x == 0:
        n = 1

    #encode x into a byte array.
    encoded_bytes = bytearray()
    #iterate backwards from n-1 to 0. starting from the (MSB) to the (LSB)
    for i in range(n-1, -1, -1):
        byte = (x >> (8 * i)) & 0xFF  # Shift right to get to the correct byte and mask with 0xFF to extract it
        encoded_bytes.append(byte)  # Append the byte to the end of the bytearray

    #Prepend the length of the encoded bytes as a byte in index 0 follow by left endcoding.
    output = bytearray([n]) + encoded_bytes

    return bytes(output)
  
def bytepad( X:bytes, w:int ) -> bytes:
    """
    Unambiguously pad a binary sequence with zeros until it is a multiple of "w"
      bytes long, as defined by NIST Special Publication 800-185. In English, the 
      algorithm prepends the sequence with left_encode(w), then pads the entire
      sequence with bits until it an appropriate length. NIST's original definition
      states that "X" is a bit stream, but those aren't well supported in Python,
      so we'll work exclusively in bytes.

    PARAMETERS
    ==========
    X: A sequence of bytes that may need padding.
    w: The output byte sequence is w * n bytes long, where "n" is an integer
      greater than or equal to one.

    RETURNS
    =======
    A sequence of bytes that is a multiple of "w" bytes long.
    """
    assert type(X) is bytes
    assert type(w) is int
    assert w > 0

    #setting up the byte string to be padded.
    encode_w = left_encode(w)
    x_padding = encode_w + X

    #calculating the padding to make the length a multiple of w.
    padding_l = (w - (len(x_padding)%w)) % w 
    x_padding += bytes(padding_l)

    return x_padding

  #Construction of the string. 
def encode_string( S:Union[bytes,str] ) -> bytes:
    """
    Unambiguously encode a sequence of bits, as defined by NIST Special 
      Publication 800-185. In English, the algorithm uses left_encode() to 
      prepend the length of the bit stream to it. As Python does not have
      good support for bit sequences, we'll use bytes sequences instead.
      For programmer convenience, we'll also accept strings as input and
      automatically encode them into a byte sequence with UTF-8.

    PARAMETERS
    ==========
    S: Either a string or sequence of bytes to be encoded.

    RETURNS
    =======
    A sequence of bytes that has been encoded according to the algorithm.
    """
    assert type(S) in [bytes,str]

    #Convert S to bytes if it is a string 
    if isinstance(S, str):
        S = S.encode("utf-8")
    
    # Calculate the length of S in bytes and encode this length using left_encode
    encoded_l = left_encode(len(S) * 8)  # Note the multiplication by 8 for bit length

    #Prepend the length of S, econded as bytes 
    encoded_String = encoded_l + S

    return encoded_String  

def pseudoCSHAKE256( X:Union[bytes,str], L:int=1088, N:Union[bytes,str]=b"", \
        S:Union[bytes,str]=b"" ) -> bytes:
    """
    Implement a variant of the cSHAKE256 algorithm, as defined by NIST Special 
      Publication 800-185. In English, the original algorithm encodes N and S, 
      concatenates them, and pads the result until it is a multiple of 136 bytes 
      long. It prepends that result to X and appends a zero bit, then passes that 
      to the Keccak[512] algorithm with a request for it to return L bits. That 
      output is then returned. As Python does not have good support for bit sequences,
      we'll use byte sequences instead. For ease of use, we'll also accept
      strings and automatically encode them to byte sequences via UTF-8.

      We'll substitute hashlib's shake_256 for Keccak[512], which is identical 
      except for an inability to handle bit sequences. As a consequnce we cannot 
      append a zero bit as the official cSHAKE256 spec demands; for this implementation, 
      append a zero byte instead. That one change is why this is "pseudoCSHAKE256".

    PARAMETERS
    ==========
    X: Either a string or sequence of bytes to be hashed.
    L: The number of bits to return, as an integer. Since we don't support bit
      sequences, this MUST be a multiple of eight.
    N: Either a string or sequence of bytes, which is used to define other 
      hash functions.
    S: Either a string or sequence of bytes, which is used to customize the output
      of pseudoCSHAKE256.

    RETURNS
    =======
    The hash value of the input, as a sequence of bytes.
    """
    assert type(X) in [bytes,str]
    assert L >= 0
    assert (L & 0x7) == 0       # we can only deliver byte-resolution output
    assert type(N) in [bytes,str]
    assert type(S) in [bytes,str]

    # Encoding strings via UTF-8 if found in the paramater values 
    if isinstance(X,str):
        X = X.encode('utf-8')
    if isinstance(N,str):
        N = N.encode('utf-8')
    if isinstance(S,str):
        S = S.encode('utf-8')

    # Use shake_256 if N and S are both empty. return SHAKE256(X, L);
    if N == b"" and S == b"":
        return hashlib.shake_256(X).digest(L // 8)
    
    # Encode N and S using the encode_string function from above and pad the result 
    # then we will concatanate N and S with X
    encode_N = encode_string(N)
    encode_S = encode_string(S)
    padding = bytepad(encode_N + encode_S, 136) + X + b'\x00' # Appending X and the 0 byte 

    # Hashing the padding (input) using shake_256 and returning L bits 
    return hashlib.shake_256(padding).digest(L // 8)

    
    
  


def encrypt( iv:bytes, plaintext:Union[bytes,str], enc_key:bytes ) -> bytes:
    """
    Encrypt the given plaintext, with the given IV and key, using pseudoCSHAKE256().
      In English, this algorithm generates a random byte stream by hashing the
      concatenation of the encoded iv string and encoded encryption key string, 
      in that order, asking for a digest exactly as long as the plaintext. That 
      digest is XOR-ed with the plaintext to give the encrypted output.
         
    Do not prepend the IV to the output. Customize pseudoCSHAKE256() by supplying
      the byte sequence "ENCRYPT", and use the length of the binary plaintext 
      stream in bits for N, after encoding it with left_encode(). The lack 
      of a matching decrypt() function is deliberate.

    PARAMETERS
    ==========
    iv:        The initialization vector used to boost semantic security, a byte sequence.
    plaintext: The data to be encrypted, which could either be a byte sequence or string.
    enc_key:   A bytes object to be used as an encryption key.

    RETURNS
    =======
    A bytes object containing the encrypted value. Note that the return is not a list or
      generator.
    """
    assert type(iv) is bytes
    assert type(plaintext) in [bytes,str]
    assert type(enc_key) is bytes

    #checking that the plaintxt is in bytes 
    if isinstance(plaintext, str):
      plaintext = plaintext.encode('utf-8')
    
    #encoding IV and the key, then putting them together 
    encoded_iv = encode_string(iv)
    encoded_key = encode_string(enc_key)
    encoded_iv_key = encoded_iv + encoded_key

    #calculating the length of the playtext in bits to use for the pseudoCShake256
    k_stream = pseudoCSHAKE256(encoded_iv_key, len(plaintext) * 8, N=left_encode(len(plaintext) * 8), S=b"ENCRYPT")


    #XOR plaintext with k_stream(key stream)
    encryption = xor(k_stream, plaintext)

    return encryption




def MAC_then_encrypt( plaintext:Union[bytes,str], key:Union[bytes,str], \
        iv_bits:int=256, tag_bits:int=128, key_bits:int=128 ) -> bytes:
    """
    Encrypt a plaintext with your encryption function. In English, this algorithm
      uses encode_string() to encode the plaintext. It calculates a tag of the 
      encoded plaintext via pseudoCSHAKE256 (customized with the bytes "TAG"), 
      derives the actual encryption key from the iv via pseudoCSHAKE256 (N is 
      the user-supplied key, S is the byte sequence "KEY_DERIVATION"). It then 
      uses encrypt() to encrypt the concatenation of the tag and encoded plaintext 
      with the derived key, and returns the output but with the IV prepended 
      to it.

    The output must be decryptable by decrypt_and_verify(). Note the order of 
      operations!
    
    PARAMETERS
    ==========
    plaintext: The bytes or string object to be encrypted. Not necessarily padded!
    key: The bytes or string object to be used as a key.
    iv_bits: The length of the desired IV, in bits. Must be greater than 256
      and a multiple of 8.
    key_bits: The length of the generated key, in bits. Must be greater than 128
      and a multiple of 8.
    tag_bits: The length of the tag, in bits. Must be positive and a multiple 
      of 8.

    RETURNS
    =======
    The full cyphertext, as a bytes object. Note that the return is not a list or
      generator.
    """
    assert type(plaintext) in [bytes,str]
    assert type(key) in [bytes,str]
    assert iv_bits >= 256
    assert (iv_bits & 0x7) == 0
    assert tag_bits > 0
    assert (tag_bits & 0x7) == 0
    assert key_bits >= 128
    assert (key_bits & 0x7) == 0

    #check that the input are in bytes 
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')

    #encoding the plaintext 
    plaintxt_encoding = encode_string(plaintext)
    
    # Tag and IV generating for encoding plaintxt. 
    '''It calculates a tag of the 
      encoded plaintext via pseudoCSHAKE256 (customized with the bytes "TAG"), 
      derives the actual encryption key from the iv via pseudoCSHAKE256 (N is 
      the user-supplied key, S is the byte sequence "KEY_DERIVATION").'''
     
    tag = pseudoCSHAKE256(plaintxt_encoding, tag_bits, N=b'', S=b'TAG')
    iv = generate_iv(iv_bits // 8) #bits to bytes

    #then we derive the key for the encryption and encrypt creating the cyphertxt
    Encription_KEY = pseudoCSHAKE256(iv, key_bits, N=key, S=b"KEY_DERIVATION")
    encrypt_data = encrypt(iv, tag + plaintxt_encoding, Encription_KEY)

    
    return iv + encrypt_data

def decrypt_and_verify( cyphertext:bytes, key:Union[bytes,str], \
        iv_bits:int=256, tag_bits:int=128, key_bits:int=128 ) -> bytes:
    """
    Decrypt a plaintext that had been encrypted with MAC_then_encrypt().
      Also performs integrity checking to help ensure the original wasn't
      corrupted.
    
    PARAMETERS
    ==========
    cyphertext: The bytes object to be decrypted.
    key: The bytes or string object to be used as a key.
    iv_bits: The length of the desired IV, in bits. Must be greater than 256
      and a multiple of 8.
    key_bits: The length of the generated key, in bits. Must be greater than 128
      and a multiple of 8.
    tag_bits: The length of the tag, in bits. Must be positive and a multiple 
      of 8.

    RETURNS
    =======
    If the cyphertext could be decrypted and is valid, this returns a bytes 
      object containing the plaintext. Otherwise, it returns None.
    """
    assert type(cyphertext) is bytes
    assert len(cyphertext) >= (iv_bits + tag_bits)>>3 + 2
    assert type(key) in [bytes,str]
    assert iv_bits >= 256
    assert (iv_bits & 0x7) == 0
    assert tag_bits > 0
    assert (tag_bits & 0x7) == 0
    assert key_bits >= 128
    assert (key_bits & 0x7) == 0

    

    
    iv_bytes = iv_bits >> 3 # converting bits to bytes 
    tag_bytes = tag_bits >> 3

    #gather the IV from the correct location  0 to iv_l in cyphertxt 
    iv = cyphertext[:iv_bytes]
    #deriving the encryption key in order to perform decription 
    enc_key = pseudoCSHAKE256( iv, key_bits, N=key, S=b'KEY_DERIVATION' )
    #decrypt the data and retrive the tag + the encoded txt
    combo = encrypt( iv, cyphertext[iv_bytes:], enc_key )
    
    #gather the encrypted data from the cypher txt to decrypt
    mac = combo[:tag_bytes]


    #integraty checking using tag and parcing the cyphertxt to retrive the relative information for the decode  
    if mac != pseudoCSHAKE256( combo[tag_bytes:], tag_bits, S=b'TAG' ):
        return None

    #decryption
    len_bytes         = combo[tag_bytes]
    length            = int.from_bytes( combo[tag_bytes+1:tag_bytes+1+len_bytes], 'big' ) >> 3
    plaintext         = combo[tag_bytes+1+len_bytes:]

    return plaintext if len(plaintext) == length else None
    


def generate_passwords( start_date:date, end_date:date, names:dict ):
    """
    A generator that creates all the passwords we'd use for a brute-force attack.
      A valid password comes in the form NAME + YEAR + MONTH + DAY, where
      "NAME" is a name drawn from the "names" dictionary, and YEAR, MONTH, and
      DAY are the respective integers converted to strings. 

    Each of the four components are optional, but at least one must be present 
      and the order of concatenation is constant. MONTH and DAY values can either 
      be a direct conversion, or one that's been padded to always be two characters
      by prepending a "0". YEAR can either be four characters, or the last two 
      digits of the year with zero-padding. NAME is always all-caps. No separators
      are used to deliniate between components. Any remaining details are on
      the assignment specification.

    An old but still relevant tutorial on generators: https://wiki.python.org/moin/Generators

    PARAMETERS
    ==========
    start_date: The earliest possible date that could be used for a password, as
      a date object.
    end_date: The latest possible date that could be used for a password, as
      a date object. Note that this value could be output!
    names: A dictionary object containing three lists of equal length. The one
      keyed to 'First name at birth' is a list of first names assigned at birth.
      'VALUE' is the total number of Canadians assigned that first name for the 
      given year, and 'REF_DATE' contains the year those statistics were gathered.

    RETURNS
    =======
    None.

    YIELDS
    =======
    A potential password as a string, according to the above specifications.
    """
    assert type(start_date) is date
    assert type(end_date) is date
    assert type(names) is dict
    for key in ['REF_DATE','First name at birth','VALUE']:
        assert key in names
        assert len(names['REF_DATE']) == len(names[key])

     # Iterating through each day in the given date range.
    date_cursor = start_date
    while date_cursor <= end_date:
        # Extracting and formatting date components.
        year_long = date_cursor.strftime('%Y')  # Full year
        year_short = date_cursor.strftime('%y')  # Last two digits of the year
        month_with_zero = date_cursor.strftime('%m')  # Month with leading zero
        month_no_zero = str(int(month_with_zero))  # Month without leading zero
        day_with_zero = date_cursor.strftime('%d')  # Day with leading zero
        day_no_zero = str(int(day_with_zero))  # Day without leading zero

        # Combining name with all date format variations.
        for individual_name in names['First name at birth']:
            #name_capitalized = individual_name.upper()  # Ensuring name is in uppercase.
            # Creating combinations of name with year, month, and day.
            for yr in [year_long, year_short, '']:
                for mnth in [month_with_zero, month_no_zero, '']:
                    for dy in [day_with_zero, day_no_zero, '']:
                        # Generating password only if at least one date component is present.
                        if individual_name or yr or mnth or dy:
                            password = f"{individual_name}{yr}{mnth}{dy}"
                            yield password

        # Additionally, iterating over date components without name.
        for yr in [year_long, year_short, '']:
            for mnth in [month_with_zero, month_no_zero, '']:
                for dy in [day_with_zero, day_no_zero, '']:
                    # Ensuring at least one component is present.
                    if yr or mnth or dy:
                        password = f"{yr}{mnth}{dy}"
                        yield password

        # Proceeding to the next day.
        date_cursor += timedelta(days=1)

def load_names( input ):
    """
    Load the name database from disk, and format for use with generate_passwords().
      The canonical database is a BZ2-compressed CSV file, with at least four
      columns: 'REF_DATE' (the year the stats were gathered), 'First name at birth'
      (a first name in all-caps), 'Indicator' (the type of statistic stored in
      'VALUE') and 'VALUE (the value of the 'Indicator'). The original source
      of this CSV file is this Statistics Canada dataset:

    https://www150.statcan.gc.ca/t1/tbl1/en/tv.action?pid=1710014701

    PARAMETERS
    ==========
    input: A File-like object for accessing the database.

    RETURNS
    =======
    A dictionary object with three equal-length lists under the keys 'REF_DATE',
      'First name at birth', and 'VALUE'.
    """

    # set up some storage space
    names = {col:[] for col in ['REF_DATE','First name at birth','VALUE']}

    # parse the database
    with bz2.open(input,'rt') as file:
        for row in csv.DictReader(file):

            # we only care about the number of people born with a name
            if row['Indicator'] == 'Frequency':
                for col in ['REF_DATE','First name at birth','VALUE']:
                    names[col].append( row[col] )

    # convert some of the columns to more relevant values
    names['REF_DATE'] = [int(x) for x in names['REF_DATE']]
    names['VALUE'] = [int(float(x)) for x in names['VALUE']]
    
    return names


##### MAIN


if __name__ == '__main__':

    # parse the command line args
    cmdline = argparse.ArgumentParser( description="Encrypt or decrypt a file." )

    methods = cmdline.add_argument_group( 'ACTIONS', "The three actions this program can do." )

    methods.add_argument( '--decrypt', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='A file to be decrypted.' )
    methods.add_argument( '--encrypt', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='A file to be encrypted.' )
    methods.add_argument( '--dump', action='store_true', \
        help='Dump the passwords this program would check in brute-force mode.' )

    methods = cmdline.add_argument_group( 'OPTIONS', "Modify the defaults used for the above actions." )

    methods.add_argument( '--output', metavar='OUTPUT', type=argparse.FileType('wb', 0), \
        help='The output file. If omitted, print the decrypted plaintext or dump to stdout. The destination\'s contents are wiped, even on error.' )
    methods.add_argument( '--password', metavar='PASSWORD', type=str, default="swordfish", \
        help='The password to use as a key.' )
    methods.add_argument( '--reference', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='If provided, check the output matches what is in this file.' )
    methods.add_argument( '--threads', type=int, default=0, \
        help='Number of threads to use when brute-forcing the password. Numbers < 1 implies all available.' )

    methods.add_argument( '--start_date', type=date.fromisoformat, default=date(2003,1,1), \
        help='When brute-forcing passwords, start from this date (inclusive).' )
    methods.add_argument( '--end_date', type=date.fromisoformat, default=date(2006,12,31), \
        help='When brute-forcing passwords, end on this date (inclusive).' )
    methods.add_argument( '--names', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='If provided, use this name list to brute-force the password.' )

    methods.add_argument( '--iv_bytes', type=int, default=32, \
        help='The number of bytes to use for the initialization vector. Must be a positive integer greater than 31.' )
    methods.add_argument( '--key_bytes', type=int, default=16, \
        help='The number of bytes to use for the derived key. Must be a positive integer greater than 15.' )
    methods.add_argument( '--tag_bytes', type=int, default=16, \
        help='The number of bytes to use for the tag. Must be a positive integer greater than 0.' )

    args = cmdline.parse_args()

    if args.threads < 1:
        args.threads = cpu_count()

    if args.iv_bytes < 32:
        args.iv_bytes = 32
    if args.key_bytes < 16:
        args.key_bytes = 16
    if args.tag_bytes < 1:
        args.tag_bytes = 1

    # which mode are we in?
    if args.decrypt:

        plaintext = None
        cyphertext = args.decrypt.read()
        args.decrypt.close()

        if args.names:
            
            names = load_names( args.names )
            
            def check_password( x ):
                retVal = decrypt_and_verify( cyphertext, x, args.iv_bytes<<3, args.tag_bytes<<3, args.key_bytes<<3 )
                return (retVal,x) if retVal else None

            if args.threads > 1:
                with Pool(args.threads) as p:
                    for output in p.imap( check_password, generate_passwords(args.start_date, args.end_date, names), 32 ):
                        if output:
                            plaintext, password = output
                            print( f'Found the password for this file: {password}' )
                            break
            else:
                for output in map( check_password, generate_passwords(args.start_date, args.end_date, names)):
                    if output:
                        plaintext, password = output
                        print( f'Found the password for this file: {password}' )
                        break

        else:
            plaintext = decrypt_and_verify( cyphertext, args.password, args.iv_bytes<<3, args.tag_bytes<<3, args.key_bytes<<3 )

        if plaintext is None:
            print( "ERROR: Could not decrypt the file!" )
            exit( 1 )

        if args.reference:
            ref = args.reference.read()
            if ref != plaintext:
                print( "ERROR: The output and reference did not match!" )
                exit( 2 )

        if args.output:
            args.output.write( plaintext )
            args.output.close()

        else:
            try:
                print( plaintext.decode('utf-8') )
            except UnicodeError as e:
                print( "WARNING: Could not print out the encrypted contents. Was it UTF-8 encoded?" )
                exit( 3 )

    elif args.encrypt:

        cyphertext = MAC_then_encrypt( args.encrypt.read(), args.password, args.iv_bytes<<3, args.tag_bytes<<3, args.key_bytes<<3 )

        if args.reference:
            ref = args.reference.read()
            if ref != cyphertext:
                print( "ERROR: The output and reference did not match!" )
                exit( 4 )

        if args.output:
            args.output.write( cyphertext )
            args.output.close()

        else:
            print( "As the cyphertext is binary, it will not be printed to stdout." )

    elif args.dump and args.names:

        names = load_names( args.names )
        for password in generate_passwords(args.start_date, args.end_date, names):
            if args.output:
                args.output.write( password.encode('utf-8') + b'\n' )
            else:
                stdout.buffer.write( password.encode('utf-8') + b'\n' )

    else:

        print( "Please select one of encryption, decryption, or dumping." )
