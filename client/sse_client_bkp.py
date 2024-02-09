'''
 The MIT License (MIT)

 Copyright (c) 2016 Ian Van Houdt

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
'''


############
#
#  sse_client.py
#
#  Serves as SSE implementation for client. The routines 
#  for SSE are invoked by the client module via the API.
#
############

import sqlite3
from requests.api import get
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from datetime import datetime, timedelta
import bcrypt
import binascii
import string
import dbm
from flask import Flask, jsonify, request
import requests
from nltk.stem.porter import PorterStemmer
import os
import json
import re
import inspect
import sys
import shutil
from time import time

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from jmap import jmap
from client.file_handler import FileHandler
from client.log_handler import variable_schema, LogHandler

DEBUG = 1
SEARCH = "search"
SEARCH_DOC = "search_doc"
UPDATE = "update"
ADD = "add"

ENCODE=True
CSV_INPUT = 1

# Default url is localhost, and the port 5000 is set by Flask on the server
DEFAULT_URL = "http://127.0.0.1:5000/"

NO_RESULTS = "Found no results for query"

DELIMETER = "++?"

# TODO: Maybe strip out some of the excluded punctuation. Could be useful
# to keep some punct in the strings. We're mostly looking to strip the
# final punct (ie: '.' ',' '!' etc)
EXCLUDE = string.punctuation

def get_schema_id(query_type):
    if query_type == 'p':
        return ['5', '6']           # indexes for pid and ppid in csv log
    elif query_type == 'f':
        return ['16', '23']         # indexes for fd[0].inode and fd[1].inode in csv log
    else:
        return None


def get_lookup_table():
    try:
        with open('ltdict.json', 'r') as f:
            ltdict = json.load(f)
        with open('vdict.json', 'r') as f:
            vdict = json.load(f)
        lookup_table = [ltdict, vdict]
    except:
        lookup_table = [{},{}]
    return lookup_table


def get_segment_cluster_info(word, schema_ids):
    segment_ids = []
    cluster_ids = []
    try:
        with open('vdict.json', 'r') as f:
            vdict = json.load(f)
        
        for cid, value in vdict.items():
            for schema_id in schema_ids:
                for each in value.get(schema_id).values():
                    if each[0] == word:
                        segment_ids.extend(each[1])
                        if cid not in cluster_ids:
                            cluster_ids.append(cid)
        return (segment_ids, cluster_ids)
    except:
        return (segment_ids, cluster_ids)

########
#
# SSE_Client
#
########
class SSE_Client():

    def __init__(self):

        # TODO: placeholder for password. Will eventually take
        # as an arg of some sort
        self.password = b"password"

        # TODO: need to sort out use of salt. Previously, salt was
        # randomly generated in initKeys, but the resulting pass-
        # words k & kPrime were different on each execution, and 
        # decryption was impossible. Hardcoding salt makes dectyption
        # possible but may be a bad short cut
        self.iv = None
        self.salt = b"$2b$12$ddTuco8zWXF2.kTqtOZa9O"

        # Two keys, generated/Initialized by KDF
        (self.k, self.kPrime) = self.initKeys()

        # Two K's: generated/initialized by PRF
        self.k1 = None
        self.k2 = None

        # client's cipher (AES w/ CBC)
        self.cipher = self.initCipher()

        # Stemming tool (cuts words to their roots/stems)
        self.stemmer = PorterStemmer()
        self.db = self.ensure_metadata_db()

    def initKeys(self):
        # initialize keys k & kPrime
        # k used for PRF; kPrime used for Enc/Dec
        # return (k, kPrime)

        #hashed = bcrypt.hashpw(self.password, bcrypt.gensalt())
        hashed = bcrypt.hashpw(self.password, self.salt)

        if(DEBUG > 1):
            print(("len of k = %d" % len(hashed)))
            print(("k = %s" % hashed))

        # Currently k and kPrime are equal
        # TODO: Sort out requirements of k and kPrime
        # Research uses both, but not sure the difference
        return (hashed, hashed)


    def initCipher(self):
        # initialize Cipher, using kPrime
        # return new Cipher object

        # TODO: fix key. Currently just a hack: AES keys must be
        # 16, 24 or 32 bytes long, but kPrime is 60
        key = self.kPrime[:16]

        # generates 16 byte random iv
        self.iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, self.iv)

        return cipher

    def ensure_metadata_db(self):
        db = sqlite3.connect('metadata')
        db.execute('''CREATE TABLE IF NOT EXISTS SEGMENT_INFO (file_id text, segment_id text, cluster_id text, ts_start real, ts_end real)''')
        if db == None:
            print("Error while opening database")
        return db
        
        
    def encryptSegment(self, infile, outfile):
        # read in infile (opened file descriptor)
        buf = infile.read()
        if buf == '': 
            print("[Enc] segment to encrypt is empty!\nExiting\n")
            exit(1)

        # pad to mod 16
        while len(buf)%16 != 0:
            buf = buf + "\x08"

        # write encrypted data to new file
        outfile.write((self.iv + self.cipher.encrypt(buf.encode('latin1'))))


    def decryptSegment(self, buf, outfile=None):
        # Just pass in input file buf and fd in which to write out
        if buf == '': 
            print("[Dec] segment to decrypt is empty!\nExiting\n")
            exit(1)
        
        if type(buf) == str:
            buf = buf.encode('latin1')

        # self.kPrime[:16] is the  first 16 bytes of kPrime, ie: enc key
        # buf[:16] is the iv of encrypted msg

        # pad to mod 16
        while len(buf)%16 != 0:
            buf = buf + b"\x08"

        cipher = AES.new(self.kPrime[:16], AES.MODE_CBC, buf[:16])

        # decrypt all but first 16 bytes (iv)
        # if outfile is supplied, write to file
        if (outfile):
            outfile.write((cipher.decrypt(buf[16:])).decode('latin1'))
        # else print to terminal
        else:
            tmp = cipher.decrypt(buf[16:])
            return(tmp.decode('latin1'))


    def update(self, filename):
        begin_ts = datetime.now()
        print("update started")
        
        file = FileHandler(filename)
        segments = file.split_file()
        file.encode_logs(ENCODE)        
        encode_ts = datetime.now()
        
        # Then encrypt msg
        for seg in segments:
            print("Encrypting segment: ", seg)
            infile = open(seg, "r") 
            outfilename_ = seg.split('/')[1]
            outfilename = "enc/" + outfilename_
            outfile = open(outfilename, "wb+")
            self.encryptSegment(infile, outfile)
            infile.close()
    
            outfile.seek(0)
            data = binascii.hexlify(outfile.read())
            message = jmap.pack(ADD, data, "1", outfilename_)

            # Then send message
            r = self.send(ADD, message, outfilename)        
            if(type(r) != dict):
                r = r.json()
            results = r['results']
            print("Results of UPDATE/ADD FILE: " + results)

            outfile.close()

        # for f in os.listdir("tmp/"):
        #     os.remove(os.path.join("tmp/", f))
        
        encrypt_ts = datetime.now()
        
        print("\nStats (time required):")
        # print("Encode segments: {}\nUpdate index: {}\nEncrypt index: {}\nEncrypt segments: {}\n"
            #   .format(encode_ts-begin_ts, update_idx_ts-encode_ts, encrypt_idx_ts-update_idx_ts, encrypt_ts-encrypt_idx_ts))
        print("Encoding: {}\nEncrypting: {}\nTotal: {}".format(encode_ts-begin_ts, encrypt_ts-encode_ts, encrypt_ts-begin_ts))

        for f in os.listdir("enc/"):
            os.remove(os.path.join("enc/", f))


    def search(self, query, base_ts=0, search_type='', query_type=''):
        return_result = ""
        return_result += "metainfo: %s\n" % time()

        word = query.lower()
        schema_id = get_schema_id(query_type)
        (segments_ids, cluster_ids) = get_segment_cluster_info(word, schema_id)
        
        cur = self.db.cursor()
        if search_type == 'f':
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_start<=? and ts_end>=?''', (base_ts, base_ts))
            base_segment = [list[0] for list in cur.fetchall()]
            if len(base_segment) >= 1:
                base_segment = base_segment[0]
                cur.execute('''SELECT ts_start FROM SEGMENT_INFO WHERE segment_id=?''', (base_segment, ))
                base_ts = cur.fetchone()[0]
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_start>=?''', (base_ts, ))
            relevant_segments = [list[0] for list in cur.fetchall()]
        
        elif search_type == 'b':
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_start<=? and ts_end>=?''', (base_ts, base_ts))
            base_segment = [list[0] for list in cur.fetchall()]
            # print(base_ts, base_segment)
            if len(base_segment) >= 1:
                base_segment = base_segment[-1]
                cur.execute('''SELECT ts_end FROM SEGMENT_INFO WHERE segment_id=?''', (base_segment, ))
                base_ts = cur.fetchone()[0]
            cur.execute('''SELECT segment_id FROM SEGMENT_INFO WHERE ts_end<=?''', (base_ts, ))
            relevant_segments = [list[0] for list in cur.fetchall()]
            # print("rel:", relevant_segments)
        
        return_segments = []
        for each in segments_ids:
            if each in relevant_segments:
                return_segments.append(each)
        
        message = jmap.pack(SEARCH_DOC, return_segments)
        ret_data = self.send(SEARCH_DOC, message)
        
        if(type(ret_data) != dict):
            ret_data = ret_data.json()
        results = ret_data['results']
        return_result += "Results of SEARCH:\n"
        
        if results == NO_RESULTS:
            return_result += "%s\n" % results
            return return_result

        decoded_message = ''''''
        for i in results:
            decrypted = self.decryptSegment(i.encode('latin1'), )
            lookup_table = get_lookup_table()
            decrypted_ = decrypted.split('\n')[:-1]
            for cid in cluster_ids:
                l = LogHandler(lookup_table, cid)
                for each in decrypted_:
                    decoded = l.decode(each)
                    if re.search(r'\b{}\b'.format(word), decoded):
                        decoded_message += (decoded+'\n')
        
        return_result += "metainfo: %s\n" % time()
        return_result += "%s" % decoded_message
        # print(return_result)
        return(return_result)


    def PRF(self, k, data):
        if type(data) == str:
            data = data.encode('latin1')
        if type(k) == str:
            k = k.encode('latin1')
        hmac = HMAC.new(k, data, SHA256)
        return hmac.hexdigest()

    # Decrypt doc ID using k2
    def dec(self, k2, d):
        d_bin = binascii.unhexlify(d) 
        iv = d_bin[:16]
        cipher = AES.new(k2[:16], AES.MODE_CBC, iv)
        doc = cipher.decrypt(d_bin[16:])

        return doc

    def send(self, routine, data, filename = None, in_url = DEFAULT_URL):
        # print("sending to ", in_url)
        url = in_url

        # Currently, each server url is just <IP>/<ROUTINE>, so just append
        # routine to url, and set up headers with jmap package.

        if routine == SEARCH:
            url = url + SEARCH
            headers = jmap.jmap_header()
        elif routine == SEARCH_DOC:
            url = url + SEARCH_DOC
            headers = jmap.jmap_header()
        elif routine == UPDATE:
            url = url + UPDATE
            headers = jmap.jmap_header()
        elif routine == ADD:
            url = url + ADD
            # For sending mail, need to do a little extra with the headers
            headers = {'Content-Type': 'application/json',
                       'Content-Disposition': 
                       'attachment;filename=' + filename}
        else:
            print("[Client] Error: bad routine for send()")
            exit(1)

        if (DEBUG > 1): 
            print(url)

        # Send to server using requests's post method, and return results
        # to calling method
        client_out_time = time()
        result = requests.post(url, data, headers = headers)
        client_in_time = time()
        result_json = result.json()
        if(len(result_json['results'])>1 and type(result_json['results']) == list and type(result_json['results'][-1]) == float):
            server_out_time = result_json['results'].pop()
            server_in_time = result_json['results'].pop()
            # print("client-to-server:", float(server_in_time)-client_out_time)  # n/w delay when sending
            # print("server-to-client:", client_in_time-float(server_out_time))  # n/w delay when receiving
        return (result_json)
