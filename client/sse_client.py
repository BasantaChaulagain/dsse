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
from collections import defaultdict
from configparser import ConfigParser
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

config_ = ConfigParser()
config_.read("config.ini")
NUM_OF_SEGMENTS = int(config_["CONF"]["num_of_segments"])
NUM_OF_CLUSTERS = int(config_["CONF"]["num_of_clusters"])
SSE_MODE = int(config_["GLOBAL"]["SSE_MODE"])
LAST_SEG_ID = int(config_['CONF']['last_segment_id'])

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


def get_cgid_from_segments(cur, segments):
    cgids = []
    for seg in segments:
        cur.execute('''SELECT clustergroup_id FROM SEGMENT_INFO WHERE segment_id=?''', (seg, ))
        cgid = cur.fetchone()[0]
        if cgid not in cgids:
            cgids.append(cgid)
    return cgids


def get_lookup_table(cur, segments):
    cg_ids = get_cgid_from_segments(cur, segments)
    vdict = {}
    ltdict = {}
    for cg_id in cg_ids:
        try:
            with open('ltdict/ltdict_{}.json'.format(cg_id), 'r') as f:
                content = json.load(f)
                ltdict = {**ltdict, **content}
            with open('vdict/vdict_{}.json'.format(cg_id), 'r') as f:
                content = json.load(f)
                vdict = {**vdict, **content}
        
        except FileNotFoundError:
            pass
                
    lookup_table = [ltdict, vdict]
    return lookup_table


def get_cluster_id(word, schema_ids):
    cluster_ids = []
    vdict = {}
    try:
        for file in os.listdir('vdict'):
            with open('vdict/'+file, 'r') as f:
                content = json.load(f)
                vdict.update(content)
                # vdict = {**vdict, **content}
        
        for cid, value in vdict.items():
            for schema_id in schema_ids:
                if value.get(schema_id) is not None:
                    for each in value.get(schema_id).values():
                        if each[0] == word:
                            if cid not in cluster_ids:
                                cluster_ids.append(cid)
        return (cluster_ids)
    except:
        return (cluster_ids)


def get_segment_cluster_info(word, schema_ids):
    segment_ids = []
    cluster_ids = []
    vdict = {}
    try:
        for file in os.listdir('vdict'):
            with open('vdict/'+file, 'r') as f:
                content = json.load(f)
                vdict.update(content)
                # vdict = {**vdict, **content}
        # print(json.dumps(vdict, indent=4))
        
        for cid, value in vdict.items():
            for schema_id in schema_ids:
                if value.get(schema_id) is not None:
                    for each in value.get(schema_id).values():
                        if each[0] == word:
                            segment_ids.extend(each[1])
                            if cid not in cluster_ids:
                                cluster_ids.append(cid)
        return (segment_ids, cluster_ids)
    except:
        return (segment_ids, cluster_ids)


def get_count(word, cluster_id, schema_ids):
    try:
        with open('vdict/vdict_cg'+cluster_id[1]+'.json') as f:
            vdict = json.load(f)
            vdict = vdict[cluster_id]
            cts = []
            for schema_id in schema_ids:
                if vdict.get(schema_id) is not None:
                    for each in vdict.get(schema_id).values():
                        if each[0] == word:
                            cts.append(each[2])
            return str(max(cts))
    except:
        return None
    

########
#
# SSE_Client
#
########
class SSE_Client():

    def __init__(self):
        self.password = b"password"

        self.iv = None
        # self.salt = b"$2b$12$ddTuco8zWXF2.kTqtOZa9O"
        self.salt = b"$2b$12$fz7BTMuSX.soZ7sOwNqPLu"

        # Two keys, generated/Initialized by KDF
        (self.k, self.kPrime) = self.initKeys()

        # Two K's: generated/initialized by PRF
        self.k1 = None
        self.k2 = None

        # client's cipher (AES w/ CBC)
        self.cipher = self.initCipher()

        # Stemming tool (cuts words to their roots/stems)
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
        db.execute('''CREATE TABLE IF NOT EXISTS SEGMENT_INFO (file_id text, segment_id text, cluster_id text, clustergroup_id text, ts_start real, ts_end real)''')
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


    def encryptSegmentID(self, k2, segment_ids):

        # Encrypt doc id (document) with key passed in (k2)

        # set up new cipher using k2 and random iv
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(k2[:16].encode('latin1'), AES.MODE_CBC, iv)

        # pad to mod 16
        while len(segment_ids)%16 != 0:
            segment_ids = segment_ids + '\x08'

        encId = iv + cipher.encrypt(segment_ids.encode('latin1'))

        if (DEBUG > 1):
            print(("New ID for '%s' = %s" % 
                 (segment_ids, (binascii.hexlify(encId)))))

        return binascii.hexlify(encId)


    def update_index(self, vdict):
        for k, v in vdict.items():
            cluster_id = k
            process_dict = list(v.get('5').values())
            process_dict.extend(list(v.get('6').values()))
            
            file_dict = list(v.get('16').values())
            if '23' in v.keys():
                file_dict.extend(list(v.get('23').values()))
                        
            if SSE_MODE == 1:
                merged_p_dict = {}
                for key, value in process_dict:
                    # Create a set to collect unique values
                    unique_values_set = set()
                    if key not in merged_p_dict:
                        # If the key is not in the merged dictionary, directly add the values
                        unique_values_set.update(value)
                    else:
                        # If the key is already in the merged dictionary, add only unique values
                        existing_values = set(merged_p_dict[key])
                        unique_values_set.update(existing_values.union(value))
                    # Convert the set back to a list
                    unique_values_list = list(unique_values_set)
                    merged_p_dict[key] = unique_values_list

                process_list = [[key, value] for key, value in merged_p_dict.items()]
                # print(process_list)
                
                merged_f_dict = {}
                for key, value in file_dict:
                    unique_values_set = set()
                    if key not in merged_f_dict:
                        # If the key is not in the merged dictionary, directly add the values
                        unique_values_set.update(value)
                    else:
                        # If the key is already in the merged dictionary, add only unique values
                        existing_values = set(merged_f_dict[key])
                        unique_values_set.update(existing_values.union(value))
                    # Convert the set back to a list
                    unique_values_list = list(unique_values_set)
                    merged_f_dict[key] = unique_values_list

                file_list = [[key, value] for key, value in merged_f_dict.items()]
                # print(file_list)
            
            elif SSE_MODE == 2:
                merged_p_dict = defaultdict(lambda: {'max_second': float('-inf'), 'max_third': float('-inf'), 'segs': []})
                for first, second, third, fourth in process_dict:
                    merged_p_dict[first]['max_second'] = max(merged_p_dict[first]['max_second'], second)
                    merged_p_dict[first]['max_third'] = max(merged_p_dict[first]['max_third'], third)
                    merged_p_dict[first]['segs'].extend(fourth)

                # Convert the defaultdict back to a list
                process_list = [[key, merged_p_dict[key]['max_second'], merged_p_dict[key]['max_third'], list(set(merged_p_dict[key]['segs']))] for key in merged_p_dict]
                
                merged_f_dict = defaultdict(lambda: {'max_second': float('-inf'), 'max_third': float('-inf'), 'segs': []})
                for first, second, third, fourth in file_dict:
                    merged_f_dict[first]['max_second'] = max(merged_f_dict[first]['max_second'], second)
                    merged_f_dict[first]['max_third'] = max(merged_f_dict[first]['max_third'], third)
                    merged_f_dict[first]['segs'].extend(fourth)

                # Convert the defaultdict back to a list
                file_list = [[key, merged_f_dict[key]['max_second'], merged_f_dict[key]['max_third'], list(set(merged_f_dict[key]['segs']))] for key in merged_f_dict]
                
        update_idx_ts = datetime.now()
        
        indexes = []
        index = self.encryptIndex(process_list)
        indexes.append((index, 'p', cluster_id))
        index = self.encryptIndex(file_list)
        indexes.append((index, 'f', cluster_id))
        
        return (indexes, update_idx_ts)


    def encryptIndex(self, dict_list):
        L = []
        # For each word, look through local index to see if it's there. If
        # not, set c = 0, and apply the PRF. Otherwise c == number of 
        # occurences of that word/term/number 
        for each in dict_list:
            word = each[0]
            k1 = self.PRF(self.k, ("1" + word))
            k2 = self.PRF(self.k, ("2" + word))
            
            if SSE_MODE == 1:
                segment_ids = DELIMETER.join(each[1])
                l = k1
                d = self.encryptSegmentID(k2, segment_ids).decode()
                L.append((l, d))

            elif SSE_MODE == 2:
                segment_ids = DELIMETER.join(each[3])
                l = self.PRF(k1, str(each[2]))
                d = self.encryptSegmentID(k2, segment_ids).decode()
                lprime = self.PRF(k1, str(each[1]))
                L.append((l, d, lprime))
    
        return L


    def update(self, filename):
        begin_ts = datetime.now()
        file = FileHandler(filename)
        segments = file.split_file()
        
        if SSE_MODE == 1:
            file.encode_logs()
            encode_ts = datetime.now()
            total_clusters = len(os.listdir("vdict"))
            for i in range(total_clusters - LAST_SEG_ID):
                try:
                    with open("vdict/vdict_cg"+str(i)+".json", 'r') as f:
                        vdict = json.load(f)
                except:
                    vdict = {}
                (indexes, update_idx_ts) = self.update_index(vdict)
                
                for index in indexes:
                    # ((index, p or f, cluster_id))
                    message = jmap.pack(UPDATE, index[0], index[1], index[2])
                    # print(message)
                    r = self.send(UPDATE, message)
                    if(type(r) != dict):
                        r = r.json()
                    results = r['results']
                    print("Results of Index UPDATE: " + results)
                    
                encrypt_idx_ts = datetime.now()
        
        elif SSE_MODE == 2:
            segment_count = int(config_["CONF"]["last_segment_id"])
            for segment in segments:
                cluster_id = int(segment_count/NUM_OF_SEGMENTS)
                clustergrp_id = int(cluster_id/NUM_OF_CLUSTERS)
                segment_count+=1
                
                file.encode_logs_(segment, segment_count, cluster_id, clustergrp_id)
                encode_ts = datetime.now()

                try:
                    with open("vdict/vdict_cg"+str(cluster_id)+".json", 'r') as f:
                        vdict = json.load(f)
                except:
                    vdict = {}
                (indexes, update_idx_ts) = self.update_index(vdict)
                for index in indexes:
                    # ((index, p or f, cluster_id))
                    message = jmap.pack(UPDATE, index[0], index[1], index[2])
                    # print(message)
                    r = self.send(UPDATE, message)
                    if(type(r) != dict):
                        r = r.json()
                    results = r['results']
                    print("Results of Index UPDATE: " + results)
              
            config_["CONF"]["last_segment_id"] = str(segment_count)
            with open('config.ini', 'w') as conf:
                config_.write(conf)          
            encrypt_idx_ts = datetime.now()
        
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

        for f in os.listdir("tmp/"):
            os.remove(os.path.join("tmp/", f))
        
        encrypt_ts = datetime.now()
        
        print("\nStats (time required):")
        # print("Encode segments: {}\nUpdate index: {}\nEncrypt index: {}\nEncrypt segments: {}\n"
            #   .format(encode_ts-begin_ts, update_idx_ts-encode_ts, encrypt_idx_ts-update_idx_ts, encrypt_ts-encrypt_idx_ts))
        print("Encoding: {}\nEncrypting: {}\nTotal: {}".format(encode_ts-begin_ts, encrypt_ts-encode_ts, encrypt_ts-begin_ts))

        for f in os.listdir("enc/"):
            os.remove(os.path.join("enc/", f))


    def search(self, query, base_ts=0, search_type='', query_type=None):
        return_result = ""
        return_result += "metainfo: %s\n" % time()
        begin_ts = time()
        
        L = []
        word = query.lower()
        schema_id = get_schema_id(query_type)
        if SSE_MODE == 0:
            (segments_ids, cluster_ids) = get_segment_cluster_info(word, schema_id)
        else:
            cluster_ids = get_cluster_id(word, schema_id)
            
            k1 = self.PRF(self.k, ("1" + word))
            k2 = self.PRF(self.k, ("2" + word)).encode('latin1', 'ignore')
            
            if SSE_MODE == 1:
                L.append((k1))
            elif SSE_MODE == 2:
                for cid in cluster_ids:
                    count = get_count(word, cid, schema_id)
                    L.append((k1, count))
            message = jmap.pack(SEARCH, L, query_type, cluster_ids)
            ret_data = self.send(SEARCH, message)

            segments_e = ret_data['results']
            segments_ids = []
            
            for each in segments_e:
                m_str = ''
                m = self.dec(k2, each).decode()
                for x in m:
                    if x in string.printable:
                        m_str += x
                for msg in m_str.split(DELIMETER):
                    if msg not in segments_ids:
                        segments_ids.append(str(msg))
            
            
        print("segs = ", segments_ids)
        print("clus = ", cluster_ids)
        
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
        
        # print(relevant_segments)
        return_segments = []
        for each in segments_ids:
            if each in relevant_segments:
                return_segments.append(each)
        index_ts = time()
        print ("index time: ", index_ts-begin_ts)
        
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
        lookup_table = get_lookup_table(cur, return_segments)
        # print(lookup_table)
        for i in results:
            decrypted = self.decryptSegment(i.encode('latin1'), )
            decrypted_ = decrypted.split('\n')[:-1]
            for cid in cluster_ids:
                l = LogHandler(lookup_table, cid)
                for each in decrypted_:
                    decoded = l.decode(each)
                    # print(decoded)
                    if re.search(r'\b{}\b'.format(word), decoded):
                        decoded_message += (decoded+'\n')
        
        return_result += "metainfo: %s\n" % time()
        return_result += "%s" % decoded_message
        print(return_result)
        return(return_result)


    # def search_segments(self, segments, cluster_ids):
    #     message = jmap.pack(SEARCH_DOC, segments)
    #     ret_data = self.send(SEARCH_DOC, message)
    #     cur = self.db.cursor()
    #     if(type(ret_data) != dict):
    #         ret_data = ret_data.json()
    #     results = ret_data['results']

    #     begin_ts = time()
    #     decoded_message = ''''''
    #     lookup_table = get_lookup_table(cur, segments)
    #     for i in results:
    #         decrypted = self.decryptSegment(i.encode('latin1'), )
    #         decrypted_ = decrypted.split('\n')[:-1]
    #         for cid in cluster_ids:
    #             l = LogHandler(lookup_table, cid)
    #             for each in decrypted_:
    #                 decoded = l.decode(each)                    
    #                 decoded_message += (decoded+'\n')
    #     end_ts = time()
    #     print("decrypt-decode: ", end_ts-begin_ts)
        

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
            # print("server-processing-time:", float(server_out_time)-float(server_in_time)) # server processing time
            print("nw-time:", client_in_time-client_out_time) # total network time
        return (result_json)
