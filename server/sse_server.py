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
#  sse_server.py
#
#  Serves as SSE implementation for mail server. The routines 
#  for SSE are invoked by the server module via the API.
#
############

from datetime import timedelta
import os
import inspect
import sys

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from configparser import ConfigParser
import binascii
import dbm
import string
from flask import Flask
from flask import request
from flask import jsonify
from pathlib import Path
import time

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from jmap import jmap

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'enc'

config_ = ConfigParser()
config_.read("../client/config.ini")
SSE_MODE = int(config_["GLOBAL"]["SSE_MODE"])
print("mode", SSE_MODE)

DEBUG = 1

# CMD list
UPDATE = "update"
SEARCH = "search"
SEARCH_DOC = "search_doc"
ADD_FILE = "add"
SEARCH_METHOD = "getDecryptedSegments"
SEARCH_DOC_METHOD = "getEncryptedMessages"
UPDATE_METHOD = "updateEncryptedIndex"
ADD_FILE_METHOD = "putEncryptedMessage"

DELIMETER = "++?"

########
#
# SSE_Server
#
########

@app.route('/add', methods=['POST'])
def add_segment():

    # Return error if request is not properly formatted
    if not request.json:
        return jsonify(results='Error: not json')

    # Unpack 'arguments'
    (method, file, filename, id_num) = jmap.unpack(ADD_FILE, request.get_json())

    if method != ADD_FILE_METHOD:
        return jsonify(results='Error: Wrong Method for url')

    # return file to binary
    file = binascii.unhexlify(file)

    # open file and write to it locally
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
    f = open(path, "wb+")
    if type(file) == str:
        file = file.encode('latin1')
    f.write(file)
    f.close()

    return jsonify(results="GOOD ADD FILE")


@app.route('/update', methods=['POST'])
def update():
    # Return error if request is not properly formatted
    if not request.json:
        return jsonify(results='Error: not json')

    # Unpack 'arguments'
    (method, new_index, id_num, cluster_id) = jmap.unpack(UPDATE, request.get_json())

    if method != UPDATE_METHOD:
        return jsonify(results='Error: Wrong Method for url')

    # Open local ecypted index and get length
    index = dbm.open("indexes/"+str(cluster_id)+"_"+str(id_num)+"_index", "c")

    if SSE_MODE == 2:
    # Iterate through update list, replacing existing entries in local index if collisions
        for i in new_index:
            i0 = i[0].encode('latin1', 'ignore')
            i1 = i[1].encode('latin1', 'ignore')
            if i[2]:
                i2 = i[2].encode('latin1', 'ignore')
            match = i2 or i0

            # Go through local index and compare, if match, then delete that entry and add new one.
            for k in index.keys():
                if match == k: # and i1 == v:
                    del index[k]
                    break

            index[i0] = i1
            
    elif SSE_MODE == 1:
    # Iterate through add list, adding new entries
        for i in new_index:
            # i0 is the key (ie the hashed term), 
            # i1 is the value (encrypted list of mailIDs where that word is present.
            i0 = i[0].encode('latin1', 'ignore')
            i1 = i[1].encode('latin1', 'ignore')

            index[i0] = i1

    index.close()
    return jsonify(results="GOOD UPDATE")


@app.route('/search', methods=['POST'])
def search():
    print("in search")
    in_time = time.time()
    if not request.json:
        return jsonify(results='Error: not json')

    (method, query, id_num, cluster_id) = jmap.unpack(SEARCH, request.get_json())
    print(query, id_num, cluster_id)

    if method != SEARCH_METHOD:
        return jsonify(results='Error: Wrong Method for url')

    # query is a list of search terms, so each 'i' is a word/query
    # each word/query is a tuple containing k1, a hash of the search term,
    # and k2 for decrypting the document name(s).  Use k1 to match the key 
    # and use k2 to decrypt each value (mail ID or name) that is associated
    # with that key.
    results = []
    
    for i in range(len(cluster_id)):
        index = dbm.open("indexes/"+cluster_id[i]+"_"+id_num+"_index", "r")
        print("searching in file: ", "indexes/"+cluster_id[i]+"_"+id_num+"_index")
            
        if SSE_MODE == 1:
            seg_ids = index[query[i]].decode('latin1')
            results.append(seg_ids)

        elif SSE_MODE == 2:
            k1 = query[i][0].encode('latin1', 'ignore')
            count = query[i][1].encode('latin1', 'ignore') or b'0'
            
            seg_ids = new_get(index, k1, count).decode('latin1')
            results.append(seg_ids)

    # 'd' represents an encrypted id number for a message (in the 
    # simple case, just the message's name).

    # Go through list of d's in which the search query was found and
    # dec() each and add to list of id's (M).
    # Send those messages are found to the client
    return ({"results":results})


@app.route('/search_doc', methods=['POST'])
def search_doc():
    in_time = time.time()
    if not request.json:
        return jsonify(results='Error: not json')

    (method, query) = jmap.unpack(SEARCH_DOC, request.get_json())
    print(query)
    
    if method != SEARCH_DOC_METHOD:
        return jsonify(results='Error: Wrong Method for url')
        
    buf = []
    
    for seg_id in query:
        path = os.path.join(app.config['UPLOAD_FOLDER'], seg_id)
        fd = open(path, "rb")
        buf.append(fd.read().decode('latin1'))
        fd.close()
    
    out_time = time.time()
    buf.append(in_time)
    buf.append(out_time)
    return jsonify(results=buf)


# Decrypt doc ID using k2
def dec(k2, d):
    d_bin = binascii.unhexlify(d) 
    iv = d_bin[:16]
    cipher = AES.new(k2[:16], AES.MODE_CBC, iv)
    doc = cipher.decrypt(d_bin[16:])

    return doc


def PRF(k, data):
    if type(data) == str:
            data = data.encode('latin1')
    if type(k) == str:
        k = k.encode('latin1')
    hmac = HMAC.new(k, data, SHA256)
    return hmac.hexdigest()

def get_index_len(index):
    # TODO: crappy hack for now. Need to get size of index,
    # but I'm not sure what the best method is. So for now, 
    # just iterate through and grab the count.
    count = 0
    for k in index.keys():
        count = count+1

    return count

# Use k1 (hashed search term) and c (num of files it's in) to get key, and 
# then value of index entry.
def new_get(index, k1, c):
    try:
        F = PRF(k1, c)
        d = index[F]
    except:
        d = None
    return d


if __name__ == '__main__':
    app.run(debug=True)

