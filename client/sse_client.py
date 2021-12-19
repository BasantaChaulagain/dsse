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

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import bcrypt
import binascii
import string
import dbm
from flask import Flask
import requests
from nltk.stem.porter import PorterStemmer
import os
import inspect
import sys

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from jmap import jmap
from client.file_handler import FileHandler
from client.log_handler import LogHandler

DEBUG = 1
SEARCH = "search"
UPDATE = "update"
ADD_MAIL = "addmail"

# Default url is localhost, and the port 5000 is set by Flask on the server
DEFAULT_URL = "http://127.0.0.1:5000/"

NO_RESULTS = "Found no results for query"

DELIMETER = "++?"

# TODO: Maybe strip out some of the excluded punctuation. Could be useful
# to keep some punct in the strings. We're mostly looking to strip the
# final punct (ie: '.' ',' '!' etc)
EXCLUDE = string.punctuation

app = Flask(__name__)

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


    def encryptSegment(self, infile, outfile):

        # read in infile (opened file descriptor)
        buf = infile.read()
        if buf == '': 
            print("[Enc] mail to encrypt is empty!\nExiting\n")
            exit(1)

        if (DEBUG > 1): print(("[Enc] mail to encrypt: %s\n" % (buf)))

        # pad to mod 16
        while len(buf)%16 != 0:
            buf = buf + "\x08"

        # write encrypted data to new file
        outfile.write((self.iv + self.cipher.encrypt(buf.encode('latin1'))))

    def decryptSegment(self, buf, outfile=None):
        # Just pass in input file buf and fd in which to write out

        if buf == '': 
            print("[Dec] mail to decrypt is empty!\nExiting\n")
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
            print(tmp.decode('latin1'))


    def encryptSegmentID(self, k2, document, word=None, index_IDs=None):

        # Encrypt doc id (document) with key passed in (k2)

        # set up new cipher using k2 and random iv
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(k2[:16].encode('latin1'), AES.MODE_CBC, iv)

        document = document.encode('latin1')
        # pad to mod 16
        while len(document)%16 != 0:
            document = document + b'\x08'

        # If word and index_IDs are supplied, then we're updated the 
        # existing list of ids for a corresponding word/term.
        # This is used so that we can encrypt a list of mailIDs, rather
        # than just a single one, speeding up SEARCH routine later.
        if word and index_IDs:
            IDs = index_IDs[word]
            IDs = IDs.decode() + DELIMETER + document.decode() 

            while len(IDs)%16 != 0:
                IDs = IDs + "\x08"

            encId = iv + cipher.encrypt(IDs.encode('latin1'))

        # Else, encrypt single document (likely meaning it's the first time
        # a particular word has been found in the mail, so the first ID to
        # get added to the index for that word
        else:
            encId = iv + cipher.encrypt(document)

        if (DEBUG > 1):
            print(("New ID for '%s' = %s" % 
                 (document, (binascii.hexlify(encId)))))

        return binascii.hexlify(encId)


    def update(self, infilename, outfilename):

        # First update index and send it
        data = self.update_index(infilename)
        message = jmap.pack(UPDATE, data, "1")
        r = self.send(UPDATE, message)
        data = r.json()
        results = data['results']
        print("Results of UPDATE: " + results) 
        
        # Then encrypt msg
        infile = open(infilename, "r")     
        outfilename_full = "enc/" + outfilename
        outfile = open(outfilename_full, "wb+")
        self.encryptSegment(infile, outfile)
        infile.close()
        
        outfile.seek(0)
        data = binascii.hexlify(outfile.read())
        message = jmap.pack(ADD_MAIL, data, "1", outfilename)

        # Then send message
        r = self.send(ADD_MAIL, message, outfilename)        
        data = r.json()
        results = data['results']
        print("Results of UPDATE/ADD FILE: " + results)

        outfile.close()


    def update_index(self, document):

        # Open file, read it's data, and close it
        msg_lines = []
        with open(document, "r") as infile:
            msg_lines = infile.readlines()
        infile.close()

        # Parse body of email and return list of words
        word_list = self.parseDocument(msg_lines)

        if (DEBUG > 1): print("[Update] Words from doc: " + str(word_list))

        # Encrypt the index to send to the server (body terms)
        index = self.encryptIndex(document.split("/")[1], word_list)

        if (DEBUG > 1):
            print("\n[Client] Printing list elements to add to index")
            for x in index:
                print("%s\n%s\n\n" % (x[0], x[1]))
        return index


    def parseDocument(self, logs):

        # Iterate through email's body, line-by-line, word-by-word,
        # strip unwanted characters, skip duplicates, and add to list
        word_list = []
        for line in logs:
            for word in line.split():
                try:
                    if any(s in EXCLUDE for s in word):
                        word = self.removePunctuation(word)
                        word = self.stemmer.stem(word)
                    word = word.lower()
                    word = word.encode('latin1', 'ignore')
                    if  word not in word_list and b'\x08' not in word:
                        word_list.append(word)
                # except catches case of first word in doc, and an
                # empty list cannot be iterated over
                except:
                    if any(s in EXCLUDE for s in word):
                        word = self.removePunctuation(word)
                    word = self.stemmer.stem(word)
                    word = word.lower()
                    word = word.encode('latin1', 'ignore')
                    word_list = [word]

        return word_list


    def removePunctuation(self, string):
        return ''.join(ch for ch in string if ch not in EXCLUDE)


    def encryptIndex(self, document, word_list):

        # This is where the meat of the SSE update routine is implemented

        if (DEBUG > 1): 
            print("Encrypting index of words in '%s'" % document)

        L = []
        index = dbm.open("index", "c")
        index_IDs = dbm.open("index_IDs", "c")
       
        # For each word, look through local index to see if it's there. If
        # not, set c = 0, and apply the PRF. Otherwise c == number of 
        # occurences of that word/term/number 

        for w in word_list:
            if type(w) == bytes:
                w = w.decode()
            # Initialize K1 and K2
            k1 = self.PRF(self.k, ("1" + w))
            k2 = self.PRF(self.k, ("2" + w))

            if (DEBUG > 1): print(("k1 = %s\nk2 = %s\n" % (k1, k2)))

            # counter "c" (set as 0 if not in index), otherwise set
            # as number found in index (refers to how many documents
            # that word appears in
            c = 0
            found = 0
            try:
                c = int(index[w])
                found = 1
                if (DEBUG > 1): 
                    print(("Found '%s' in db. C = %d" % (w, c)))
            except:
                c = 0
 
            # Set l as the PRF of k1 (1 || w) and c (num of occur) if 
            # parsing the body (ENC_BODY).
            # If parsing header list, then PRF k1 and header term.
            
            l = self.PRF(k1, str(c))
            lprime = self.PRF(k1, str(c-1))

            # Update encryptSegmentID() opens index_IDs and appends
            # new document to list with DELIMETER and encrypts all.
            # Set d as encrypted mail id [list]
            if not found:
                d = self.encryptSegmentID(k2, document).decode()
            else:
                d = self.encryptSegmentID(k2, document, w, index_IDs).decode()

            if (DEBUG > 1):
                print("w = " + w + "\tc = " + str(c))
                print(("l = %s\nd = %s\n" % (l, d)))

            # Increment c (1 indexed, not 0), then add unecrypted
            # values to local index, and append encrypted/hashed
            # values to L, the list that will extend the remote index
            c = c + 1
            index[w] = str(c)
            if found:
                IDs = index_IDs[w].decode()
                if document not in IDs.split(DELIMETER):
                    index_IDs[w] = IDs + DELIMETER + document
            else:
                index_IDs[w] = document

            L.append((l, d, lprime))

        index.close()
        index_IDs.close()

        return L


    def search(self, query):

        index = dbm.open("index", "r")
        query = query.split()

        # Generate list of querys (may be just 1)
        L = []
        for i in query:
            if (DEBUG > 1): print(repr(i))
            i = i.lower()

            # For each term of query, first try to see if it's already in
            # index. If it is, send c along with k1 and k2. This will 
            # massively speed up search on server (1.5 minutes to < 1 sec)
            try:
                c = index[i]
            except:
                c = None

            # Use k, term ('i') and '1' or '2' as inputs to a pseudo-random
            # function to generate k1 and k2. K1 will be used to find the 
            # correct encrypted entry for the term on the server, and k2
            # will be used to decrypt the mail ID(s)
            k1 = self.PRF(self.k, ("1" + i))
            k2 = self.PRF(self.k, ("2" + i))

            # If no 'c' (term not in local index so likely not on server),
            # just send k1 and k2. Will take a long time to return false
            # TODO, should the client just kill any search for a term not
            # in local index?  Can we rely on the local index always being
            # up to date?
            if not c:
                L.append((k1, k2))
            # Otherwise send along 'c'-1. 
            else:
                c = str(int(c)-1)
                L.append((k1, k2, c))

            if (DEBUG > 1): 
                print("k1 = " + k1)
                print("k2 = " + k2)

        message = jmap.pack(SEARCH, L, "1")

        # Send data and unpack results.
        r = self.send(SEARCH, message) 
        ret_data = r.json()
        results = ret_data['results']
        print("Results of SEARCH:")

        if results == NO_RESULTS:
            print(results)
            return -1

        # Print out messages that are returned from server
        # TODO: Should recieve and print out mail, or just recieve mailIDs
        # and resend requests for those messages?

        # FIXME: hack to decide if server is returning encrypted msgs (1)
        # or just the decrypted IDs (0)
        FILES = 1
        for i in results:
            if (FILES):
                self.decryptSegment(i.encode('latin1'), )
            else:
                print(i)


    def PRF(self, k, data):
        if type(data) == str:
            data = data.encode('latin1')
        if type(k) == str:
            k = k.encode('latin1')
        hmac = HMAC.new(k, data, SHA256)
        return hmac.hexdigest()


    def send(self, routine, data, filename = None, in_url = DEFAULT_URL):
        print("sending to ", in_url)
        url = in_url

        # Currently, each server url is just <IP>/<ROUTINE>, so just append
        # routine to url, and set up headers with jmap package.

        if routine == SEARCH:
            url = url + SEARCH
            headers = jmap.jmap_header()
        elif routine == UPDATE:
            url = url + UPDATE
            headers = jmap.jmap_header()
        elif routine == ADD_MAIL:
            url = url + ADD_MAIL
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
        return requests.post(url, data, headers = headers)


    def testSearch(self, index):
        '''
        Method for testing locally if the encryption in the update
        routine is actually accurate. 
        -create a static search term (ie: "the")
        -generate hashes with self.k (ie generate k1 and k2)
        -implement the backend get() and dec() methods to see if they
         return the correct data
        -try with search query that isn't in index
        '''

        # 'Client' activities
        query = "This"
        k1 = self.PRF(self.k, ("1" + query))
        k2 = self.PRF(self.k, ("2" + query))

        if (DEBUG > 1): 
            print(("[testSearch]\nk1:%s\nk2:%s" % (k1, k2)))

        # 'Server' activities
        c = 0
        found = 0
        while c < len(index):
            if (DEBUG): print("c = " + str(c))
            result = self.testGet(index, k1, c)
            if result: break
            c = c + 1

        if not result:
            print("NOT FOUND in INDEX")

        else:
            print("FOUND RESULT")


    def testGet(self, index, k, c):

        cc = 0
        while cc < len(index):
            F = self.PRF(k, str(c))
            if (DEBUG > 1):
                print("[Get] F: " + F)
                print("[Get] Idx: " + index[cc][0] + "\n")
            if F == index[cc][0]:
                return F
            cc = cc + 1
