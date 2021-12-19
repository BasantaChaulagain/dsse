############
#
#  file_handler.py
#
# Contains class File_Handler, takes file as input. 
# Responsible for dividing files into segments. Storing the information in database.
#
############

import inspect
import json
import os
import sqlite3
import sys
import shortuuid

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from client.log_handler import LogHandler

# Number of logs in each segment. (threshold value)
NUM_OF_LOGS = 4

FILE_ = 'orig/sample1.log'
logs = ['''type=SYSCALL msg=audit(1471074506.946:35559672): arch=c000003e syscall=0 success=no exit=-11 a0=4 a1=7fc786f02cd0 a2=10 a3=19078622 items=0 ppid=1 pid=1236 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="gmain" exe="/usr/lib/accountsservice/accounts-daemon" key=(null)''',
    '''type=UNKNOWN[1327] msg=audit(1471074506.934:35559671): proctitle="/usr/lib/accountsservice/accounts-daemon"''',
    '''type=DAEMON_START msg=audit(1471074506.938:4196): auditd start, ver=2.3.2 format=raw kernel=4.2.0-27-generic auid=1003 pid=49013 subj=unconfined  res=success''',
    '''type=SYSCALL msg=audit(1471074506.946:35559673): arch=c000003e syscall=1 success=yes exit=8 a0=4 a1=7fc786f02c88 a2=8 a3=19158250 items=0 ppid=1 pid=1236 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="gmain" exe="/usr/lib/accountsservice/accounts-daemon" key=(null)'''
]
segment = ["2b8797c5-cbe6-42b8-991a-8ac85a562498", "2b8797c5-cbe6-42b8-991a-8ac85a562498", "3b8797c5-cbe6-42b8-991a-8ac85a562499", "1b8797c5-cbe6-42b8-991a-8ac85a562497"]
lookup_table = []
# lookup_table = [{'0': 'type=\x112 msg=\x112 arch=\x114 syscall=\x113 success=\x112 exit=\x113 a0=\x113 a1=\x114 a2=\x113 a3=\x113 items=\x113 ppid=\x113 pid=\x113 auid=\x113 uid=\x113 gid=\x113 euid=\x113 suid=\x113 fsuid=\x113 egid=\x113 sgid=\x113 fsgid=\x113 tty=\x111 ses=\x113 comm=\x110 exe=\x110 key=\x111 ', '1': 'type=\x115 msg=\x112 proctitle=\x110 ', '2': 'type=\x114 msg=\x112 ver=\x116 format=\x112 kernel=\x116 auid=\x113 pid=\x113 subj=\x112 res=\x112 ', '3': 'type=\x112 msg=\x112 arch=\x114 syscall=\x113 success=\x112 exit=\x113 a0=\x113 a1=\x114 a2=\x113 a3=\x114 items=\x113 ppid=\x113 pid=\x113 auid=\x113 uid=\x113 gid=\x113 euid=\x113 suid=\x113 fsuid=\x113 egid=\x113 sgid=\x113 fsgid=\x113 tty=\x111 ses=\x113 comm=\x110 exe=\x110 key=\x111 '}, {'3': {'0': '-11', '1': '19078622', '2': '0', '3': '10', '4': '1236', '5': '4', '6': '4294967295', '7': '1', '8': '1003', '9': '49013', '10': '8'}, '4': {'0': 'c000003e', '1': '7fc786f02cd0', '2': 'DAEMON_START', '3': '7fc786f02c88', '4':'19b58250'}, '2': {'0': 'audit', '1': 'no', '2': 'SYSCALL', '3': 'raw', '4': 'unconfined', '5': 'success', '6': 'yes'}, '0': {'0': '"gmain"', '1': '"/usr/lib/accountsservice/accounts-daemon"'}, '1': {'0': '(null)', '1': '(none)'}, '5': {'0': 'UNKNOWN[1327]'}, '6': {'0': '4.2.0-27-generic', '1': '2.3.2'}}]


class FileHandler():
    def __init__(self, file):
        self.file_to_handle = file
        self.db = sqlite3.connect('metadata')
        if self.db == None:
            print("Error while opening database")

    def get_new_file(self):
        new_file_name = 'tmp/'+str(shortuuid.uuid())
        new_file = open(new_file_name, 'a+')
        return new_file

    def split_file(self):
        segment = self.get_new_file()
        line_count = 0
        self.db.execute('''INSERT INTO file_segment (file_id, segment_id) VALUES (?, ?)''',(self.file_to_handle, segment.name))
        self.db.commit()

        with open(self.file_to_handle, 'r') as file_:
            for line in file_:
                if line_count < NUM_OF_LOGS:
                    segment.write(line)
                    line_count += 1                
                else:
                    segment.close()
                    segment = self.get_new_file()
                    self.db.execute('''INSERT INTO file_segment (file_id, segment_id) VALUES (?, ?)''',(self.file_to_handle, segment.name))
                    self.db.commit()
                    segment.write(line)
                    line_count = 1
        segment.close()

    def get_lookup_table(self):
        if not os.path.exists('ltdict.json'):
            with open('ltdict.json', 'w+') as f:
                ltdict = {}
                json.dump(ltdict, f)   
        if not os.path.exists('vdict.json'):
            with open('vdict.json', 'w+') as f:
                vdict = {}
                json.dump(vdict, f)
        else:
            with open('ltdict.json', 'r') as f:
                ltdict = json.load(f)
            with open('vdict.json', 'r') as f:
                vdict = json.load(f)
        lookup_table = [ltdict, vdict]
        return lookup_table
    
    def set_lookup_table(self, lookup_table):
        with open('ltdict.json', 'w+') as f:
            ltdict = lookup_table[0]
            json.dump(ltdict, f)   
        with open('vdict.json', 'w+') as f:
            vdict = lookup_table[1]
            json.dump(vdict, f)

    def write_to_file(self, line, segment):
        with open(segment, 'a+') as f:
            f.writelines(line)
            f.writelines('\n')

    def encode_logs(self, segment):
        with open(segment, 'r') as seg:
            for log in seg:
                lookup_table = self.get_lookup_table()
                segment_id=segment.split('/')[1]        # get filename only
                l = LogHandler(lookup_table)
                encoded_message = l.encode(log, segment_id)
                self.write_to_file(encoded_message, segment+'_en')
                lookup_table = l.get_updated_lookup_table()
                self.set_lookup_table(lookup_table)
        
    def decode_logs(self, segment):
        with open(segment, 'r') as seg:
            for line in seg:
                lookup_table = self.get_lookup_table()
                l = LogHandler(lookup_table)
                log = l.decode(line.rstrip('\n'))
                self.write_to_file(log, segment+'_de')

f = FileHandler(FILE_)
# f.split_file()
# f.encode_logs('tmp/jGUHKTFim7HpDoNqRUZ6f3')
f.decode_logs('tmp/jGUHKTFim7HpDoNqRUZ6f3_en')
