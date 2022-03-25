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
NUM_OF_LOGS = 21
CSV_INPUT = 1

class FileHandler():
    def __init__(self, file):
        self.file_to_handle = file
        self.segments = []
        self.db = sqlite3.connect('metadata')
        if self.db == None:
            print("Error while opening database")

    def get_new_segment(self):
        new_file_name = 'tmp/'+str(shortuuid.uuid())
        new_file = open(new_file_name, 'a+')
        self.segments.append(new_file_name)
        return new_file

    def split_file(self):
        segment = self.get_new_segment()
        line_count = 0
        with open(self.file_to_handle, 'r') as file_:
            for line in file_:
                if line_count < NUM_OF_LOGS:
                    segment.write(line)
                    line_count += 1         
                else:
                    segment.close()
                    segment = self.get_new_segment()
                    segment.write("")
                    segment.write(line)
                    line_count = 1
        segment.close()
        return self.segments

    def get_timestamps_from_segment(self, segment):
        with open(segment, 'rb') as f:
            first_line = f.readline().decode()
            try:  # catch OSError in case of a one line file 
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b'\n':
                    f.seek(-2, os.SEEK_CUR)
            except OSError:
                f.seek(0)
            last_line = f.readline().decode()
        ts_start = first_line.split(',')[0].split(':')[0]
        ts_end = last_line.split(',')[0].split(':')[0]
        return (ts_start, ts_end)

    def insert_to_metadata_db(self, segment):
        file_id = self.file_to_handle.split('/')[1]
        ts_start, ts_end = self.get_timestamps_from_segment(segment)
        segment = segment.split('/')[1]
        self.db.execute('''INSERT INTO file_segment (file_id, segment_id, ts_start, ts_end) VALUES (?, ?, ?, ?)''',(file_id, segment, ts_start, ts_end))
        self.db.commit()

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
        # lookup_table in the format [ltdict, vdict]
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

    def encode_logs(self):
        for segment in self.segments:
            with open(segment, 'r') as seg:
                for log in seg:
                    lookup_table = self.get_lookup_table()
                    segment_id=segment.split('/')[1]        # get filename only
                    l = LogHandler(lookup_table)
                    encoded_message = l.encode(log, segment_id)
                    self.write_to_file(encoded_message, segment+'_en')
                    lookup_table = l.get_updated_lookup_table()
                    self.set_lookup_table(lookup_table)
            os.remove(segment)
            os.rename(segment+'_en', segment)
            self.insert_to_metadata_db(segment)

        
    def decode_logs(self):
        for segment in self.segments:
            with open(segment, 'r') as seg:
                for line in seg:
                    lookup_table = self.get_lookup_table()
                    l = LogHandler(lookup_table)
                    log = l.decode(line.rstrip('\n'))
                    self.write_to_file(log, segment+'_')

# for a single file:
# f = FileHandler(FILE_)
# f.split_file()
# f.encode_logs()
# f.decode_logs()