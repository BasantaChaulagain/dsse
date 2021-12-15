############
#
#  file_handler.py
#
# Contains class File_Handler, takes file as input. 
# Responsible for dividing files into segments. Storing the information in database.
#
############

import inspect
import os
import sqlite3
import sys
import uuid

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from client.log_handler import LogHandler

# Number of logs in each segment. (threshold value)
NUM_OF_LOGS = 4

FILE_ = 'orig/sample1.log'

class FileHandler():
    def __init__(self, file):
        self.file_to_handle = file
        self.db = sqlite3.connect('metadata')
        if self.db == None:
            print("Error while opening database")

    def get_new_file(self):
        new_file_name = 'tmp/'+str(uuid.uuid4())
        new_file = open(new_file_name, 'a+')
        return new_file

    def fragment(self):
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


f = FileHandler(FILE_)
# f.fragment()