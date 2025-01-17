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
from configparser import ConfigParser

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from client.log_handler import LogHandler

config_ = ConfigParser()
config_.read("config.ini")

NUM_OF_LOGS = int(config_["CONF"]["num_of_logs"])
NUM_OF_SEGMENTS = int(config_["CONF"]["num_of_segments"])
NUM_OF_CLUSTERS = int(config_["CONF"]["num_of_clusters"])
SSE_MODE = int(config_["GLOBAL"]["SSE_MODE"])

class FileHandler():
    def __init__(self, file):
        self.file_to_handle = file
        self.segments = []
        self.db = sqlite3.connect('metadata')
        self.db.execute('''CREATE TABLE IF NOT EXISTS SEGMENT_INFO (file_id text, segment_id text, cluster_id text, clustergroup_id text, ts_start real, ts_end real)''')
        if self.db == None:
            print("Error while opening database")
            
        if not os.path.exists('tmp/'):
            os.makedirs('tmp/')
        if not os.path.exists('enc/'):
            os.makedirs('enc/')
        if not os.path.exists('vdict/'):
            os.makedirs('vdict/')
        if not os.path.exists('ltdict/'):
            os.makedirs('ltdict/')
        if not os.path.exists('../server/indexes/'):
            os.makedirs('../server/indexes/')
        if not os.path.exists('../server/enc/'):
            os.makedirs('../server/enc/')
            

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
            if(f.readline() == b'\n'):
                pass
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


    def insert_to_metadata_db(self, segment, cluster_id, clustergroup_id):
        file_id = self.file_to_handle.split('/')[1]
        ts_start, ts_end = self.get_timestamps_from_segment(segment)
        segment = segment.split('/')[1]
        self.db.execute('''INSERT INTO SEGMENT_INFO (file_id, segment_id, cluster_id, clustergroup_id, ts_start, ts_end) VALUES (?, ?, ?, ?, ?, ?)''',(file_id, segment, cluster_id, clustergroup_id, ts_start, ts_end))
        self.db.commit()


    def get_lookup_table(self, cg_id):
        try:
            with open('ltdict/ltdict_cg{}.json'.format(cg_id), 'r') as f:
                ltdict = json.load(f)
            with open('vdict/vdict_cg{}.json'.format(cg_id), 'r') as f:
                vdict = json.load(f)
        
        except FileNotFoundError:
            if not os.path.exists('ltdict/ltdict_cg{}.json'.format(cg_id)):
                with open('ltdict/ltdict_cg{}.json'.format(cg_id), 'w+') as f:
                    ltdict = {}
                    json.dump(ltdict, f)   
            if not os.path.exists('vdict/vdict_cg{}.json'.format(cg_id)):
                with open('vdict/vdict_cg{}.json'.format(cg_id), 'w+') as f:
                    vdict = {}
                    json.dump(vdict, f)
                    
        lookup_table = [ltdict, vdict]
        return lookup_table
    
    
    def set_lookup_table(self, lookup_table, cg_id):
        # lookup_table in the format [ltdict, vdict]
        with open('ltdict/ltdict_cg{}.json'.format(cg_id), 'w+') as f:
            ltdict = lookup_table[0]
            json.dump(ltdict, f)
        with open('vdict/vdict_cg{}.json'.format(cg_id), 'w+') as f:
            vdict = lookup_table[1]
            json.dump(vdict, f)
            
            
    def write_to_file(self, content, segment):
        with open(segment, 'w+') as f:
            f.write(content)


    def encode_logs(self):
        segment_count = int(config_["CONF"]["last_segment_id"])
        
        for segment in self.segments:
            cluster_id = int(segment_count/NUM_OF_SEGMENTS)
            clustergrp_id = int(cluster_id/NUM_OF_CLUSTERS)
            segment_count+=1
            
            print("encoding the segment {}: {}".format(segment_count, segment))
            lookup_table = self.get_lookup_table(clustergrp_id)      # [{},{}] initially
            encoded_content = ""
            with open(segment, 'r') as seg:
                for log in seg:
                    segment_id=segment.split('/')[1]        # get filename only
                    l = LogHandler(lookup_table, "c"+str(cluster_id))
                    encoded_message = l.encode(log, segment_id, None)
                    encoded_content = encoded_content + "\n" + encoded_message
                    lookup_table = l.get_updated_lookup_table()
            self.set_lookup_table(lookup_table, clustergrp_id)
    
            self.write_to_file(encoded_content, segment)
            self.insert_to_metadata_db(segment, "c"+str(cluster_id), "cg"+str(clustergrp_id))
            
        # write last_cluster_id to conf file after processing all the segments
        config_["CONF"]["last_segment_id"] = str(segment_count)
        with open('config.ini', 'w') as conf:
            config_.write(conf)
        
        
    def encode_logs_(self, segment, segment_count, cluster_id, clustergrp_id):
        print("encoding the segment {}: {}".format(segment_count, segment))
        lookup_table = self.get_lookup_table(clustergrp_id)      # [{},{}] initially
        encoded_content = ""
        with open(segment, 'r') as seg:
            first_log = True
            for log in seg:
                segment_id=segment.split('/')[1]        # get filename only
                l = LogHandler(lookup_table, "c"+str(cluster_id))
                encoded_message = l.encode(log, segment_id, first_log)
                encoded_content = encoded_content + "\n" + encoded_message
                lookup_table = l.get_updated_lookup_table()
                first_log = False
        self.set_lookup_table(lookup_table, clustergrp_id)
        
        self.write_to_file(encoded_content, segment)
        self.insert_to_metadata_db(segment, "c"+str(cluster_id), "cg"+str(clustergrp_id))
        
    # def decode_logs(self):
    #     for segment in self.segments:
    #         with open(segment, 'r') as seg:
    #             for line in seg:
    #                 lookup_table = self.get_lookup_table()
    #                 l = LogHandler(lookup_table)
    #                 log = l.decode(line.rstrip('\n'))
    #                 self.write_to_file(log, segment+'_')


# file = FileHandler("orig/sample.csv")
# file.split_file()
# file.encode_logs(True)
