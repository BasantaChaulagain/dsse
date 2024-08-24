############
#
# index_handler.py
#
# Contains class Index_Handler, takes an individual log as input. 
# Responsible for parsing logs and creating ltdict, and vdict, and making index files.
#
############

import re
from configparser import ConfigParser

timestamp_id_pattern = [r"\d{10}\.\d{3}\:\d+", 
                r"\d{4}(\/|\-|\:)\d{2}(\/|\-|\:)\d{2}(T|\s+|\:)\d{0,24}\:\d{0,59}\:\d{0,59}"]

# this captures everything in the form key=value where values can have space in between (like filename with space.)
kv_pattern = re.compile(r'(\w+\=(?:\"|\().*?(?:\"|\))|\w+\=\S+)')

csv_pattern = re.compile(r'\s*(.*?);')

# more generic regex should be written at the end.
variable_schema = { '0': r'\w+\(\d+\)',
                    '1': r'\"[\/\w\-\_]+\"',
                    '2': r'\([\w]+\)',
                    '3': r'([A-Za-z]+\[\d+\]\=[\w]+\s*)+',
                    '4': r'[A-Za-z]+\[\d+\]',
                    '5': r'\d+_\d+\.\d+',
                    '6': r'\d+\.\d+\_\d+\_\d+',
                    '7': r'(\/[\w\.]+)+',
                    '8': r'[A-Za-z\.]+',
                    '9': r'-?\d+',
                    '10': r'[\da-fA-F]+',
                    '11': r'[\d\w]+',
                    '12': r'\s*',
                    '13': r'.*?'
                   }

CSV_INPUT = 1
ENCODING_FLAG = 1

config_ = ConfigParser()
config_.read("config.ini")
SSE_MODE = int(config_["GLOBAL"]["SSE_MODE"])

class LogHandler:
    def __init__(self, lookup_table, cluster_id):
        self.lt_string = ""             # id,lt_string,segment
        self.variable = []
        self.variable_ids = ""
        self.log_type_id = ""
        self.cid = cluster_id

        if cluster_id not in lookup_table[0].keys():
            lookup_table[0][cluster_id] = {}
        if cluster_id not in lookup_table[1].keys():
            lookup_table[1][cluster_id] = {}

        self.vdict = lookup_table[1]
        self.ltdict = lookup_table[0]
        
    def get_updated_lookup_table(self):
        return [self.ltdict, self.vdict]

    def extract_timestamp(self, log):
        ts = log.split(';')[1].split(';')[0].split('(')[0].strip(' ')
        return ts

    def extract_event_id(self, log):
        eid = log.split(';')[0]
        return eid

    def get_variable_id(self, var, dict):
        for key, value in dict.items():
            if value[0] == var:
                return key
        return None
    
    def get_log_type_id(self, ltstring):
        for key, value in self.ltdict[self.cid].items():
            if value == ltstring:
                return(key)
        return None

    # code to find the variables and log_type
    def parse_log(self, log):
        match = csv_pattern.findall(log)
        if match:
            self.variable = match[2:]
            for each in self.variable:
                if each:
                    schema_id = '1'
                else:
                    schema_id = '0'
                self.lt_string = self.lt_string + schema_id + ' '
            self.lt_string = self.lt_string.rstrip(' ')
    
    
    # function to unparse log that is in csv format
    def unparse_log_csv(self, ts, eid):
        lt_keys = self.lt_string.split(' ')
        log_variables = []
        for schema_id, lt_key in enumerate(lt_keys):            
            if lt_key == '1':
                var_dict = self.vdict[self.cid][str(schema_id)]
                var = var_dict.get(self.variable_ids[schema_id])[0]
                log_variables.append(var)
            elif lt_key == '0':
                log_variables.append('')
        log = '; '.join(log_variables)
        log = eid + "; " + ts + "; " + log + ";"
        return(log)


    def write_to_vdict(self, segment, first_log):
        variable_ids = ""
        for key, var in enumerate(self.variable):
            if var:
                schema_id = str(key)
                vdict_each = self.vdict[self.cid].get(schema_id)
                if not vdict_each:
                    self.vdict[self.cid][schema_id] = {}
                    vdict_each = self.vdict[self.cid].get(schema_id)
                size_vdict_each = len(vdict_each)
                var_id = self.get_variable_id(var, vdict_each)
                
                # if the variable is not already present:
                if not var_id:
                    var_id = str(size_vdict_each)
                    if SSE_MODE == 2:
                        self.vdict[self.cid][schema_id][var_id] = [var, 0, 1, [segment]]
                    else:
                        self.vdict[self.cid][schema_id][var_id] = [var, [segment]]
                else:
                    if SSE_MODE == 2:
                        if first_log:
                            self.vdict[self.cid][schema_id][var_id][1] = self.vdict[self.cid][schema_id][var_id][2]
                        self.vdict[self.cid][schema_id][var_id][2] += 1
                        segment_list = self.vdict[self.cid][schema_id][var_id][3]
                    else:
                        segment_list = self.vdict[self.cid][schema_id][var_id][1]
                    if segment not in segment_list:
                        segment_list.append(segment)
            else:
                var_id = '0'            
            variable_ids = variable_ids + var_id + ","
        self.variable_ids = variable_ids.rstrip(',')
                
        
    def write_to_ltdict(self):
        logtype_id = self.get_log_type_id(self.lt_string)
        # if log_type_id is not present, add the ltstring, else just update the segment id and count.
        if not logtype_id:
            size_ltdict = len(self.ltdict[self.cid])
            self.ltdict[self.cid][str(size_ltdict)] = self.lt_string
        

    # code to encode the message using ltdict and vdict
    def encode(self, log, segment, first_log):
        ts = self.extract_timestamp(log)
        eid = self.extract_event_id(log)
        self.parse_log(log)
        self.write_to_vdict(segment, first_log)
        self.write_to_ltdict()
        logtype_id = self.get_log_type_id(self.lt_string)
        encoded_message = ts + ":" + eid + "," + logtype_id + "," + self.variable_ids
        return(encoded_message)
    
    
    #code to decode the message using ltdict and vdict
    def decode(self, encoded_log):
        try:
            splitted = encoded_log.split(",",2)
            ts = splitted[0].split(":")[0]
            eid = splitted[0].split(":")[1]
            
            logtype_id = splitted[1]
            self.variable_ids = splitted[2].split(',')

            # look from here:
            self.lt_string = self.ltdict[self.cid].get(logtype_id)
            log = self.unparse_log_csv(ts, eid)
            
            return (log)
        except:
            # print("unable to decode:\t", encoded_log)
            return ""


# logs = [
#     '''35559695; 1471074506.950(Sat Aug 13 03:48:26 2016); read(0); 4096;  a[0]=0x4 a[1]=0x7fc46876a000 a[2]=0x1000; 49011_1471074506.930; 0.000_0_0; ; 49005; sudo; /usr/bin/sudo; 0; 0; 1003; 4; file; login.defs; /etc/login.defs; 131246; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ''',
#     '''917008067; 1670087460.743(Sat Dec  3 12:11:00 2022); rename(82); 0;  a[0]=0x336200646200 a[1]=0x336200271f70; 5035_1670087440.624; 0.000_0_0; 5035; 4958; Chrome_ChildIOT; /usr/share/code/code; 1000; 1000; 1000; ; file; the-real-index; /home/lab301/.config/Code/Cache/Cache_Data/index-dir/the-real-index; 24906515; ; ; ; file; the-real-index; /home/lab301/.config/Code/Cache/Cache_Data/index-dir/the-real-index; 24906513; ; ; ; ; ; 3690199849677304375; ; ; ; '''
# ]

# lookup = [{}, {}]
# for log in logs:
#     l = LogHandler(lookup, "c0")
#     e = l.encode(log, 'seg1')
#     print(lookup)
#     print(e)

# for log in enc_logs:
#     l = LogHandler(lookup, "c1")
#     e = l.decode(log)
#     print(e)
