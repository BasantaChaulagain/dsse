############
#
# index_handler.py
#
# Contains class Index_Handler, takes an individual log as input. 
# Responsible for parsing logs and creating ltdict, and vdict, and making index files.
#
############

import json
import re

log1 = '''type=SYSCALL msg=audit(1471074506.946:35559672): arch=c000003e syscall=0 success=no exit=-11 a0=4 a1=7fc786f02cd0 a2=10 a3=19078622 items=0 ppid=1 pid=1236 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="gmain" exe="/usr/lib/accountsservice/accounts-daemon" key=(null)'''
log2 = '''type=UNKNOWN[1327] msg=audit(1471074506.934:35559671): proctitle="/usr/lib/accountsservice/accounts-daemon"'''
log3 = '''type=DAEMON_START msg=audit(1471074506.938:4196): auditd start, ver=2.3.2 format=raw kernel=4.2.0-27-generic auid=1003 pid=49013 subj=unconfined  res=success'''

segment = "2b8797c5-cbe6-42b8-991a-8ac85a562498"
lookup_table = []

timestamp_id_pattern = [r"\d{10}\.\d{3}\:\d+", 
                r"\d{4}(\/|\-|\:)\d{2}(\/|\-|\:)\d{2}(T|\s+|\:)\d{0,24}\:\d{0,59}\:\d{0,59}"]

# this captures everything in the form key=value where values can have space in between (like filename with space.)
kv_pattern = re.compile(r'(\w+\=(?:\"|\().*?(?:\"|\))|\w+\=\S+)')

# more generic regex should be written at the end.
variable_schema = { '0': r'\"[\/\w\-\_]+\"',
                    '1': r'\([\w]+\)', 
                    '2': r'[A-Za-z]+', 
                    '3': r'-?\d+', 
                    '4': r'[\d\w]+',
                    '5': r'[A-Za-z]+\[\d+\]',
                    '6': r'.*?'
                   }


class LogHandler:
    def __init__(self, log, segment, lookup_table):
        self.log = log
        self.segment = segment
        self.lt_string = ""             # id,lt_string,segment
        self.variable = []
        self.log_type_id = ""
        self.encoded_message = ""       # timestamp,log_type_id,variable values
        if len(lookup_table) != 0:
            self.vdict = lookup_table[1]
            self.ltdict = lookup_table[0]
        else:
            self.vdict = {}
            self.ltdict = {}

    def get_updated_lookup_table(self):
        return [self.ltdict, self.vdict]

    def extract_timestamp(self):
        for ts_patt in timestamp_id_pattern:
            ts_patt = re.compile(ts_patt)
            match = ts_patt.search(self.log)
            if match:
                return(match.group())

    def get_schema_id(self, var):
        for key, value in variable_schema.items():
            match = re.fullmatch(value, var)
            if match:
                return(key)

    def get_variable_id(self, var, dict):
        for key, value in dict.items():
            if value[0] == var:
                return key
        return None
    
    def get_log_type_id(self, ltstring):
        for key, value in self.ltdict.items():
            if value[0] == ltstring:
                return(key)
        return None

    # code to find the variables and log_type
    def parse_log(self):
        match = kv_pattern.findall(self.log)
        if match:
            for each in match:
                key_value = each.split('=')
                # if key is msg field, take off the timestamp:id from the variable. This is specific to linux audit log.
                if key_value[0] == 'msg':
                    value = key_value[1].split('(')[0]                   
                else:
                    value = key_value[1]

                # if value not in self.variable:
                self.variable.append(value)
                schema_id = self.get_schema_id(value) 
                self.lt_string = self.lt_string+key_value[0]+'='+'\x11'+schema_id+' '
        
    def write_to_vdict(self):
        variable_unique = list(set(self.variable))
        for var in variable_unique:
            schema_id = self.get_schema_id(var)
            vdict_id = self.vdict.get(schema_id)
            if not vdict_id:
                self.vdict[schema_id] = {}
            vdict_id = self.vdict.get(schema_id)
            size_vdict_id = len(vdict_id)
            # if var not in any values in vdict_id, add to the dictionary, else update segment id.
            var_id = self.get_variable_id(var, vdict_id)
            if not var_id:
                self.vdict[schema_id][str(size_vdict_id)] = [var, [self.segment]]
            else:
                segment_list = self.vdict[schema_id][var_id][1]
                if self.segment not in segment_list:
                    segment_list.append(self.segment)

        
    def write_to_ltdict(self):
        logtype_id = self.get_log_type_id(self.lt_string)
        # if log_type_id is not present, add the ltstring, else just update the segment id.
        if not logtype_id:
            size_ltdict = len(self.ltdict)
            self.ltdict[str(size_ltdict)] = [self.lt_string, [self.segment]]
        else:
            segment_list = self.ltdict[logtype_id][1]
            if self.segment not in segment_list:
                segment_list.append(self.segment)
        
    def get_variable_ids(self):
        # get each schema_type from lt_string and lookup each variables in variable list with the the vdict of particular schema type.
        variable_ids = ""
        pattern = r'(?:\x11)(\d+)'
        match = re.findall(pattern, self.lt_string)
        if match and len(match)==len(self.variable):
            for schema_id, variable in zip (match, self.variable):
                var_dict = self.vdict[schema_id]
                var_id = self.get_variable_id(variable, var_dict)
                variable_ids = variable_ids + var_id +","
        variable_ids = variable_ids.rstrip(',')
        return variable_ids

    # code to encode the message using ltdict and vdict
    def encode(self):
        ts = self.extract_timestamp()
        self.parse_log()
        self.write_to_vdict()
        self.write_to_ltdict()
        variable_ids = self.get_variable_ids()
        logtype_id = self.get_log_type_id(self.lt_string)
        self.encoded_message = ts + "," + logtype_id + "," + variable_ids
        print(self.encoded_message)


# i = LogHandler(log2, segment, lookup_table)
# i.encode()