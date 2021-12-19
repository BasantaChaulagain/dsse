############
#
# index_handler.py
#
# Contains class Index_Handler, takes an individual log as input. 
# Responsible for parsing logs and creating ltdict, and vdict, and making index files.
#
############

import re
from sys import setdlopenflags

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
    def __init__(self, lookup_table):
        self.lt_string = ""             # id,lt_string,segment
        self.variable = []
        self.variable_ids = []
        self.log_type_id = ""
        if len(lookup_table) != 0:
            self.vdict = lookup_table[1]
            self.ltdict = lookup_table[0]
        else:
            self.vdict = {}
            self.ltdict = {}

    def get_updated_lookup_table(self):
        return [self.ltdict, self.vdict]

    def extract_timestamp(self, log):
        for ts_patt in timestamp_id_pattern:
            ts_patt = re.compile(ts_patt)
            match = ts_patt.search(log)
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
    def parse_log(self, log):
        match = kv_pattern.findall(log)
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
    
    def unparse_log(self, ts, variables):
        patt = re.compile(r'\w+\=\x11\d+')
        kv_pair = patt.findall(self.lt_string)
        updated_kv = []
        for each, var in zip(kv_pair, variables):
            each = re.sub(r'\x11\d+', var, each)
            if re.match(r'msg=\w+', each):
                each = each+"("+ts+"):"
            updated_kv.append(each)
        log = ' '.join(updated_kv)
        return log
        
    def write_to_vdict(self, segment):
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
                self.vdict[schema_id][str(size_vdict_id)] = [var, [segment]]
            else:
                segment_list = self.vdict[schema_id][var_id][1]
                if segment not in segment_list:
                    segment_list.append(segment)

        
    def write_to_ltdict(self, segment):
        logtype_id = self.get_log_type_id(self.lt_string)
        # if log_type_id is not present, add the ltstring, else just update the segment id.
        if not logtype_id:
            size_ltdict = len(self.ltdict)
            self.ltdict[str(size_ltdict)] = [self.lt_string, [segment]]
        else:
            segment_list = self.ltdict[logtype_id][1]
            if segment not in segment_list:
                segment_list.append(segment)
        
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

    def get_variables_from_id(self):
        variables = []
        pattern = r'(?:\x11)(\d+)'
        schema_ids = re.findall(pattern, self.lt_string)
        if schema_ids and len(schema_ids)==len(self.variable_ids):
            for schema_id, variable_id in zip(schema_ids, self.variable_ids):
                var_dict = self.vdict[schema_id]
                var = var_dict.get(variable_id)[0]
                variables.append(var)
        return variables

    # code to encode the message using ltdict and vdict
    def encode(self, log, segment):
        ts = self.extract_timestamp(log)
        self.parse_log(log)
        self.write_to_vdict(segment)
        self.write_to_ltdict(segment)
        variable_ids = self.get_variable_ids()
        logtype_id = self.get_log_type_id(self.lt_string)
        encoded_message = ts + "," + logtype_id + "," + variable_ids
        return(encoded_message)
    
    #code to decode the message using ltdict and vdict
    def decode(self, encoded_log):
        splitted = encoded_log.split(",",2)
        ts = splitted[0]
        logtype_id = splitted[1]
        self.variable_ids = splitted[2].split(',')
        self.lt_string = self.ltdict.get(logtype_id)[0]
        variables = self.get_variables_from_id()
        log = self.unparse_log(ts, variables)
        return(log)


encoded = '1471074506.946:35559673,0,0,2,0,3,6,10,2,3,10,11,1,3,0,5,1,1,1,1,1,1,1,1,1,5,0,1,0'
lookup_table = [{'0': ['type=\x112 msg=\x112 arch=\x114 syscall=\x113 success=\x112 exit=\x113 a0=\x113 a1=\x114 a2=\x113 a3=\x113 items=\x113 ppid=\x113 pid=\x113 auid=\x113 uid=\x113 gid=\x113 euid=\x113 suid=\x113 fsuid=\x113 egid=\x113 sgid=\x113 fsgid=\x113 tty=\x111 ses=\x113 comm=\x110 exe=\x110 key=\x111 ', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '1': ['type=\x115 msg=\x112 proctitle=\x110 ', ['2b8797c5-cbe6-42b8-991a-8ac85a562498']], '2': ['type=\x114 msg=\x112 ver=\x116 format=\x112 kernel=\x116 auid=\x113 pid=\x113 subj=\x112 res=\x112 ', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']]}, {'2': {'0': ['SYSCALL', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '1': ['no', ['2b8797c5-cbe6-42b8-991a-8ac85a562498']], '2': ['audit', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '3b8797c5-cbe6-42b8-991a-8ac85a562499', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '3': ['success', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']], '4': ['raw', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']], '5': ['unconfined', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']], '6': ['yes', ['1b8797c5-cbe6-42b8-991a-8ac85a562497']]}, '0': {'0': ['"gmain"', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '1': ['"/usr/lib/accountsservice/accounts-daemon"', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']]}, '3': {'0': ['1236', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '1': ['0', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '2': ['4', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '3': ['1', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '4': ['19078622', ['2b8797c5-cbe6-42b8-991a-8ac85a562498']], '5': ['4294967295', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '6': ['-11', ['2b8797c5-cbe6-42b8-991a-8ac85a562498']], '7': ['10', ['2b8797c5-cbe6-42b8-991a-8ac85a562498']], '8': ['1003', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']], '9': ['49013', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']], '10': ['8', ['1b8797c5-cbe6-42b8-991a-8ac85a562497']], '11': ['19158250', ['1b8797c5-cbe6-42b8-991a-8ac85a562497']]}, '1': {'0': ['(null)', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '1': ['(none)', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']]}, '4': {'0': ['c000003e', ['2b8797c5-cbe6-42b8-991a-8ac85a562498', '1b8797c5-cbe6-42b8-991a-8ac85a562497']], '1': ['7fc786f02cd0', ['2b8797c5-cbe6-42b8-991a-8ac85a562498']], '2': ['DAEMON_START', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']], '3': ['7fc786f02c88', ['1b8797c5-cbe6-42b8-991a-8ac85a562497']]}, '5': {'0': ['UNKNOWN[1327]', ['2b8797c5-cbe6-42b8-991a-8ac85a562498']]}, '6': {'0': ['2.3.2', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']], '1': ['4.2.0-27-generic', ['3b8797c5-cbe6-42b8-991a-8ac85a562499']]}}]
# i = LogHandler(lookup_table)
# print(i.decode(encoded))