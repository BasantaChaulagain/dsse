############
#
# index_handler.py
#
# Contains class Index_Handler, takes an individual log as input. 
# Responsible for parsing logs and creating ltdict, and vdict, and making index files.
#
############

import re

log = '''type=SYSCALL msg=audit(1471074506.946:35559672): arch=c000003e syscall=0 success=no exit=-11 a0=4 a1=7fc786f02cd0 a2=10 a3=19078622 items=0 ppid=1 pid=1236 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="gmain" exe="/usr/lib/accountsservice/accounts-daemon" key=(null)'''
segment = "2b8797c5-cbe6-42b8-991a-8ac85a562498"

timestamp_id_pattern = [r"\d{10}\.\d{3}\:\d+", 
                r"\d{4}(\/|\-|\:)\d{2}(\/|\-|\:)\d{2}(T|\s+|\:)\d{0,24}\:\d{0,59}\:\d{0,59}"]
# this captures everything in the form key=value where values can have space in between (like filename with space.)
kv_pattern = re.compile(r'(\w+\=(?:\"|\().*?(?:\"|\))|\w+\=\S+)')

# more generic regex should be written at the end.
variable_schema = { '0': r'\"[\/\w\-\_]+\"',
                    '1': r'\([\w]+\)', 
                    '2': r'[A-Za-z]+', 
                    '3': r'-?\d+', 
                    '4': r'[\d\w]+'
                   }


class LogHandler:
    def __init__(self, log):
        self.log = log
        self.segment = segment
        self.lt_string = ""             # id,lt_string,segment
        self.variable = []
        self.encoded_message = ""       # timestamp,log_type_id,variable values
        self.vdict = {}
        # self.vdict = self.get_vdict_from_file()

    def extract_timestamp(self):
        for ts_patt in timestamp_id_pattern:
            ts_patt = re.compile(ts_patt)
            match = ts_patt.search(self.log)
            if match:
                return(match.group())

    # code to find the variables and log_type
    def parse_log(self):
        match = kv_pattern.findall(log)
        if match:
            for each in match:
                key_value = each.split('=')
                # if key is msg field, take off the timestamp:id from the variable. This is specific to linux audit log.
                if key_value[0] == 'msg':
                    self.lt_string = self.lt_string+key_value[0]+'='+'\x14 '+': '
                    value = key_value[1].split('(')[0]
                    if value not in self.variable:
                        self.variable.append(value)
                else:
                    self.lt_string = self.lt_string+key_value[0]+'='+'\x14 '
                    if key_value[1] not in self.variable:
                        self.variable.append(key_value[1])
        print(self.lt_string)
        print(self.variable)

    # code to encode the message using ltdict and vdict
    def encode(self):
        self.extract_timestamp()
        self.parse_log()
        self.write_to_vdict()
        self.write_to_ltdict()

    def get_schema_type(self, var):
        for key, value in variable_schema.items():
            match = re.fullmatch(value, var)
            if match:
                return(key)

    def write_to_ltdict(self):
        # id,lt_string,segment_id
        # need to change the lt_string to include variable schema id.
        pass

    def write_to_vdict(self):
        # id,schema,segment_id          # id,variable_value,segment_id
        for var in self.variable:
            schema_id = self.get_schema_type(var)
            vdict_id = self.vdict.get(schema_id)
            if not vdict_id:
                self.vdict[schema_id] = {}
            vdict_id = self.vdict.get(schema_id)
            # print(vdict_id, type(vdict_id))
            # print(vdict_id)
            size_vdict_id = len(vdict_id)
            self.vdict[schema_id][str(size_vdict_id)] = var
        
        print(self.vdict)





i = LogHandler(log)
i.encode()