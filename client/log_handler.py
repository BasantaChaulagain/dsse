############
#
# index_handler.py
#
# Contains class Index_Handler, takes an individual log as input. 
# Responsible for parsing logs and creating ltdict, and vdict, and making index files.
#
############

import re

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
        if (CSV_INPUT):
            ts = log.split(';')[1].split(';')[0].split('(')[0].strip(' ')
            return ts
        else:
            for ts_patt in timestamp_id_pattern:
                ts_patt = re.compile(ts_patt)
                match = ts_patt.search(log)
                if match:
                    return(match.group())

    def extract_event_id(self, log):
        eid = log.split(';')[0]
        return eid

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
        if (CSV_INPUT):
            match = csv_pattern.findall(log)
            if match:
                self.variable = match[2:]
                for each in self.variable:
                    schema_id = self.get_schema_id(each)
                    self.lt_string = self.lt_string + '\x11' + schema_id + ' '
        else:
            match = kv_pattern.findall(log)
            if match:
                for each in match:
                    key_value = each.split('=')
                    # if key is msg field, take off the timestamp:id from the variable. This is specific to linux audit log.
                    if key_value[0] == 'msg':
                        value = key_value[1].split('(')[0]
                    else:
                        value = key_value[1]
                    self.variable.append(value)
                    schema_id = self.get_schema_id(value) 
                    self.lt_string = self.lt_string+key_value[0]+'='+'\x11'+schema_id+' '
    
    def unparse_log(self, ts, variables):
        patt = re.compile(r'\w+\=\x11\d+')
        kv_pair = patt.findall(self.lt_string)
        updated_kv =[]
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
            # if var not in any values in vdict_id, add to the dictionary, else update segment id and count.
            var_id = self.get_variable_id(var, vdict_id)
            if not var_id:
                self.vdict[schema_id][str(size_vdict_id)] = [var, 1, [segment]]
            else:
                segment_list = self.vdict[schema_id][var_id][2]
                if segment not in segment_list:
                    segment_list.append(segment)
                self.vdict[schema_id][var_id][1] += 1

        
    def write_to_ltdict(self, segment):
        logtype_id = self.get_log_type_id(self.lt_string)
        # if log_type_id is not present, add the ltstring, else just update the segment id and count.
        if not logtype_id:
            size_ltdict = len(self.ltdict)
            self.ltdict[str(size_ltdict)] = [self.lt_string, 1, [segment]]
        else:
            segment_list = self.ltdict[logtype_id][2]
            if segment not in segment_list:
                segment_list.append(segment)
            self.ltdict[logtype_id][1] += 1
        
    def get_variable_ids(self):
        # get each schema_type from lt_string and lookup each variables in variable list with the the vdict of particular schema type.
        variable_ids = ""
        pattern = r'(?:\x11)(\d+)'
        print("ltstring", self.lt_string)
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
        if (CSV_INPUT):
            eid = self.extract_event_id(log)
        self.parse_log(log)
        self.write_to_vdict(segment)
        self.write_to_ltdict(segment)
        print(self.ltdict)
        print(self.vdict)
        variable_ids = self.get_variable_ids()
        logtype_id = self.get_log_type_id(self.lt_string)
        if (CSV_INPUT):
            print(logtype_id, variable_ids)
            encoded_message = ts + ":" + eid + "," + logtype_id + "," + variable_ids
        else:
            encoded_message = ts + "," + logtype_id + "," + variable_ids
        return(encoded_message)
    
    #code to decode the message using ltdict and vdict
    def decode(self, encoded_log):
        try:
            splitted = encoded_log.split(",",2)
            ts = splitted[0]
            logtype_id = splitted[1]
            self.variable_ids = splitted[2].split(',')
            self.lt_string = self.ltdict.get(logtype_id)[0]
            variables = self.get_variables_from_id()
            log = self.unparse_log(ts, variables)
            return(log)
        except:
            # print("unable to decode:\t",encoded_log)
            return ""


logs = [
    '''35559695; 1471074506.950(Sat Aug 13 03:48:26 2016); read(0); 4096;  a[0]=0x4 a[1]=0x7fc46876a000 a[2]=0x1000; 49011_1471074506.930; 0.000_0_0; 49011; 49005; sudo; /usr/bin/sudo; 0; 0; 1003; 4; file; login.defs; /etc/login.defs; 131246; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ''',
    '''35559700; 1471074506.950(Sat Aug 13 03:48:26 2016); sendto(44); 78;  a[0]=0x5 a[1]=0x55dbbfbdc420 a[2]=0x4e a[3]=0x4000; 49011_1471074506.930; 0.000_0_0; 49011; 49005; sudo; /usr/bin/sudo; 0; 0; 1003; 5; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; '''
]

# logs = [
#     '''type=SYSCALL msg=audit(1471074506.946:35559676): arch=c000003e syscall=1 success=yes exit=8 a0=4 a1=7fc786f02cb8 a2=8 a3=0 items=0 ppid=1 pid=1236 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="gmain" exe="/usr/lib/accountsservice/accounts-daemon" key=(null)'''
# ]

t=0
for log in logs:
    l = LogHandler({})
    e = l.encode(log, "test"+str(t))
    t+=1
    print(e)