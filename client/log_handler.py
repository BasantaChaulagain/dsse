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

# more generic regex should be written at the end.
variable_schema = { '0': r'\"[\/\w\-\_]+\"',
                    '1': r'\([\w]+\)', 
                    '2': r'[A-Za-z]+',
                    '3': r'-?\d+',
                    '4': r'[\da-fA-F]+',
                    '5': r'[\d\w]+',
                    '6': r'[A-Za-z]+\[\d+\]',
                    '7': r'.*?'
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
