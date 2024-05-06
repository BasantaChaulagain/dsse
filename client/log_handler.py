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


    def write_to_vdict(self, segment):
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
                    self.vdict[self.cid][schema_id][var_id] = [var, [segment]]
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
    def encode(self, log, segment):
        ts = self.extract_timestamp(log)
        eid = self.extract_event_id(log)
        self.parse_log(log)
        self.write_to_vdict(segment)
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


# enc_logs = [
#             '''1670087354.223:916793266,3,0,1,1,0,0,0,0,0,0,0,0,0,1'''
# ]

# lookup = [{"c0": {"0": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0", "1": "1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "2": "1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", "3": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1", "4": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "5": "1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "6": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "7": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1"}, "c1": {"0": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "1": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1", "2": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0", "3": "1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "4": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "5": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "6": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "7": "1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 1 0 0 0 1 0 0 0 0 1 0 0 0", "8": "1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", "9": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 1 1 0 0 0 0 0 0 0 0 1 0 0 0", "10": "1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 0 0 0", "11": "1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0"}, "c2": {"0": "1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0", "1": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1", "2": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1", "3": "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0"}}, 
#           {"c0": {"0": {"0": ["recvfrom(45)", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["close(3)", ["STD6U7hZEguZABdjuxCXaz"]], "2": ["openat(257)", ["STD6U7hZEguZABdjuxCXaz"]], "3": ["read(0)", ["STD6U7hZEguZABdjuxCXaz"]], "4": ["mmap(9)", ["STD6U7hZEguZABdjuxCXaz"]]}, "1": {"0": ["36", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["0", ["STD6U7hZEguZABdjuxCXaz"]], "2": ["4", ["STD6U7hZEguZABdjuxCXaz"]], "3": ["5", ["STD6U7hZEguZABdjuxCXaz"]], "4": ["4096", ["STD6U7hZEguZABdjuxCXaz"]], "5": ["-994549760", ["STD6U7hZEguZABdjuxCXaz"]], "6": ["2358", ["STD6U7hZEguZABdjuxCXaz"]]}, "2": {"0": ["a[0]=0x5 a[1]=0x7fff22b540e0 a[2]=0x231c a[3]=0x40", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["a[0]=0x5", ["STD6U7hZEguZABdjuxCXaz"]], "2": ["a[0]=0xffffff9c a[1]=0x5611c3bad4b0 a[2]=0x90800 a[3]=0x0", ["STD6U7hZEguZABdjuxCXaz"]], "3": ["a[0]=0xffffff9c a[1]=0x7fc8996b2a52 a[2]=0x0 a[3]=0x0", ["STD6U7hZEguZABdjuxCXaz"]], "4": ["a[0]=0x5 a[1]=0x55e4b44711e0 a[2]=0x1000", ["STD6U7hZEguZABdjuxCXaz"]], "5": ["a[0]=0xffffff9c a[1]=0x7fffd453f3b0 a[2]=0x0 a[3]=0x0", ["STD6U7hZEguZABdjuxCXaz"]], "6": ["a[0]=0x0 a[1]=0x205 a[2]=0x1 a[3]=0x1", ["STD6U7hZEguZABdjuxCXaz"]]}, "3": {"0": ["1325537_1670087354.223", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["1325541_1670087354.223", ["STD6U7hZEguZABdjuxCXaz"]]}, "4": {"0": ["0.000_0_0", ["STD6U7hZEguZABdjuxCXaz"]]}, "5": {"0": ["1325537", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["1325541", ["STD6U7hZEguZABdjuxCXaz"]]}, "6": {"0": ["1325518", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["1325539", ["STD6U7hZEguZABdjuxCXaz"]]}, "7": {"0": ["sudo", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["audispd", ["STD6U7hZEguZABdjuxCXaz"]]}, "8": {"0": ["/usr/bin/sudo", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["/usr/sbin/audispd", ["STD6U7hZEguZABdjuxCXaz"]]}, "9": {"0": ["0", ["STD6U7hZEguZABdjuxCXaz"]]}, "10": {"0": ["0", ["STD6U7hZEguZABdjuxCXaz"]]}, "11": {"0": ["0", ["STD6U7hZEguZABdjuxCXaz"]]}, "12": {"0": ["5", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["4", ["STD6U7hZEguZABdjuxCXaz"]]}, "13": {"0": ["netlink", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["file", ["STD6U7hZEguZABdjuxCXaz"]]}, "17": {"0": ["netlink_family:16", ["STD6U7hZEguZABdjuxCXaz"]]}, "18": {"0": ["netlink_pid:0", ["STD6U7hZEguZABdjuxCXaz"]]}, "29": {"0": ["64", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["5", ["STD6U7hZEguZABdjuxCXaz"]], "2": ["4096", ["STD6U7hZEguZABdjuxCXaz"]], "3": ["1", ["STD6U7hZEguZABdjuxCXaz"]]}, "14": {"0": ["login.defs", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["syslog.conf", ["STD6U7hZEguZABdjuxCXaz"]]}, "15": {"0": ["/etc/login.defs", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["/etc/audisp/plugins.d/", ["STD6U7hZEguZABdjuxCXaz"]], "2": ["/etc/audisp/plugins.d/syslog.conf", ["STD6U7hZEguZABdjuxCXaz"]]}, "16": {"0": ["57409718", ["STD6U7hZEguZABdjuxCXaz"]], "1": ["57412152", ["STD6U7hZEguZABdjuxCXaz"]], "2": ["57412179", ["STD6U7hZEguZABdjuxCXaz"]]}, "32": {"0": ["0", ["STD6U7hZEguZABdjuxCXaz"]]}}, "c1": {"0": {"0": ["mmap(9)", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["sendto(44)", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["recvmsg(47)", ["RypdgX4fAkxwxdaAU7YMEs"]], "3": ["close(3)", ["RypdgX4fAkxwxdaAU7YMEs"]], "4": ["mprotect(10)", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "1": {"0": ["784601088", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["784740352", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["496", ["RypdgX4fAkxwxdaAU7YMEs"]], "3": ["786280448", ["RypdgX4fAkxwxdaAU7YMEs"]], "4": ["786599936", ["RypdgX4fAkxwxdaAU7YMEs"]], "5": ["786624512", ["RypdgX4fAkxwxdaAU7YMEs"]], "6": ["0", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "2": {"0": ["a[0]=0x0 a[1]=0x1f1660 a[2]=0x1 a[3]=0x802", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["a[0]=0x7fab2ec63000 a[1]=0x178000 a[2]=0x5 a[3]=0x812", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["a[0]=0x27 a[1]=0xba807d94e00 a[2]=0x1f0 a[3]=0x4000", ["RypdgX4fAkxwxdaAU7YMEs"]], "3": ["a[0]=0x7fab2eddb000 a[1]=0x4e000 a[2]=0x1 a[3]=0x812", ["RypdgX4fAkxwxdaAU7YMEs"]], "4": ["a[0]=0x3b a[1]=0x7f53e9d3b320 a[2]=0x40", ["RypdgX4fAkxwxdaAU7YMEs"]], "5": ["a[0]=0x7fab2ee29000 a[1]=0x6000 a[2]=0x3 a[3]=0x812", ["RypdgX4fAkxwxdaAU7YMEs"]], "6": ["a[0]=0x7fab2ee2f000 a[1]=0x3660 a[2]=0x3 a[3]=0x32", ["RypdgX4fAkxwxdaAU7YMEs"]], "7": ["a[0]=0x3", ["RypdgX4fAkxwxdaAU7YMEs"]], "8": ["a[0]=0x7fab2ee29000 a[1]=0x4000 a[2]=0x1", ["RypdgX4fAkxwxdaAU7YMEs"]], "9": ["a[0]=0x5555630cf000 a[1]=0x1000 a[2]=0x1", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "3": {"0": ["1325543_1670087354.223", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["5182_1670087354.223", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["5006_1670087354.223", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "4": {"0": ["0.000_0_0", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "5": {"0": ["1325543", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["5182", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["5006", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "6": {"0": ["1325518", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["4958", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["4962", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "7": {"0": ["pidof.sh", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["Compositor", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["Chrome_ChildIOT", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "8": {"0": ["/usr/sbin/killall5", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["/usr/share/code/code", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "9": {"0": ["1000", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "10": {"0": ["1000", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "11": {"0": ["1000", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "12": {"0": ["39", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["59", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["3", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "13": {"0": ["file", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "14": {"0": ["libc.so.6", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "15": {"0": ["/lib/x86_64-linux-gnu/libc.so.6", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "16": {"0": ["139331717", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "29": {"0": ["2050", ["RypdgX4fAkxwxdaAU7YMEs"]], "1": ["2066", ["RypdgX4fAkxwxdaAU7YMEs"]], "2": ["16384", ["RypdgX4fAkxwxdaAU7YMEs"]], "3": ["64", ["RypdgX4fAkxwxdaAU7YMEs"]], "4": ["50", ["RypdgX4fAkxwxdaAU7YMEs"]], "5": ["3", ["RypdgX4fAkxwxdaAU7YMEs"]], "6": ["1", ["RypdgX4fAkxwxdaAU7YMEs"]]}, "32": {"0": ["0", ["ABShA667jm2m6eedaV5oe9"]]}, "17": {"0": ["path:/dev/log", ["AhgTRugCcSH267ZCUa4rBV"]]}, "18": {"0": ["netlink_pid:0", ["VHGj7pkyQfhawWusgR64E3"]]}, "20": {"0": ["unix", ["AhgTRugCcSH267ZCUa4rBV"]], "1": ["pipe", ["AhgTRugCcSH267ZCUa4rBV"]]}, "24": {"0": ["path:/dev/log", ["AhgTRugCcSH267ZCUa4rBV"]]}, "19": {"0": ["4", ["AhgTRugCcSH267ZCUa4rBV"]]}, "27": {"0": ["a[0]=pidofa[1]=auditd", ["ABShA667jm2m6eedaV5oe9"]]}, "28": {"0": ["/usr/bin/pidof", ["ABShA667jm2m6eedaV5oe9"]]}}, "c2": {"0": {"0": ["mprotect(10)", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["openat(257)", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "2": ["read(0)", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "3": ["close(3)", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "1": {"0": ["0", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["3", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "2": ["4", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "3": ["208", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "4": ["47", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "2": {"0": ["a[0]=0x7fab2ee75000 a[1]=0x1000 a[2]=0x1", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["a[0]=0xffffff9c a[1]=0x5555630ce3df a[2]=0x90800 a[3]=0x0", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "2": ["a[0]=0xffffff9c a[1]=0x7ffc26093d30 a[2]=0x0 a[3]=0x0", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "3": ["a[0]=0x4 a[1]=0x7ffc26094d40 a[2]=0x1000", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "4": ["a[0]=0x4 a[1]=0x7ffc26094e10 a[2]=0xc00", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "5": ["a[0]=0x4", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "6": ["a[0]=0x4 a[1]=0x555563ed9520 a[2]=0x400", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "3": {"0": ["1325543_1670087354.223", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "4": {"0": ["0.000_0_0", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "5": {"0": ["1325543", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "6": {"0": ["1325518", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "7": {"0": ["pidof.sh", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "8": {"0": ["/usr/sbin/killall5", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "9": {"0": ["1000", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "10": {"0": ["1000", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "11": {"0": ["1000", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "29": {"0": ["1", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["4096", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "2": ["3072", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "3": ["4", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "4": ["1024", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "12": {"0": ["3", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["4", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "13": {"0": ["file", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "15": {"0": [".", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["1/stat", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "2": ["1/cmdline", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "3": ["2/stat", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "16": {"0": ["1", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["82968", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "2": ["18548", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "3": ["19742", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "32": {"0": ["0", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "14": {"0": ["stat", ["m7PZD7Bn6z9MRoUxmDVpWR"]], "1": ["cmdline", ["m7PZD7Bn6z9MRoUxmDVpWR"]]}, "0": {"0": ["read(0)", ["J7XRb8JwsqxBNyDQphtYrd"]], "1": ["close(3)", ["J7XRb8JwsqxBNyDQphtYrd"]], "2": ["openat(257)", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "1": {"0": ["151", ["J7XRb8JwsqxBNyDQphtYrd"]], "1": ["0", ["J7XRb8JwsqxBNyDQphtYrd"]], "2": ["4", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "2": {"0": ["a[0]=0x4 a[1]=0x7ffc26094d40 a[2]=0x1000", ["J7XRb8JwsqxBNyDQphtYrd"]], "1": ["a[0]=0x4 a[1]=0x7ffc26094dd7 a[2]=0xc00", ["J7XRb8JwsqxBNyDQphtYrd"]], "2": ["a[0]=0x4", ["J7XRb8JwsqxBNyDQphtYrd"]], "3": ["a[0]=0xffffff9c a[1]=0x7ffc26093d30 a[2]=0x0 a[3]=0x0", ["J7XRb8JwsqxBNyDQphtYrd"]], "4": ["a[0]=0x4 a[1]=0x555563ed9520 a[2]=0x400", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "3": {"0": ["1325543_1670087354.223", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "4": {"0": ["0.000_0_0", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "5": {"0": ["1325543", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "6": {"0": ["1325518", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "7": {"0": ["pidof.sh", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "8": {"0": ["/usr/sbin/killall5", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "9": {"0": ["1000", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "10": {"0": ["1000", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "11": {"0": ["1000", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "12": {"0": ["4", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "13": {"0": ["file", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "14": {"0": ["stat", ["J7XRb8JwsqxBNyDQphtYrd"]], "1": ["cmdline", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "15": {"0": ["2/stat", ["J7XRb8JwsqxBNyDQphtYrd"]], "1": ["2/cmdline", ["J7XRb8JwsqxBNyDQphtYrd"]], "2": ["3/stat", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "16": {"0": ["19742", ["J7XRb8JwsqxBNyDQphtYrd"]], "1": ["36143", ["J7XRb8JwsqxBNyDQphtYrd"]], "2": ["19744", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "29": {"0": ["4096", ["J7XRb8JwsqxBNyDQphtYrd"]], "1": ["3072", ["J7XRb8JwsqxBNyDQphtYrd"]], "2": ["4", ["J7XRb8JwsqxBNyDQphtYrd"]], "3": ["1024", ["J7XRb8JwsqxBNyDQphtYrd"]]}, "32": {"0": ["0", ["J7XRb8JwsqxBNyDQphtYrd"]]}}}
# ]

# for log in enc_logs:
#     l = LogHandler(lookup, "c1")
#     e = l.decode(log)
#     print(e)
