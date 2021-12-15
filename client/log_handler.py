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

timestamp_pattern = [r"\d{10}\.\d{3}", 
                r"\d{4}(\/|\-|\:)\d{2}(\/|\-|\:)\d{2}(T|\s+|\:)\d{0,24}\:\d{0,59}\:\d{0,59}"]

class LogHandler:
    def __init__(self, log):
        self.log = log

    def extract_timestamp(self):
        for ts_patt in timestamp_pattern:
            ts_patt = re.compile(ts_patt)
            match = ts_patt.search(self.log)
            if match:
                return(match.group())

    def find_variables(self):
        pass

    # code to encode the message using ltdict and vdict
    def encode(self):
        self.extract_timestamp()
        self.find_variables()
        self.write_to_vdict()
        self.write_to_ltdict()
        pass

    def write_to_ltdict(self):
        pass

    def write_to_vdict(self):
        pass




i = LogHandler(log)
i.extract_timestamp()