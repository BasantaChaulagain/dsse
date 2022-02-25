import copy
import re
from db_recorder import DBRecorder

kv_pattern = re.compile(r'(\w+\=(?:\"|\().*?(?:\"|\))|\w+\=\S+)')
timestamp_id_pattern = re.compile(r'(\d{10}\.\d{3})\:(\d+)')

type_1 = ['UNDEFINED', 'DAEMON_START', 'USER_AUTH', 'USER_ACCT', 'CRED_ACQ', 'USER_END', 'USER_LOGIN', 'USER_START', 'USER_ROLE_CHANGE', 'CRED_DISP', 'LOGIN', 'SYSCALL']
type_2 = ['SOCKADDR', 'CWD', 'PATH', 'EXECVE', 'FD_PAIR']

# create a json file named taxonomy, and load it as dictionary.
log_entry_base = {'extra_inodes':[], 'filenames':[]}

class LogAnalyzer:
    path_dict = {}
    thread_dict = {}
    process_dict = {}
    logs = []
    prev_record_id = 0
    prev_log_entry = {}
    db_rec = None

    def __init__(self, logs):
        self.logs = logs
        self.db_rec = DBRecorder()

    def process_log(self):
        for log in self.logs:
            self.analyze_log(log)
        # saving the last log record
        # print(self.prev_log_entry)
        self.db_rec.save_record_to_db(self.prev_log_entry, self.path_dict)
        self.db_rec.save_path_dict(self.path_dict)

    def find_kv_from_log(self, log):
        kv_pair = {}
        match = kv_pattern.findall(log)
        if match:
            ts_id_match = timestamp_id_pattern.findall(match[1])
            if ts_id_match:
                match[1] = match[1].split('(')[0]
                match.append("timestamp="+ts_id_match[0][0])
                match.append("record_id="+ts_id_match[0][1])
        for each in match:
            kv = each.split("=")
            kv_pair[kv[0]] = kv[1]
        return(kv_pair)
    

    def process_path(self, name, mode, cwd):
        is_dir = False
        name = name.strip('"')
        if cwd.endswith('/') == False:
            cwd = cwd + '/'
        if mode.startswith('04'):
            is_dir = True
        if name.startswith('./'):
            name = name[2:]
        if name.endswith('/'):
            name = name[:-1]
            is_dir = True
        if name.startswith('/') == False:
            name = cwd + '/' + name
        return (is_dir, name)


    def analyze_log(self, log):
        kv_pair = self.find_kv_from_log(log)
        
        if kv_pair['record_id'] == self.prev_record_id:
            log_entry = copy.deepcopy(self.prev_log_entry)
        else:
            log_entry = copy.deepcopy(log_entry_base)
            self.prev_record_id = kv_pair['record_id']
            # save the record to db if all logs with the same record id is analyzed.
            # print(self.prev_log_entry)
            self.db_rec.save_record_to_db(self.prev_log_entry, self.path_dict)
            
        log_type = kv_pair['type']
        if log_type in type_1:
            for key in ['type', 'timestamp', 'record_id','pid', 'ppid', 'uid', 'auid']:
                log_entry[key] = kv_pair[key]
            if log_type=='SYSCALL':
                log_entry['sysnum'] = kv_pair['syscall']
                log_entry['args'] = [kv_pair['a0'], kv_pair['a1'], kv_pair['a2'], kv_pair['a3']]
                log_entry['success'] = True if kv_pair['success']=='yes' else False
                for key in ['exit', 'comm', 'exe']:
                    kv_pair[key].strip('"')
                    log_entry[key] = kv_pair[key]
            if log_type in type_1[2:9]:
                log_entry['hostname'] = kv_pair['hostname']

        if log_type == 'SOCKADDR':
            log_entry['saddr'] = kv_pair['saddr']

        if log_type == 'CWD':
            log_entry['cwd'] = kv_pair['cwd'].strip('"')

        if log_type == 'PATH':
            inode = kv_pair['inode']
            
            #  Do not record the following case.
            if kv_pair['mode'].startswith('04'):        # This is a directory
                return
            if kv_pair['name'] in ['"(null)"', '"/dev/null"', '.']:
                return
            
            processed_path = self.process_path(kv_pair['name'], kv_pair['mode'], log_entry['cwd'])
            self.path_dict[inode] = {
                'name' : processed_path[1],
                'mode' : kv_pair['mode'],
                'isDir': processed_path[0]
            }
            if processed_path[0] == False:
                log_entry['filenames'].append(processed_path[1])
            if kv_pair['item'] == '0':
                log_entry['inode'] = inode
            else:
                log_entry['extra_inodes'].append(inode)
        
        if log_type == 'FD_PAIR':
            log_entry['fd_pair'] = [kv_pair['fd0'], kv_pair['fd1']]

        self.prev_log_entry = copy.deepcopy(log_entry)
        # return(log_entry)
        


logs = [
    '''type=SYSCALL msg=audit(1471074506.946:35559672): arch=c000003e syscall=0 success=no exit=-11 a0=4 a1=7fc786f02cd0 a2=10 a3=19078622 items=0 ppid=1 pid=1236 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="gmain" exe="/usr/lib/accountsservice/accounts-daemon" key=(null)''',
    '''type=UNKNOWN[1327] msg=audit(1471074506.946:35559672): proctitle="/usr/lib/accountsservice/accounts-daemon"''',
    
    '''type=SYSCALL msg=audit(1470638900.968:7419126): arch=c000003e syscall=59 success=yes exit=0 a0=1050c08 a1=104b988 a2=104bc08 a3=7ffe0ae8a800 items=2 ppid=35078 pid=35090 auid=1003 uid=1003 gid=1003 euid=1003 suid=1003 fsuid=1003 egid=1003 sgid=1003 fsgid=1003 tty=pts1 ses=1 comm="pidof" exe="/sbin/killall5" key=(null)''',
    '''type=EXECVE msg=audit(1470638900.968:7419126): argc=2 a0="pidof" a1="auditd"''',
    '''type=CWD msg=audit(1470638900.968:7419126):  cwd="/home/vagrant"''',
    '''type=PATH msg=audit(1470638900.968:7419126): item=0 name="/bin/pidof" inode=129 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL''',
    '''type=PATH msg=audit(1470638900.968:7419126): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=137895 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL''',
    '''type=UNKNOWN[1327] msg=audit(1470638900.968:7419126): proctitle=2F62696E2F62617368002F686F6D652F76616772616E742F554253492F736372697074732F61756469742E7368''',
]

la = LogAnalyzer(logs)
la.process_log()
