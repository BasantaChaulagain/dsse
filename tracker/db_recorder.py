from numpy import insert
import psycopg2
import yaml

CONFIG_FILE = "../config.yml"
logs = [
    '''type=SYSCALL msg=audit(1471074506.946:35559672): arch=c000003e syscall=0 success=no exit=-11 a0=4 a1=7fc786f02cd0 a2=10 a3=19078622 items=0 ppid=1 pid=1236 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="gmain" exe="/usr/lib/accountsservice/accounts-daemon" key=(null)''',
    '''type=UNKNOWN[1327] msg=audit(1471074506.946:35559672): proctitle="/usr/lib/accountsservice/accounts-daemon"'''
]

class DBRecorder:
    config = {}
    pg_connection = None
    pg_cursor = None

    def __init__(self):
        self._load_config()
        self._ensure_pg_database()

    def _load_config(self):
        with open(CONFIG_FILE, "r") as ymlfile:
            self.config = yaml.safe_load(ymlfile)


    def _ensure_pg_database(self):
        db = self.config["PG_DATABASE"]
        self.pg_connection = psycopg2.connect(host = db['server'], 
                                port = db['port'], 
                                database = db['dbname'],
                                user = db['username'],
                                password = db['password'])
        self.pg_cursor = self.pg_connection.cursor()


    def save_record_to_db(self, record, path_dict):
        if len(record) == 0:
            return

        columns = ['record_id', 'timestamp', 'type', 'pid', 'ppid', 'uid', 'auid', 'sysnum', 'success', 'args', 'exit', 'comm', 'exe', 'hostname', 'saddr', 'cwd', 'inode', 'fdpair', 'extra_inodes', 'filenames']
        values = []
        print(record)
        for col in columns:
            if col in record.keys():
                if type(record[col]) == list:
                    if len(record[col]) == 0:
                        value = 'null'
                    else:
                        value = tuple(record[col])
                        if len(value) == 1:
                            value = value[0]
                else:
                    value = record[col]
                values.append(value)
            else:
                values.append('null')
        
        print(values)
        _query = '''INSERT INTO log_records (record_id, timestamp, type, pid, ppid, uid, auid, sysnum, success, args, exit, comm, exe, hostname, saddr, cwd, inode, fdpair, extra_inodes, filenames) \
            VALUES {}'''.format(tuple(values))
        self.pg_cursor.execute(_query)
        self.pg_connection.commit()
        
            


    def save_path_dict(self, path_dict):
        for each in path_dict:
            values = []
            values.append(each)
            for key, value in path_dict[each].items():
                values.append(value)
            _query = '''INSERT INTO paths (inode, name, mode, is_dir) VALUES {}'''.format(tuple(values))
            self.pg_cursor.execute(_query)
            self.pg_connection.commit()

