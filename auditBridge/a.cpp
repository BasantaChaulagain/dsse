#include <cstring>
#include <stdio.h>
#include <string>
#include <string.h>
#include <string>
#include <stdlib.h>

using namespace std;

void compose_fd(char *buf, const char *type, const char *keyword1, const char *keyword2, const char *keyword3, const char* keyword4, int fd, const char* ip, const char *port)
{
	// printf("buf: %s\n", buf);
		char *ptr = buf;
		char *ptr2, ptr3[1000], *temp;
		long inode;
		string filename, path, cwd;
		// FILE *testout2;
		// testout2 = fopen("./testout2", "a+");

		while( (temp=strstr(ptr, "type=PATH")) != NULL) {
			string line, delimiter_ = "\n";
			int pos = 0;
			string s = string(temp);
			while ((pos = s.find(delimiter_)) != std::string::npos){
					line = s.substr(0, pos);
					strcpy(ptr3, line.c_str());
					// printf("line: %s, kw: %s\n", ptr3, keyword1);
					ptr2 = strstr(ptr3, keyword1);
					if(ptr2 == NULL && keyword2) ptr2 = strstr(ptr3, keyword2);
					if(ptr2 == NULL && keyword3) ptr2 = strstr(ptr3, keyword3);
					if(ptr2 == NULL && keyword4) ptr2 = strstr(ptr3, keyword4);
					if(ptr2 != NULL)
					{
							// path = extract_string(ptr3, "name=");
							// if(extract_long(ptr3, " inode=", &inode) == 0) inode=0;
                            printf("ptr: %s\n", ptr3);
							// fprintf(testout2, "path:%s, inode:%ld, ptr:%s\n", path.c_str(), inode, ptr3);
					}

					s.erase(0, pos + delimiter_.length());
			}
			strcpy(temp, s.c_str());
		}
		

		//cwd = extract_string(buf, "cwd=");
		//if(!cwd.empty()) str << "proc.cwd=" << cwd.c_str() << DELIMITER;

		// return string(str.str());
}

int main(){
    char buf[5000] = "type=SYSCALL msg=audit(1471074635.151:35644170): arch=c000003e syscall=82 success=yes exit=0 a0=7fff341e6490 a1=618c20 a2=7fff341e6400 a3=7f18135826a0 items=5 ppid=49035 pid=49036 auid=1003 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=10 comm=\"useradd\" exe=\"/usr/sbin/useradd\" key=(null)\n\
type=CWD msg=audit(1471074635.151:35644170):  cwd=\"/\"\n\
type=PATH msg=audit(1471074635.151:35644170): item=0 name=\"/etc/\" inode=131073 dev=08:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT\n\
type=PATH msg=audit(1471074635.151:35644170): item=1 name=\"/etc/\" inode=131073 dev=08:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT\n\
type=PATH msg=audit(1471074635.151:35644170): item=2 name=\"/etc/group+\" inode=191561 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE\n\
type=PATH msg=audit(1471074635.151:35644170): item=3 name=\"/etc/group\" inode=191618 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE\n\
type=PATH msg=audit(1471074635.151:35644170): item=4 name=\"/etc/group\" inode=191561 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE\n\
type=UNKNOWN[1327] msg=audit(1471074635.151:35644170): proctitle=2F7573722F7362696E2F75736572616464006A6F686E";
    
    char *ptr, *ptr2;
    char ptr3[1000];
    string s_fd0, s_fd1;
    int fd0, fd1;

    char *temp = (char *)malloc(strlen(buf)+1);
    strcpy(temp, buf);
    compose_fd(temp, "file", "nametype=DELETE", NULL, NULL, NULL, fd0, NULL, NULL);
    printf("\n\n\n");
    strcpy(temp, buf);
    compose_fd(temp, "file", "nametype=CREATE", NULL, NULL, NULL, fd1, NULL, NULL);
    printf("\n\n");

    return 0;
}