#include <cstring>
#include <stdio.h>
#include <string>
#include <string.h>
#include <stdlib.h>

using namespace std;

int get_sysno(char *syscall){
	char *ptr = strtok(syscall, "(");
	ptr = strtok(NULL, ")");
	return atoi(ptr);
}

int get_tid(char *tid){
	char *ptr = strtok(tid, "_");
	return atoi(ptr);
}

int main()
{
	// int i = 0;
    // char buf[4000] = "35660162; 1471074648.880(Sat Aug 13 03:50:48 2016); open(2); 3;  a[0]=0xae24d0 a[1]=0x0 a[2]=0x1b6; 49059_1471074648.732; 0.000_0_0; 49059; 49058; killall; /usr/bin/killall; 0; 0; 0; 3; file; cmdline; /proc/2882/cmdline; 19955; ; ; ; ; ; ; ; ; ; ; ; ; ; b; a; ";
	// char list[34][200], *ptr;
	// ptr = strtok(buf, ";");
	// while (ptr != NULL){
	// 	strcpy(list[i++], ptr);
	// 	ptr = strtok(NULL, ";");
	// }

	// int j = 0;
	// printf("splitted items\n");
	// for (j=0; j<34; j++){
	// 	printf("%d: %s\n", j, list[j]);
	// }

	// long sysno = get_sysno(list[2]);
	// printf("%ld\n", sysno);

	// long tid = get_tid(list[5]);

	// ptr = strstr(list[4], "a[2]=");
	// ptr = strtok(ptr, " ");
	// printf("ptr: %s\n", ptr+5);

	// ptr = strstr(list[4], "a[0]=");
	// ptr = strtok(ptr, " ");
	// printf("ptr: %s\n", ptr+5);

	char str[100] = " path:/var/run/nscd/socket";
	char *ptr = strstr(str, "path");
	if (ptr != NULL)
		strncpy(ptr, "file", 4);
	printf("%s\n", str+1);
	return 0;

	string str;
}