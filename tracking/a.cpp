#include <cstring>
#include <stdio.h>
#include <string>
#include <string.h>
#include "uthash.h"
#include <stdlib.h>

using namespace std;

// typedef struct timestamp_table_t {
// 		long keyword;
// 		long ts;
// 		UT_hash_handle hh;
// } timestamp_table_t;
// timestamp_table_t *timestamp_table = NULL;


int main()
{
	char temp[350] = "35641505; 1471074625.623(Sat Aug 13 03:50:25 2016); execve(59); 0;  a[0]=0x55fece7b92b8 a[1]=0x55fece7c0358 a[2]=0x55fece7cad80; 49031_1471074625.619; 0.000_0_0; 49031; 49030; vsftp.file; /home/vagrant/vsftp.file; 0; 0; 0; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; a[0]=./vsftp.file; ./vsftp.file; 701395; ; ; ; ";

	long eid = strtol(temp, NULL, 10);
	double ts = stod(temp+10);


	printf("eid: %ld, ts:%.3f\n", eid, ts);


	// long kw = 49018;
	// timestamp_table_t *tt;
	
	// printf("start\n");

	// HASH_FIND(hh, timestamp_table, &kw, sizeof(long), tt);
	
	// if (tt == NULL){
	// 	tt = new timestamp_table_t;
	// 	tt->keyword = kw;
	// 	tt->ts = 2354785372;
	// 	HASH_ADD(hh, timestamp_table, keyword, sizeof(long), tt);
	// }

	// printf("added\n");

	// HASH_FIND(hh, timestamp_table, &kw, sizeof(long), tt);
	// if (tt !=NULL){
	// 	printf("found kw:%ld, ts:%ld.\n", tt->keyword, tt->ts);
	// 	tt->ts = 44444444;
	// }
	// printf("updated\n");

	// HASH_FIND(hh, timestamp_table, &kw, sizeof(long), tt);
	// if (tt !=NULL){
	// 	printf("found kw:%ld, ts:%ld.\n", tt->keyword, tt->ts);
	// }

	return 0;
}
