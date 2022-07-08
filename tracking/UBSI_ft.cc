#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <ctime>
#include "init_scan.h"
#include "utils.h"
#include "tables.h"
#include "graph.h"

using namespace std;

void write_handler(int sysno, long eid, int tid, int fd, double ts, double* forward_ts, int* flag)
{
		debugtrack("In write handler\n");
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);

		if(is_tainted_unit(pt, tid, unitid) == false) return;

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);

		if(fd_el == NULL || fd_el->num_path == 0) {
				debug("pid %d, eid %ld, fd %d does not exist\n", pid, eid, fd);
				return;
		}

		debugtrack("Taint file: WRITE fd %d (sysno %d, eid %ld, tid %d, unitid %d) (# path %d): inode %ld, path:%s, pathtype: %s\n",
						fd, sysno, eid, tid, unitid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
						get_absolute_path(fd_el, fd_el->num_path-1).c_str(), fd_el->pathtype[fd_el->num_path-1].c_str());
		if(fd_el->is_socket) { // it is socket
				debugtaint("%s\n", fd_el->path[fd_el->num_path-1].c_str());
				int t_socket = taint_socket(fd_el->path[fd_el->num_path-1]);
				edge_proc_to_socket(tid, unitid, t_socket);
		} else {
				taint_inode(fd_el->inode[fd_el->num_path-1], eid, get_absolute_path(fd_el, fd_el->num_path-1));
				edge_proc_to_file(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);
				
				timestamp_table_t *tt;
				update_timestamp_table(tt, fd_el->inode[fd_el->num_path-1], ts, 0);
		}
		*flag = 1;

		if (ts > *forward_ts)	*forward_ts = ts;
		debugtrack("w-forward_ts: %lf\t", *forward_ts);
}

void read_handler(int sysno, long eid, int tid, int fd, string exe, int ret, double ts, double* forward_ts, int* flag)
{
		debugtrack("In read handler\n");
		if (sysno == 43)	fd = ret; 	//SYS_accept
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);
		
		if(pt == NULL) {
				printf("WARNING: PT is NULL\n");
				return;
		}

		if(fd < 3) return;

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);
		
		if(fd_el == NULL || fd_el->num_path == 0) {
				debugbt("tid %d, pid %d(%s), eid %ld, fd %d does not exist\n", tid, pid, exe.c_str(), eid, fd);
				return;
	 	}
	
		if(fd_el->is_socket == false && is_tainted_inode(fd_el->inode[fd_el->num_path-1], eid)) { // only check the last path..
				edge_file_to_proc(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);
				if(taint_unit(pt, tid, unitid, exe)) {
						debugtrack("taint unit (tid %d, unitid %d, exe %s): read (sysno %d, eid %ld) (# path %d): inode %ld, path:%s, pathtype: %s\n", 
										tid, unitid, exe.c_str(),
										sysno, eid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
										get_absolute_path(fd_el, fd_el->num_path-1).c_str(), 
										fd_el->pathtype[fd_el->num_path-1].c_str());
				}
				*flag = 1;
				timestamp_table_t *tt;
				update_timestamp_table(tt, tid, ts, 0);

				if (ts > *forward_ts)	*forward_ts = ts;
				debugtrack("r-forward_ts: %lf\t", *forward_ts);
		}
}

void fork_handler(int sysno, long eid, int tid, int a1, int ret, string exe, double ts, double* forward_ts, int* flag)
{
		debugtrack("In fork handler\n");
		int unitid = -1;
		if(a1 > 0) return;
		
		process_table_t *pt = get_process_table(get_pid(tid));

		// printf("is_tainted_unit: %d = %d\n", tid, is_tainted_unit(pt, tid, unitid));
		if(is_tainted_unit(pt, tid, unitid)) {
				taint_all_units_in_pid(ret, "");
				edge_proc_to_proc(tid, unitid, ret);
				debugbt("Taint Process: fork (sysno %d) pid %d, unitid %d, exit %d\n", sysno, tid, unitid, ret);
				
				*flag = 1;
				timestamp_table_t *tt;
				update_timestamp_table(tt, ret, ts, 0);
				
				if (ts > *forward_ts)	*forward_ts = ts;
				debugtrack("f-forward_ts: %lf\t", *forward_ts);
		}
}

void exec_handler(int sysno, long eid, int tid, string exe, long inode, double ts, double* forward_ts, int* flag)
{
		debugtrack("In exec handler\n");
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);

		if(is_tainted_inode(inode, eid)) {
				taint_all_units_in_pid(pid, exe);
				edge_file_to_proc(tid, -1, inode, eid);
				debugtrack("taint unit (tid %d(pid %d), unitid %d, exe %s): exec (sysno %d, eid %ld), inode %ld\n", 
										tid, pid, -1, exe.c_str(),
										sysno, eid, inode);

				*flag = 1;
				timestamp_table_t *tt;
				update_timestamp_table(tt, pid, ts, 0);

				if (ts > *forward_ts)	*forward_ts = ts;
				debugtrack("e-forward_ts: %lf\t", *forward_ts);
		}
}

void ft_syscall_handler(char * buf, double ts, double* forward_ts, int* flag)
{
		char *ptr, args[100], list[12][100];
		int i=0, j=0, sysno, fd, ret, tid;
		string exe, cwd, path;
		long eid, inode, a1;

		ptr = strtok(buf, ";");
		while (ptr != NULL){
			if(i==0 || i==2 || i==3 || i==4 || i==7 || i==10 || i==14 || i==17 || i==18 || i==28 || i==30 || i==31){
				strcpy(list[j++], ptr);
			}
			ptr = strtok(NULL, ";");
			i++;
		}

		eid = strtol(list[0], NULL, 10);
		sysno = get_sysno(list[1]);
		ret = atoi(list[2]);
		strcpy(args, list[3]);
		tid = atoi(list[4]);
		exe = list[5];
		fd = atoi(list[6]);
		cwd = list[9];
		if(sysno == 59){
			path = list[10];
			inode = strtol(list[11], NULL, 10);
		}
		else{
			path = list[7];
			inode = strtol(list[8], NULL, 10);
		}

		if(is_exec(sysno)) {
				exec_handler(sysno, eid, tid, exe, inode, ts, forward_ts, flag);
				debugtrack("new forward_ts: %ld\t", *forward_ts);
		}
		if(is_read(sysno)) {
				read_handler(sysno, eid, tid, fd, exe, ret, ts, forward_ts, flag);
				debugtrack("new forward_ts: %ld\t", *forward_ts);
		}
		if(is_write(sysno)) {
				write_handler(sysno, eid, tid, fd, ts, forward_ts, flag);
				debugtrack("new forward_ts: %ld\t", *forward_ts);
		}
		if(is_fork_or_clone(sysno)) {
				char* temp = strstr(args, "a[1]=");
				if(temp){
					temp = strtok(temp, " ");
					a1 = strtol(temp+5, NULL, 16);
				}
				fork_handler(sysno, eid, tid, a1, ret, exe, ts, forward_ts, flag);
				debugtrack("new forward_ts: %ld\t", *forward_ts);
		}
}

void table_scan_f(int user_pid, long user_inode)
{
	FILE* pp;
	char buf[10000][530];
	// int eid_list[10000], eid_index=0;
	int keywords[1000] = {0};
	int i, k, start_index = 0, stop_index, first_iteration = 1;
	int buf_add_index, buf_search_index, keyword_add_index, keyword_search_index;
	buf_add_index = buf_search_index = keyword_add_index = keyword_search_index = 0;
	
	string query = "python client.py -c 1 -s ";

	if (user_pid>0) keywords[0] = user_pid;
	else if (user_inode>0) keywords[0] = int(user_inode);
	debugtrack("keywords[0]: %d\n", keywords[0]);
	int q=0;	

	do {
			char line[530];
			string search_string = query + to_string(keywords[keyword_search_index++]);
			printf("\nsearch string: %s\n", search_string.c_str());
			pp = popen(search_string.c_str(), "r");

			while(fgets(line, 530, pp) != NULL){\
				if (strtol(line, NULL, 10) == 0)
					continue;

				char temp[530], *ptr;
				strcpy(temp, line);
				ptr = strtok(temp, ";");
				ptr = strtok(NULL, ";");
				ptr = strtok(NULL, ";");
				if (strncmp(ptr, " UBSI_ENTRY", 11)==0 || strncmp(ptr, " UBSI_EXIT", 10)==0)
					continue;
				ptr = strtok(ptr, "(");
				ptr = strtok(NULL, ")");
				int sysno = atoi(ptr);
				if (is_file_create(sysno)==0 && is_exec(sysno)==0 && is_write(sysno)==0 && is_read(sysno)==0 && is_fork_or_clone(sysno)==0)
					continue;

				strcpy(buf[buf_add_index++], line);
			}

			debugtrack("Running for buf with index %d to %d\n", start_index, buf_add_index-1);
			stop_index = buf_add_index-1;
			for (k=start_index; k<=stop_index; k++){
					int flag=0, new_eid=1, l;	// flag is to denote if the event has been tainted.
					char temp[530];
					strcpy(temp, buf[k]);
					long eid = strtol(temp, NULL, 10);
					double ts = stod(temp+10);

					if (first_iteration){
						long kw = long(keywords[keyword_search_index-1]);
						timestamp_table_t* tt;
						HASH_FIND(hh, timestamp_table, &kw, sizeof(long), tt);
						if (tt != NULL){
							debugtrack("tt is not null. %lf: %d\n", tt->ts, kw);
							forward_ts = tt->ts;
						}
						else{
							debugtrack("tt is null. %lf: %d\n", ts, kw);
							forward_ts = ts;
						}
						first_iteration = 0;
					}

					debugtrack("\neid: %d, ts: %lf, forward_ts: %lf\t\t", eid, ts, forward_ts);
					// for(l=0; l<eid_index; l++){
					// 	if(eid_list[l]==eid){
					// 		new_eid = 0;
					// 		break;
					// 	}
					// }

					if(ts !=0 && ts >= forward_ts && new_eid == 1){
						// printf("\nIn ft syscall handler: index: %d :: %s", k, temp);
						ft_syscall_handler(temp, ts, &forward_ts, &flag);
						// eid_list[eid_index++] = (int)eid;

						// extract pid and inode from the logs.
						if (flag == 1){
							char *ptr, list[2][12];
							strcpy(temp, buf[k]);
							ptr = strtok(temp, ";");
							int i = 0, j = 0;
							while(ptr != NULL){
								if(i==7 || i==18)
									strcpy(list[j++], ptr);
								ptr = strtok(NULL, ";");
								i++;
							}
							int pid = atoi(list[0]);
							int inode = atoi(list[1]);
							debugtrack("\npid: %d, inode: %d\n", pid, inode);

							int pid_exist = 0, inode_exist = 0;
							for (i=0; i<=keyword_add_index; i++){
								if (pid == keywords[i]){
									pid_exist = 1;
									break;
								}
							}
							for (i=0; i<=keyword_add_index; i++){
								if (inode == keywords[i]){
									inode_exist = 1;
									break;
								}
							}
							debugtrack("pid_exist %d, inode_exist %d\n", pid_exist, inode_exist);
							if (pid_exist == 0 && pid > 0)
								keywords[++keyword_add_index] = pid;
							if (inode_exist == 0 && inode > 0)
								keywords[++keyword_add_index] = inode;							
						}
						
						// add a line to the new index only if the prev log is tainted, else replace it.
						if (flag == 0)
							buf_add_index--;
					}
			}
			start_index = buf_add_index;
			first_iteration = 1;
			
			// printf("\nkeywords\t");
			// for (i=0; i<=keyword_add_index; i++){
			// 	printf("%d\t", keywords[i]);
			// }

			debugtrack("\nnext keyword: %d\n", keywords[keyword_search_index]);
			debugtrack("lines in buf: %d\n", buf_add_index);
			pclose(pp);
	} while (keywords[keyword_search_index] != 0);
}


int main(int argc, char** argv)
{
		auto start = chrono::system_clock::now();
		bool load_init_table = true;

		FILE *fp;

		int opt = 0;
		char *log_name = NULL;
		char *init_table_name = NULL;
		char *f_name = NULL;
		char *p_name = NULL;

		while ((opt = getopt(argc, argv, "i:f:p:t:h")) != -1) {
				switch(opt) {
						case 'i':
								log_name = optarg;
								printf("Log file name=%s\n", log_name);
								break;
						case 't':
								init_table_name = optarg;
								printf("Init table name=%s\n", init_table_name);
								break;
						case 'f':
								f_name = optarg;
								user_inode = atol(f_name);
								printf("User Tainted File Inode=%s(%ld)\n", f_name, user_inode);
								break;
						case 'p':
								p_name = optarg;
								user_pid = atoi(p_name);
								printf("User Tainted Process Id=%s(%d)\n", p_name, user_pid);
								break;
						case 'h':
								printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
								return 0;
								break;
				}
		}
		
		if((log_name == NULL && init_table_name == NULL) || (user_inode == 0 && user_pid == 0)) {
				printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
				return 0;
		}

		if (log_name != NULL){
			if((fp = fopen(log_name, "r")) == NULL) {
					printf("Error: Cannot open the log file: %s\n", log_name);
					printf("Usage: ./UBSI_bt [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
					return 0;
			}
			fclose(fp);
		}
		
		if(log_name != NULL && init_table_name == NULL) {
				init_table_name = (char*) malloc(sizeof(char)*1024);
				sprintf(init_table_name, "%s_init_table.dat", log_name);
				printf("Init table name=%s\n", init_table_name);
		}

		init_table();

		printf("Load init_table (%s)\n", init_table_name);
		if(load_init_tables(init_table_name) == 0) load_init_table = false;
		
		if(!load_init_table && log_name != NULL) {
				if(!init_scan(log_name)) return 0;
				printf("Save init_table (%s)\n", init_table_name);
				save_init_tables(init_table_name);
		}
		
		if(log_name != NULL){
				fp = fopen(log_name, "r");
				generate_fp_table(fp);
				print_fp_table();
		}
		
		if(user_pid > 0) {
				printf("user taint tid = %d, pid = %d\n", user_pid, get_pid(user_pid));
				taint_all_units_in_pid(user_pid, "start_node");
		}

		if(user_inode > 0) {
				string path;
				long user_eid = check_inode_list(user_inode, &path, &forward_ts);
				if(user_eid < 0) return 1;
				debugtaint("taint inode from initial : %ld [%ld]\n", user_inode, user_eid);
				if (path[0] == ' ') path = path.substr(1);
				taint_inode(user_inode, user_eid, path);
		}
		if(log_name != NULL){
				fclose(fp);
		}
		else{
				printf("calling table scan.\n");
				table_scan_f(user_pid, user_inode);
		}

		fp = fopen("AUDIT_ft.graph", "w");

		emit_graph(fp);
		emit_graph_detail(fp);
		fclose(fp);

		auto end = chrono::system_clock::now();
		chrono::duration<double> elapsed_seconds = end-start;
		printf("elapsed time: %lf\n", elapsed_seconds.count());

		return 1;
}

