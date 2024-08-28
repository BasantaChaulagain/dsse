import sys, getopt
import re

def main(argv):
    opts, args = getopt.getopt(argv, "hi:n:g:")
    num_of_relevant_logs = -1
    for opt, arg in opts:
        if opt == "-h":
            print("USAGE:: python coverage_report.py -i <original_file> -g <graph_file>")
            sys.exit()
        elif opt == "-i":
            original_file = arg
        elif opt == "-o":
            num_of_relevant_logs = int(arg)
        elif opt == "-g":
            graph_file = arg
    
    pid_list = {}           # 7:9
    inode_list = {}         # 18:17
    eid_list = []           # 12
    
    with open(original_file, "r") as fp:
        for count, line in enumerate(fp):
            vals = line.split(';')
            if vals[7].strip() not in pid_list:
                pid_list[vals[7].strip()] = vals[9].strip()
            if vals[12].strip() not in eid_list:
                eid_list.append(vals[12].strip())
            if vals[18].strip() not in inode_list:
                inode_list[vals[18].strip()] = vals[17].strip()
    
    graph_pids = []
    graph_inodes = []
    graph_sockets = []
    with open(graph_file, "r") as fp:
        for line in fp.readlines():
            pid_match = re.match(r'\s+pid\s(\d+)', line)
            if pid_match:
                graph_pids.append(pid_match.groups()[0])
            inode_match = re.match(r'\s+inode\s(\d+)', line)
            if inode_match:
                graph_inodes.append(inode_match.groups()[0])
            socket_match = re.match(r'\s+\[\d+\]\s(.*?)\n', line)
            if socket_match:
                graph_sockets.append(socket_match.groups()[0])
    
            
    if num_of_relevant_logs > 0:
        total_lines_count = count
        print("Total lines of logs: ", total_lines_count)
        print("Total lines of analysed logs: ", num_of_relevant_logs)
        print("Coverage %: ", num_of_relevant_logs/total_lines_count*100, "\n")

    print("Total pids: ", len(pid_list))
    print("Graph pids: ", len(graph_pids))
    print("Total inodes: ", len(inode_list))
    print("Graph inodes: ", len(graph_inodes))
    print("Graph sockets: ", len(graph_sockets))
    total_nodes = len(pid_list)+len(inode_list)
    graph_nodes = len(graph_pids)+len(graph_inodes)+len(graph_sockets)
    print("Nodes coverage (%): ", graph_nodes/total_nodes*100, "\n")
    
#    print("Hidden processes::")
#    new_list = {}
#    for k,v in pid_list:
#        if k not in graph_pids:
#            new_list.append(v)
#    print(new_list)
    
    print("\nEffective uids: ", eid_list)

if __name__ == "__main__":
    main(sys.argv[1:])
