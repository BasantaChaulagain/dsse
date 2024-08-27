# Overview

FA-SEAL (Forensically Analyzable Symmetric Encryption for Audit Logs) is a novel system that enables forensic anal- ysis directly on encrypted audit logs while exclusively disclosing only cyberattack-relevant events to third-party investigators.

FA-SEAL operates in two phases: audit log ingestion and forensic analysis. During ingestion, FA-SEAL leverages symmetric encryption to encrypt audit logs while maintaining indexes for efficient and selective searching. To further optimize performance, we employ segmentation and clustering techniques. These techniques break down the logs into manageable parts that can be independently encrypted and decrypted, improving both ingestion speed and analysis efficiency. In the analysis phase, investigators can issue queries to FA-SEAL and receive causal graphs without exposing any incident-unrelated information.

This repo contains the source code of implementation of FA-SEAL. It is a client-server architecture where client refers to the secure log server which collects the logs from various log generating devices, encodes and encrypts them and send it to the cloud server, denoted by server. The source code is partly adapted from [this repo](https://github.com/IanVanHoudt/Searchable-Symmetric-Encryption/tree/master). 

The 'client' folder contains the source code for ingestion of logs. The 'investigator' directory contains the scripts for performing forensic analysis along with the benchmarking scripts required for the evaluation. The folder 'jmap' contains the code to pack and unpack messages between the client and the server. The server-side functions during ingestion and forensic analysis is contained the 'server' directory. The 'tracking' folder contains the core backend code for log analysis, which is responsible to find the dependency relationship between entities (file, process, network sockets) and generate provenance graph out of it. 

## Environment

This system is tested on Ubuntu 20.04.06 and 24.04. The python version is 3.8.10 (pip version 20.0.2) and cpp(g++) version is >=9.4.0. Other python dependencies of the project are written in requirements.txt file. Install all the requirements before running the project.

Audit log data used in the evaluation of this project can be found [here](). We pre-process the raw audit log and convert it to a csv with all the information required for forensic analysis. Each event is represented by a 35-fields csv, the details of which can be found in [tracking/README_CSV.txt](tracking/README_CSV.txt).

## Configuration and Set-up

1. Install Python3(3.8.10), pip3(20.0.2) and python3-venv.

2. Make a virtual environment and activate it.
```
    python3.8 -m venv /path/to/new/venv
    cd /path/to/new/venv
    source bin/activate
```

3. Clone [this github repo](https://github.com/BasantaChaulagain/faseal).
```
    git clone https://github.com/BasantaChaulagain/faseal.git
```

4. Install the requirements from requirements.txt inside the virtual environment.
```
    pip install -r requirements.txt
```

5. Change the [config file](client/config.ini) to set the system hyperparameter values like number of logs in a segment, number of segments in a cluster, mode of operation, etc. Skip this step to select the default options.

6. Compile the C++ source code in 'tracking' folder, and copy 'AUDIT_bt' and 'AUDIT_ft' to the client directory
```
    cd tracking
    make
    cp AUDIT_bt ../client/
    cp AUDIT_ft ../client/
```

## Log Ingestion

1. Run the server program in a separate terminal inside a virtual environment. The server program is hosted in localhost port 5000, which represents a remote cloud server. Keep it running as long as you are using the system for ingestion and forensic analysis.
```
    cd server
    source ../../bin/activate
    python sse_server.py
```

2. From the client directory, run the script 'clean.sh' that erases the currently stored encrypted logs and indexes from the cloud server and allows to begin a new ingestion process.

```
    cd client
    source ../../bin/activate
    ./clean.sh
```

3. Initiate a log ingestion process for an audit log of the motivating example, contained in the (client/sample_data) folder. This will segment the logs, encode and encrypt the logs and send the encrypted logs and indexes to the cloud server. (can be found in server/enc and server/indexes respectively.)
```
    python client.py -u sample_data/mot_data_theft.csv
```

Note: -u is for ingesting/updating a log file. For other options, see `python client.py -h`.

## Forensic Analysis

Forensic analysis is can either by backtracking or forward tracking. Investigator needs to specify the type of analysis (backtracking or AUDIT_ft), process identifier (pid) or file inode to analyze and the audit log file containing the attack logs.

1. Create aninitial database from the log file that contains the mapping of pids and inodes to their respective process names and filenames. The following command will create a file named `a1.data_theft.csv_init_table.dat` in `sample_data` directory, which is used for analysis. Note: The table can be generated using `./AUDIT_ft` command as well, and `-p 1` denotes a dummy pid. You just need to run this command once for a log file. 
```
cd client/
./AUDIT_bt -i sample_data/a1.data_theft.csv -p 1
```

2. Go to the investigator folder and perform a forward tracking analysis on a stolen file `salary_sheet.csv (inode: 22550385)`. This will create a graph named `AUDIT_ft.gv`. Use `./AUDIT_bt` for backtracking and `-p` option to analyze pid.
```
cd ../investigator/
./forensics.sh ft a1.data_theft.csv f 22550385
```

3. Convert the text graph data to a visual form using `graphviz`. Note: Install graphviz with `sudo apt install graphviz`, if not installed.
```
dot -T png AUDIT_ft.gv -o output_graphs/graph1.png
```

4. Now, perform backtracking on the process `scph (pid: 489755)` and generate the visual graph.
```
./forensics.sh bt a1.data_theft.csv p 489755
dot -T png AUDIT_bt.gv -o output_graphs/graph2.png
```
