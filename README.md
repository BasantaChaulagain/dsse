# Overview

FA-SEAL (Forensically Analyzable Symmetric Encryption for Audit Logs) is a novel system that enables forensic anal- ysis directly on encrypted audit logs while exclusively disclosing only cyberattack-relevant events to third-party investigators.

FA-SEAL operates in two phases: audit log ingestion and forensic analysis. During ingestion, FA-SEAL leverages symmetric encryption to encrypt audit logs while maintaining indexes for efficient and selective searching. To further optimize performance, we employ segmentation and clustering techniques. These techniques break down the logs into manageable parts that can be independently encrypted and decrypted, improving both ingestion speed and analysis efficiency. In the analysis phase, investigators can issue queries to FA-SEAL and receive causal graphs without exposing any incident-unrelated information.

This repo contains the source code of implementation of FA-SEAL. It is a client-server architecture where client refers to the secure log server which collects the logs from various log generating devices, encodes and encrypts them and send it to the cloud server, denoted by server. The source code is partly adapted from [this repo](https://github.com/IanVanHoudt/Searchable-Symmetric-Encryption/tree/master). 

The 'client' folder contains the source code for ingestion of logs and performing forensic analysis, along with the scripts required for the evaluation. The folder 'jmap' contains the code to pack and unpack messages between the client and the server. The server-side functions during ingestion and forensic analysis is contained the 'server' directory. The 'tracking' folder contains the core backend code for log analysis, which is responsible to find the dependency relationship between entities (file, process, network sockets) and generate provenance graph out of it. 

## Environment

This system is tested on Ubuntu 20.04.06 and 24.04. The python version is 3.8.10 and cpp(g++) version is 9.4.0. Other python dependencies of the project are written in requirements.txt file. Install all the requirements before running the project.

Audit log data used in the evaluation of this project can be found here. We pre-process the raw audit log and convert it to a csv with all the information required for forensic analysis. Each event is represented by a 35-fields csv, the details of which can be found in [tracking/README_CSV.txt](tracking/README_CSV.txt).

## Configuration

## Log Ingestion

To use this SSE implementation, you must first have the server running:

	python sse_server.py

Then invoke the client with one of the requisite options:

	python client.py <OPTION>

It is also required that the user has access to some set of audit log file.

## Forensic Analysis
    -s, --search "<term(s)>"
        Search for term or terms in quotations

    -u, --update "<file>"
        Updates a single file, included appending local index, appending encrypted remote index, encrypting "file", and sending it to server.
