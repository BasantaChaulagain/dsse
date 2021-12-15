# SSE Implementation

# Dependencies

python-dev

libffi-dev
	
## Python packages
	
bcrypt

Stemming

numpy (optional)

pyyaml

nltk

Flask

	-install each with 'pip install <package>'

# How To
To use this SSE implementation, you must first have the server running:

	python sse_server.py

Then invoke the client with one of the requisite options:

	python sse_client.py <OPTION>

It is also required that the user has access to some set of text documents. I recommend using the Enron corpus, which provides a huge number and variety of email documents.

# Options
    -s, --search "<term(s)>"
        Search for term or terms in quotations

    -S, --search-header "<header>" "<term(s)>"
        Like --search, but only search for those terms in the listed header.

    -u, --update "<file>"
        Updates a single file, included appending local index, appending encrypted remote index, encrypting "file", and sending it to server.

    -e, --encrypt "<infile>" "<outfile>"
        Encrypts "infile", and writes out to "outfile". "Infile" is not modified.

    -d, --decrypt "<infile>" "<outfile>"
        Decrypts "infile" and writes clear text to "outfile". "Infile" is not modified.

    -i, --inspect_index
        Prints out local unencrypted index. 
        BUG: require an argument, although unused.
