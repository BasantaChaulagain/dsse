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

    -u, --update "<file>"
        Updates a single file, included appending local index, appending encrypted remote index, encrypting "file", and sending it to server.

    -i, --inspect_index
        Prints out local unencrypted index. 
        BUG: require an argument, although unused.
