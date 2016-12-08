# CrypTopology

This project includes the next files:

1)client.py - the script of the client

2)coll.py - the script of the collaborators

3)server.py - the script of the server

4)names.py - module of global variabels of protocol

5)generate_keys.py - generates the RSA keys (public&private) for the init packet

6)coll_list.txt -an example of a file that the server reads from,
in each line the format is: <collaborator_ip>-<collaborator hmac key>.
the added file is an example of a collaborator list file format with 2 collaborator.
the server takes as a parameter to the command line the path to this file.

7)col1_key.txt, col2_key.txt - examples of collaborators key files, in each of this file inserted a key of collaborator.
each collaborator takes as a parameter to the command line the path to this file.

How to run the project:

First of all, run the generate_keys.py script in order to generate the keys to the init packet.
you should update the pathes to the keys in the names.py module.
then set up machines, and make your coll_list.txt file according to the format.
then make your col_key.txt files and then you can run the scripts:'

sudo python server.py path/to/coll_list.txt

sudo python coll.py path/to/col1_key.txt
.
.
.
(do this for each collaborator)

python client.py





