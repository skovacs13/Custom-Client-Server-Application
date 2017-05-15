README for Sock352 Application

This was a school assignment for a class called Internet Technology, it was a partner assignment and Daniel Tsioni was my partner.
The client and server files 1-3 were supllied by the instructor and we modified the sock352.py file in order to get the client and server
files to communicate using the protocol we implemented.

The client and sever files can be run either on the same machine or on two different machines as long as both machines have the sock352.py
file saved in the same directory. If using the client1 file, you must use the server1 file and vice versa, the same also goes for the 
client/server 2 and 3 files. 

The custom protocol that was implemented by us was based on UDP protocal but mimiced TCP protocol.

Instructions on how to run the applictaion on the same machine:
Run the server first using the command below:

$ python server1.py -f filetoreceive.txt -u 9999 -v 8888

Where file to receive is the file the payload will be saved in and 9999 and 8888 are examples of portnumbers to use.

The client command is as follows:

$ python client1.py -f filetosend.txt -d localhost -u 8888 -v 9999

Where the -d flag denotes the destination the client is sending sending to. Note the two port numbers must be reversed.

For two different machines the command is the same for the server but for the client after -d input the ip address of the machine you 
wish to send to:

$ python client1.py -f filetosend.txt -d 123.4.56.789 -u 8888 -v 9999

The client3.py and server3.py are run exactly the same, but for client2/server2 the commands have one more argument:

$ python server2.py -f filetoreceive.txt -u 9999 -v 8888 -k keyfile
$ python client2.py -f filetosend.txt -d 123.4.56.789 -u 8888 -v 9999 -k keyfile

Where the -k flag indicates a keyfile and where "keyfile" is the name of that file. For all 3 versions both machines must have the 
sock352.py file and for the client2/server2 case both must have a valid keyfile. 

The client2/server2 files encrypt and then decrypt the data being sent.
