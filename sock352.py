import binascii
import socket as syssock
import struct
import sys
import random
import time
import nacl.utils
import nacl.secret
import pdb
from nacl.public import PrivateKey, Box

# global variables
global ENCRYPT
global publicKeys
global privateKeys
global publicKeysHex
global privateKeysHex
# populate global variables
publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}
ENCRYPT = 236
udpPkt_hdr_data = struct.Struct("!BBBBHHLLQQLL") # udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, seq_no, ack_no, window, payload_len)
# header indexes
VERSION_IND = 0
FLAGS_IND = 1
OPT_PTR_IND = 2
PROTOCOL_IND = 3
HEADER_LEN_IND = 4
CHECKSUM_IND = 5
SOURCE_PORT_IND = 6
DEST_PORT_IND = 7
SEQ_NO_IND = 8
ACK_NO_IND = 9
WINDOW_IND = 10
PAYLOAD_LEN_IND = 11
# flags
NO_FLAGS = 0x0
SYN = 0x01 # connection init
SYN_FLAG_LOC = 0x10
FIN = 0x02 # connection end
ACK = 0x04 # ack num
RESET = 0x08 # reset connection
HAS_OPT = 0xA # option field is valid
# constants
NO_ACK = 0
NO_SEQ = 0
VERSION = 0x1
ENCRYPTED = 1
RANDOM_CEIL = 1000000
HEADER_LEN = 40
TIMEOUT = 0.2
EMPTY_PAYLOAD = 0
MAX_PKT_SIZE = 65507
MAX_PAYLOAD_SIZE = 4096
DEFAULT_PORT = 27182
# unused header fields
PROTOCOL = 0
SOURCE_PORT = 0
DEST_PORT = 0
CHECKSUM = 0
WINDOW = 0

# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys

    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                    if words[1] != "*":
                        host = syssock.gethostbyname(words[1]) # when we read the keyfile we only want ip addresses
                    else:
                        host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host,port)] = keyInHex
                        privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host,port)] = keyInHex
                        publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception,e:
            print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
    else:
            print ("error: No filename presented")

    return (publicKeys,privateKeys)

def init(UDPportTx, UDPportRx):
    global transmission
    global receive

    if UDPportRx == 0:
        UDPportRx = DEFAULT_PORT

    transmission = int(UDPportTx)
    receive = int(UDPportRx)
    sock = socket()
    pass

class socket:
    sock = '' # this is our UDP socket
    partner = "" # address of partner socket (address, ack_no)
    encrypted = 0 # 0 means socket sends data unencrypted, 1 means encrypted
    window_size = 32768
    new_connection_packets = [] # list of (header, addr)
    window = [] # our window of packets, list of (header, payload, addr)
    new_ack_packets = [] # list of (header, "") empty string needed for nested one-tuple (we want to add more dimensions later)
    new_fin_packets = [] # list of (header, "")
    def __init__(self):
        # create any data structures you need
        self.sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        self.sock.settimeout(TIMEOUT)
        self.bind(('', 2))
        return

    def bind(self, address):
        try:
            self.sock.bind((address[0], receive))
        except:
            1 == 1
        return

    def connect(self, *args):
        if (len(args) >= 1):
            address = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypted = ENCRYPTED
        address = (address[0], transmission)

        seq_no = random.randint(1, RANDOM_CEIL) # initial sequence number is random
        pkt_hdr = udpPkt_hdr_data.pack(VERSION, SYN, self.encrypted, PROTOCOL, HEADER_LEN, CHECKSUM, SOURCE_PORT, DEST_PORT, seq_no, NO_ACK, WINDOW, EMPTY_PAYLOAD)

        self.__sock352_send_packet(str(pkt_hdr), "", address, "CONN")

        new_conn = self.new_connection_packets.pop()
        ack_no = new_conn[0][SEQ_NO_IND]
        self.window_size = new_conn[0][WINDOW_IND]
        self.partner = (new_conn[1], ack_no)
        return

    def listen(self, backlog):
        return

    def accept(self, *args):
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encrypted = ENCRYPTED

        while not self.new_connection_packets:
            try:
                self.__sock352_get_packet()
            except:
                1 == 1 # do nothing

        data, address = self.new_connection_packets.pop()
        new_seq_no = random.randint(1, RANDOM_CEIL) # send a random sequence number back
        ack_no = data[SEQ_NO_IND] + 1

        pkt_hdr = udpPkt_hdr_data.pack(VERSION, SYN | ACK, self.encrypted, PROTOCOL, HEADER_LEN, CHECKSUM, SOURCE_PORT, DEST_PORT, new_seq_no, ack_no, self.window_size, EMPTY_PAYLOAD)

        self.__sock352_send_packet(pkt_hdr, "", address, "")

        (clientsocket, address) = (self, address)
        self.partner = (address, new_seq_no) # set our partner, the open connection
        return (clientsocket, address)

    def close(self):
        connection_open = True
        pkt_hdr = udpPkt_hdr_data.pack(VERSION, FIN, self.encrypted, PROTOCOL, HEADER_LEN, CHECKSUM, SOURCE_PORT, DEST_PORT, NO_SEQ, NO_ACK, WINDOW, EMPTY_PAYLOAD)
        # if we send 10 FIN packets, there is a 0.00001024% chance they all fail at a 20% drop rate
        # so it's operationally guaranteed to transmit one successfully
        # until we receive a FIN, send FINs to the partner
        while not self.new_fin_packets:
            try:
                self.__sock352_get_packet()
            except:
                counter = 0
                while counter < 10:
                    counter += 1
                    self.__sock352_send_packet(pkt_hdr, "", self.partner[0], "")
        # if we've received a FIN, send a FIN back
        counter = 0
        while counter < 10:
            counter += 1
            self.__sock352_send_packet(pkt_hdr, "", self.partner[0], "")
        # close our connection
        self.sock.close()
        self.partner = None
        return

    def send(self, buffer):
        bytessent = 0
        counter = 0
        payload = buffer
        payload_len = len(payload)

        while bytessent < payload_len:
            seq_no = int(self.partner[1]) + counter
            subpayload = payload[ counter * MAX_PAYLOAD_SIZE: min( ( counter + 1 ) * MAX_PAYLOAD_SIZE, payload_len)]
            pkt_hdr = udpPkt_hdr_data.pack(VERSION, NO_FLAGS, self.encrypted, PROTOCOL, HEADER_LEN, CHECKSUM, SOURCE_PORT, DEST_PORT, seq_no, NO_ACK, WINDOW, len(subpayload))
            # send our packet until we get an ACK
            self.__sock352_send_packet(str(pkt_hdr), subpayload, self.partner[0], "ACK")

            ack = int(self.new_ack_packets.pop()[0][ACK_NO_IND])

            # if ack == seq_no: do nothing, we'll send it again
            if ack == seq_no + 1: # packet was received correctly
                counter += 1
                bytessent += len(subpayload)
        self.partner = (self.partner[0], self.partner[1] + counter) # remember which ack we should receive next
        return bytessent

    def recv(self, nbytes):
        payload = "" # what we are receiving
        bytes_received = 0
        seq_no = 0 # needs to be accessible at this logic level
        while bytes_received < nbytes:
            while not self.window:
                try:
                    self.__sock352_get_packet()
                except:
                    1 == 1 # do nothing

            packet = self.window.pop()
            seq_no = int(packet[0][SEQ_NO_IND])
            if seq_no == self.partner[1]: # correct packet
                if len(packet[1]) > nbytes:
                    payload += str(packet[1])[0:nbytes]
                    bytes_received += nbytes
                    self.window_size += nbytes # free up space in our window
                    self.window.insert(0, (packet[0], packet[1][nbytes:], packet[2])) # put what we haven't consumed back
                else:
                    seq_no += 1
                    payload += str(packet[1])
                    bytes_received += len(str(packet[1]))
                    self.window_size += len(packet[1]) + HEADER_LEN
                    pkt_hdr = udpPkt_hdr_data.pack(VERSION, ACK, self.encrypted, PROTOCOL, HEADER_LEN, CHECKSUM, SOURCE_PORT, DEST_PORT, NO_SEQ, seq_no, self.window_size, EMPTY_PAYLOAD)
                    self.__sock352_send_packet(pkt_hdr, "", self.partner[0], "")
            else:
                # if this was the wrong packet, free up space in the window and discard the packet
                self.window_size += len(packet[1]) + HEADER_LEN
            # ask for packet that's expected


            self.partner = (self.partner[0], seq_no) # update partner with the ACK we expect to receive next
        # we cannot know if they received our last ACK
        # to insure reliable data transfer, we must wait to receive one more packet from our client, before deciding how to continue
        packet_catch = True
        while packet_catch:
            while not self.window and not self.new_fin_packets:
                try:
                    self.__sock352_get_packet()
                except:
                    1 == 1 # do nothing
            if self.window:
                new_pkt = self.window.pop()
            elif self.new_fin_packets:
                new_pkt = self.new_fin_packets.pop()
            new_pkt_hdr = new_pkt[0]
            new_pkt_flags = new_pkt_hdr[FLAGS_IND]

            if new_pkt_flags & FIN: # the client is trying to end the connection, thus they got the last ACK
                self.new_fin_packets.append(new_pkt) # put it back on our queue
                packet_catch = False # and break this loop
            elif new_pkt_hdr[SEQ_NO_IND] == (self.partner[1] - 1): # the client is still trying to send the last packet, thus they did not get the last ACK
                # send the ACK again
                pkt_hdr = udpPkt_hdr_data.pack(VERSION, ACK, self.encrypted, PROTOCOL, HEADER_LEN, CHECKSUM, SOURCE_PORT, DEST_PORT, NO_SEQ, seq_no, self.window_size, EMPTY_PAYLOAD)
                __sock352_send_packet(pkt_hdr, "", self.partner[0], "")
            elif new_pkt_hdr[SEQ_NO_IND] == self.partner[1]: # the client is sending another correctly ordered packet, thus they got the last ACK
                self.window.append(new_pkt) # add the data packet back to the queue
                packet_catch = False # and break the loop
        return payload
    # this function sends a packet to the given address, and waits for a response on the given list
    # if list is False, then we don't loop
    def __sock352_send_packet(self, header, message, address, list):
        if self.encrypted == ENCRYPTED:
            message = self.__sock352_encrypt_packet(message, address)
        payload = header + message

        if list == "":
            self.sock.sendto(payload, address)
            return
        dest = (address[0], int(address[1]))

        if list == "CONN":
            while not self.new_connection_packets:
                try:
                    self.sock.sendto(payload, dest)
                    self.__sock352_get_packet()
                except:
                    1 == 1 # do nothing

        if list == "ACK":
            while not self.new_ack_packets:
                try:
                    self.sock.sendto(payload, dest)
                    self.__sock352_get_packet()
                except:
                    1 == 1 # do nothing

        if list == "FIN":
            while not self.new_fin_packets:
                try:
                    self.sock.sendto(payload, dest)
                    self.__sock352_get_packet()
                except:
                    1 == 1 # do nothing

    # this function grabs packets from the buffer and adds them to the appropriate queue
    def __sock352_get_packet(self):
        data, address = self.sock.recvfrom(MAX_PKT_SIZE)
        packed_header = ''.join(list(data)[:40]) # grab the first 40 bytes

        header = udpPkt_hdr_data.unpack(packed_header)
        flags = header[FLAGS_IND]
        options = header[OPT_PTR_IND]

        payload_len = header[PAYLOAD_LEN_IND]
        if options & ENCRYPTED:
            payload_len += 40 # encrypted payloads are 40 bytes longer
        payload = ''.join(list(data)[40:payload_len + 40]) # grab the payload
        if options & ENCRYPTED and len(payload) > 0:
            payload = self.__sock352_decrypt_packet(payload, address)
        if flags & SYN:
            self.new_connection_packets.append((header, address))
        elif flags & ACK:
            self.window_size = header[WINDOW_IND] # update available window size
            self.new_ack_packets.append((header, ""))
        elif flags & FIN:
            self.new_fin_packets.append((header, ""))
        elif not (flags & NO_FLAGS): # just a data packet
            if (self.window_size - HEADER_LEN - payload_len) >= 0:
                self.window.append((header, payload, address))
                self.window_size -= HEADER_LEN + payload_len
            else:
                1 == 1
                # the window is full so we discard our packet
        return
    # this function will encrypt the payload based on the given address and the keychain
    def __sock352_encrypt_packet(self, payload, address):
        if payload == "":
            return ""
        nonce = nacl.utils.random(Box.NONCE_SIZE)

        pkey = self.getPublicKey(address)
        skey = self.getPrivateKey()
        box = Box(skey, pkey)

        encrypted_message = box.encrypt(payload, nonce)
        return encrypted_message

    # this function will decrypt the payload based on the given address and the keychain
    def __sock352_decrypt_packet(self, payload, address):
        if payload == "":
            return ""

        pkey = self.getPublicKey(address)
        skey = self.getPrivateKey()
        box = Box(skey, pkey)

        #pdb.set_trace()
        decrypted_message = box.decrypt(payload)
        return decrypted_message

    def getPublicKey(self, address):

        key = (address[0], str(address[1]))

        try:
            pkey = publicKeys[key]
        except:
            try:
                pkey = publicKeys[(key[0], '*')]
            except:
                pkey = publicKeys[('*', '*')]
        return pkey

    def getPrivateKey(self):

        address = ('127.0.0.1', receive)

        try:
            skey = privateKeys[key]
        except:
            try:
                skey = privateKeys[(key[0], '*')]
            except:
                skey = privateKeys[('*', '*')]
        return skey
