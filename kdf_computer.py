#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#


# Modules
from threading import Thread
import binascii
import hashlib
import json
import os
import signal
import socket
import sys

class KDFComputer():

    # Hash function constants
    HASH_FUNCTION = "sha512"
    NUM_ROUNDS = 1000000 # Add an extra 0 to increase CPU load,
                         # although this should be sufficient.
    SALT_LENGTH = 512 # length of salt in bytes

    # Socket constants
    CLIENT_PORT = 9002
    RECV_BUF_SIZE = 1024
    SERVER_PORT = 9001
    SCKT_TIMEOUT = 2

    # Other constats
    MSG_START = "Starting KDFComputer..."
    PAYLOAD_ID = "id"
    PAYLOAD_JOB = "password"
    PAYLOAD_RESULT = "hash"

    def __init__(self):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)

        # Welcome message
        print(self.MSG_START + "\n" + len(self.MSG_START)*"=")

        # Hash the machine's local IP address to make an ID
        local_ip = socket.gethostbyname(socket.gethostname())
        self._id = hashlib.sha1(local_ip).hexdigest()
        print("Machine ID: " + self._id)

        self._num_threads = 0

        # Create a socket for listening for incoming connections
        try:
            self._sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            print("[-] Failed to create server socket.")
            print("[-] Terminating program.")
            sys.exit(1)

        # Start listening for connections!
        self.server_listen()

    """
    Securely hash a password using PKCS#5 password-based key derivation
    function 2 with HMAC as a pseudorandom function.

    @param password - the password to hash with the KDF
    @param salt - to season the hash
    @return - the derived key
    """
    def compute_kdf(self, password, salt): 
        bpassword = bytearray(str(password))
        bsalt = bytearray(salt)
        return hashlib.pbkdf2_hmac(self.HASH_FUNCTION, bpassword,
                                   bsalt, self.NUM_ROUNDS)

    """
    Return the results of the completed work back to the client who
    sent it.

    @param addr - the client's address.
    @param data - the completed work.
    """
    def return_client_job(self, addr, password, dk, thread_name):
        # Establish connection
        try:
            sckt_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sckt_out.settimeout(self.SCKT_TIMEOUT)
            sckt_out.connect((addr, self.CLIENT_PORT))
            print("["+thread_name+"] Connection established with client "
                  + str(addr) + ":" + str(self.CLIENT_PORT))
        except:
            print("["+thread_name+"] Unable to connect to client "
                  + str(addr) + ":" + str(self.CLIENT_PORT))
            return

        # Send the data
        data = str(json.dumps({self.PAYLOAD_ID:self._id,
                               self.PAYLOAD_RESULT:dk,
                               self.PAYLOAD_JOB:password}))
        try:
            print("["+thread_name+"] Sending data to client...")
            sckt_out.sendall(data)
            print("["+thread_name+"] Data sent to server successfully.")
        except:
            print("["+thread_name+"] Unable to send data to server.")

        # Close the socket
        sckt_out.close()

    """
    Read data from an incoming connection and process it.

    @param client_sock - the socket binding the client's connection.
    @param addr - the client's address.
    @param thread_name - name of the thread doing the work.
    """
    def serve_client(self, client_sock, addr, thread_name):
        # Read client data
        buf_in = client_sock.recv(self.RECV_BUF_SIZE)
        print("["+thread_name+"] Received data from " + str(addr[0]))

        client_sock.close()
        print("["+thread_name+"] Closing connection with " + str(addr[0]))

        # Decode the payload and check that it's valid
        try:
            data = json.loads(buf_in)
            if self.PAYLOAD_JOB not in data:
                raise
        except:
            print("["+thread_name+"] Unable to decode valid JSON from "
                  "received data.")
            return

        # Compute the derived key using the payload value
        password = data[self.PAYLOAD_JOB]
        salt = os.urandom(self.SALT_LENGTH)
        dk = self.compute_kdf(password, salt)
        dk_str = str(binascii.hexlify(dk)) # turn the dk into a readable format
        print("["+thread_name+"] Derived key (hex): " + dk_str)

        # Send the derived key back to the client
        self.return_client_job(addr[0], password, dk_str, thread_name)

    """
    Listen for incoming TCP connections and spawn threads to handle
    client data.
    """
    def server_listen(self):
        # Bind port to a socket
        try:
            self._sckt.bind(("", self.SERVER_PORT))
            print("[+] Socket binded to port "
                  + str(self.SERVER_PORT) + ".")
        except socket.error as err:
            print("[-] Failed to bind socket to port "
                  + str(self.SERVER_PORT) + "\nError: " + str(err[0])
                  + " Message: " + str(err[1]))
            print("[-] Terminating program.")
            sys.exit(1)

        self._sckt.listen(5) # 5 connections can be queued at once
        print("[+] Listening for connections on port "
              + str(self.SERVER_PORT))
        
        # Serve connections
        while(True):
            client_sock, addr = self._sckt.accept()
            print("[+] Received connection from " + str(addr[0]))
            thread_name = "Thread#" + str(self._num_threads)
            self._num_threads += 1
            t = Thread(target=self.serve_client, name=thread_name,
                       args=(client_sock, addr, thread_name))
            t.start()

        # This should never be reached.
        self._sckt.close()
        print("[!] Server socket closed.")

    """
    Catch the SIGINT call (made by Ctrl-C) and clean up the server's
    listening socket.
    """
    def signal_handler(self, signal, frame):
        print("\n[!] Closing server socket.")
        self._sckt.close()
        print("[+] Closing program.")
        # Error code for Ctrl-C should be 130 but I'm treating this as
        # a valid way to close the program.
        sys.exit(0)
    
if __name__ == "__main__":
    KDFComputer()

