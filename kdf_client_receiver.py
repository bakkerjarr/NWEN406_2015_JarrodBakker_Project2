#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#

# Modules
from threading import Thread
import json
import signal
import socket
import sys

class KDFClientReceiver():
    
    # Constants
    CLIENT_PORT = 9002
    MSG_START = "Starting KDFClient Job Receiver..."
    PAYLOAD_ID = "id"
    PAYLOAD_JOB = "password"
    PAYLOAD_RESULT = "hash"
    RECV_BUF_SIZE = 1024

    def __init__(self):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)

        # Welcome message
        print(self.MSG_START + "\n" + len(self.MSG_START)*"=")
        
        # Initialise fields
        self._num_threads = 0

        # Create a socket for listening for incoming connections.
        try:
            self._sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            print("[-] Failed to create listening socket.")
            print("[-] Terminating program.")
            sys.exit(1)

        self.receive_results()
    
    """
    Given a connection from a server who has completed a job, read the
    result from the socket and print to the terminal.

    @param rec_sock - the socket binding the server's connection.
    @param addr - the server's address.
    @param thread_name - name of the thread doing the work.
    """
    def read_results(self, recv_sock, addr, thread_name):
        # Read the data
        buf_in = recv_sock.recv(self.RECV_BUF_SIZE)
        print("["+thread_name+"] Received data from " + str(addr[0]))

        recv_sock.close()
        print("["+thread_name+"] Closing connection with " + str(addr[0]))

        # Decode the payload and check for validity
        try:
            data = json.loads(buf_in)
            if (self.PAYLOAD_ID not in data
                and self.PAYLOAD_RESULT not in data
                and self.PAYLOAD_JOB not in data):
                raise
        except:
            print("["+thread_name+"] Unable to decode valid JSON from "
                  "received data.")
            return

        # Print the result to the terminal
        print("["+thread_name+"]\tMachine ID: " + data[self.PAYLOAD_ID]
              + "\n\t\tPassword: " + data[self.PAYLOAD_JOB]
              + "\n\t\tHash: " + data[self.PAYLOAD_RESULT]) 

    """
    Receive completed jobs from the server and display them to the user.
    """
    def receive_results(self):
        # Bind port to a socket
        try:
            self._sckt.bind(("", self.CLIENT_PORT))
            print("[+] Socket binded to port "
                  + str(self.CLIENT_PORT) + ".")
        except socket.error as err:
            print("[-] Failed to bind socket to port "
                  + str(self.CLIENT_PORT) + "\nError: " + str(err[0])
                  + " Message: " + str(err[1]))
            print("[-] Terminating program.")
            sys.exit(1)

        self._sckt.listen(5) # 5 connections can be queued at once
        print("[+] Listening for connections on port "
              + str(self.CLIENT_PORT))
        
        # Serve connections
        while(True):
            recv_sock, addr = self._sckt.accept()
            print("[+] Received connection from " + str(addr[0]))
            thread_name = "Thread#" + str(self._num_threads)
            self._num_threads += 1
            t = Thread(target=self.read_results, name=thread_name,
                       args=(recv_sock, addr, thread_name))
            t.start()

        # This should never be reached.
        self._sckt.close()
        print("[!] Server socket closed.")


    """
    Catch the SIGINT call (made by Ctrl-C) and clean up the server's
    listening socket.
    """
    def signal_handler(self, signal, frame):
        print("\n[!] Closing listening socket.")
        self._sckt.close()
        print("[!] Closing program.")
        # Error code for Ctrl-C should be 130 but I'm treating this as
        # a valid way to close the program.
        sys.exit(0)


if __name__ == "__main__":
    # Start the clien receiver
    KDFClientReceiver()

