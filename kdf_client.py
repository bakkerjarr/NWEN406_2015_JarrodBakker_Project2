#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#

# Modules
from optparse import OptionParser
from threading import Thread
import binascii # NOTE may not need this?
import json
import signal
import socket
import sys

class KDFClient():
    # TODO - 1. one thread sends jobs
    # TODO - 2. another thread listens for completed work to be sent back
    
    # Constants
    CLIENT_PORT = 9002
    JOB_FILE = "./jobs.txt"
    PAYLOAD_ID = "id"
    PAYLOAD_JOB = "password"
    PAYLOAD_RESULT = "hash"
    RECV_BUF_SIZE = 1024
    SERVER_PORT = 9001
    SCKT_TIMEOUT = 2

    def __init__(self, server_address):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Initialise fields
        self._server_ip = server_address
        self._jobs = []
        self._num_threads = 0

        # Create a socket for listening for incoming connections.
        try:
            self._sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            print("[-] Failed to create listening socket.")
            print("[-] Terminating program.")
            sys.exit(1)

        self.load_jobs()
        # TODO Once jobs have loaded, create threads to hold send_jobs()
        #      and receive_results() and start them up.
        self.send_jobs()
        self.receive_results()
    
    """
    Load the jobs from a file into a list of jobs.
    """
    def load_jobs(self):
        print("[?] Opening file " + str(self.JOB_FILE) + "...")
        try:
            f = open(self.JOB_FILE)
        except:
            print("[-] Unable to open file " + str(self.JOB_FILE))
            return
        for line in f:
            if line[0] == "#" or not line.strip():
                continue # skip comments and empty lines
            self._jobs.append(line.strip("\n"))
        f.close()
        print("[?] File read successfully.")

    """
    Send the jobs to the server for processing.
    """
    def send_jobs(self):
        if len(self._jobs) < 1:
            print("[!] No jobs exist.")
            return
        for job in self._jobs:
            # Establish a connection
            try:
                sckt_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sckt_out.settimeout(self.SCKT_TIMEOUT)
                sckt_out.connect((self._server_ip, self.SERVER_PORT))
                print("[+] Connection established with server "
                      + str(self._server_ip) + ":" + str(self.SERVER_PORT))
            except:
                print("[-] Unable to connect to server "
                      + str(self._server_ip) + ":" + str(self.SERVER_PORT))
                return

            # Send the data
            data = str(json.dumps({self.PAYLOAD_JOB:job}))
            try:
                print("[?] Sending data to server...")
                sckt_out.sendall(data)
                print("[+] Data sent to server successfully.")
            except:
                print("[-] Unable to send data to server.")

            # Close the socket
            sckt_out.close()
    
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
        print("[+] Closing program.")
        # Error code for Ctrl-C should be 130 but I'm treating this as
        # a valid way to close the program.
        sys.exit(0)


if __name__ == "__main__":
    # Parse command line arguments
    parser = OptionParser()
    parser.add_option("-a", "--address", action="store", type="string",
                      dest="address", help="IP address of the server.")
    (options, args) = parser.parse_args()
    if not options.address:
        parser.error("Server IP address was not provided.")
    # Start the client
    KDFClient(options.address)

