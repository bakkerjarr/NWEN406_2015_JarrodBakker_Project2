#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#

# Modules
from optparse import OptionParser
from threading import Thread
import json
import signal
import socket
import sys

class KDFClientSender():
    
    # Constants
    JOB_FILE = "./jobs.txt"
    MSG_START = "Starting KDFClient Job Sender..."
    PAYLOAD_ID = "id"
    PAYLOAD_JOB = "password"
    PAYLOAD_RESULT = "hash"
    RECV_BUF_SIZE = 1024
    SERVER_PORT = 9001
    SCKT_TIMEOUT = 2

    def __init__(self, server_address, batch_size=5):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)

        # Welcome message
        print(self.MSG_START + "\n" + len(self.MSG_START)*"=")
        
        # Initialise fields
        self._server_ip = server_address
        self._jobs = []
        self._batch_size = batch_size
        self._num_threads = 0

        self.load_jobs()
        self.send_jobs()
        print("[!] Closing program.")

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
    
    """
    # TODO comments above
    def server_session(self, job, thread_name):
        # Establish a connection
        try:
            sckt_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sckt_out.settimeout(self.SCKT_TIMEOUT)
            sckt_out.connect((self._server_ip, self.SERVER_PORT))
            print("["+thread_name+"] Connection established with server "
                  + str(self._server_ip) + ":" + str(self.SERVER_PORT))
        except:
            print("["+thread_name+"] Unable to connect to server "
                  + str(self._server_ip) + ":" + str(self.SERVER_PORT))
            return

        # Send the data
        data = str(json.dumps({self.PAYLOAD_JOB:job}))
        try:
            print("["+thread_name+"] Sending data to server...")
            sckt_out.sendall(data)
            print("["+thread_name+"] Data sent to server successfully.")
        except:
            print("["+thread_name+"] Unable to send data to server.")

        # Wait for reply
        print("["+thread_name+"] Waiting for reply...")
        
        buf_in = sckt_out.recv(self.RECV_BUF_SIZE)
        print("["+thread_name+"] Received data from server.")
        
        # Close the socket
        sckt_out.close()
        
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
    Send the jobs to the server for processing in batches of size
    batch_size.

    @param batch_size - the number of jobs to send in one hit.
    """
    def send_jobs(self):
        if len(self._jobs) < 1:
            print("[!] No jobs exist.")
            return

        print("[?] Sending jobs in batch of max. size: " + str(self._batch_size))

        batch_count = 0
        self._server_ip = "NWEN406-ELB-1167097960.ap-southeast-2.elb.amazonaws.com"

        for job in self._jobs:
            if batch_count > self._batch_size-1:
                print("[?] Batch sent.")
                raw_input("\tPress <Enter> to continue...")
                batch_count = 0

            # send work in thread
            thread_name = "Thread#" + str(self._num_threads)
            self._num_threads += 1
            t = Thread(target=self.server_session, name=thread_name,
                       args=(job, thread_name))
            t.start()
            
            #Increment batch_count
            batch_count += 1

        print("[+] List of jobs has been exhausted.")
    
    """
    Catch the SIGINT call (made by Ctrl-C) and clean up the server's
    listening socket.
    """
    def signal_handler(self, signal, frame):
        print("[!] Closing program.")
        # Error code for Ctrl-C should be 130 but I'm treating this as
        # a valid way to close the program.
        sys.exit(0)


if __name__ == "__main__":
    # Parse command line arguments
    parser = OptionParser()
    parser.add_option("-a", action="store", type="string",
                      dest="address", help="IP address of the server.")
    parser.add_option("-b", action="store", type="int",
                      dest="batch_size",
                      help="Number of jobs to send at a time.")
    (options, args) = parser.parse_args()
    if not options.address:
        parser.error("Server IP address was not provided.")

    # Start the client sender
    if not options.batch_size:
        KDFClientSender(options.address)
    else:
        KDFClientSender(options.address, options.batch_size)

