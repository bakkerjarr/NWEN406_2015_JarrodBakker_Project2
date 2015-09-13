#!/usr/bin/python

#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#

# Modules
from optparse import OptionParser
from threading import Lock
from threading import Thread
import json
import signal
import socket
import sys

class KDFClient():
    
    # Constants
    MSG_START = "Starting KDFClient Job Sender..."
    PAYLOAD_ID = "id"
    PAYLOAD_JOB = "password"
    PAYLOAD_RESULT = "hash"
    RECV_BUF_SIZE = 1024
    SERVER_PORT = 9001

    def __init__(self, server_address, job_file):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)

        # Welcome message
        print(self.MSG_START + "\n" + len(self.MSG_START)*"=")
        
        # Initialise fields
        self._batch_size = 10
        self._completed_jobs = 0
        self._jobs = []
        self._lock = Lock()
        self._num_threads = 0
        self._server_ip = server_address

        self.load_jobs(job_file)
        self.send_jobs()
        print("[!] Closing program.")

    """
    Load the jobs from a file into a list of jobs.

    @param job_file - the file to load jobs from.
    """
    def load_jobs(self, job_file):
        print("[?] Opening file " + job_file + "...")
        try:
            f = open(job_file)
        except:
            print("[-] Unable to open file " + job_file)
            return
        for line in f:
            if line[0] == "#" or not line.strip():
                continue # skip comments and empty lines
            self._jobs.append(line.strip("\n"))
        f.close()
        print("[?] File read successfully.")

    """
    Send a job out for processing then wait for a reply containing the
    results.
    
    @param job - the job to send out to the server for processing.
    @param thread_name - name of the thread doing the work.
    """
    def server_session(self, job, thread_name):
        # Establish a connection
        try:
            sckt_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sckt_out.settimeout(360)
            sckt_out.connect((self._server_ip, self.SERVER_PORT))
            # Client has successfully connected to the server.
        except:
            # Client was unable to connect to the server.
            print("["+thread_name+"] Unable to connect to server "
                  + str(self._server_ip) + ":" + str(self.SERVER_PORT))
            return

        # Send the data
        data = str(json.dumps({self.PAYLOAD_JOB:job}))
        try:
            sckt_out.sendall(data)
            # Client sent data to the server successfully.
        except:
            # Client was unable to send data to server.
            print("["+thread_name+"] Unable to send data to server.")
            return

        # Wait for and read the reply
        buf_in = sckt_out.recv(self.RECV_BUF_SIZE)
        
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
            # Client was unable to decode valid JSON from the received data.
            print("["+thread_name+"] Unable to decode valid JSON from "
                  "received data.")
            print("["+thread_name+"] Data: " + str(data))
            return
            
        # Lock _completed_jobs before updating it. We release the lock after
        # the print has been made. This is greedy but we want to be sure
        # about what thread completed what job at a particular point in time.
        self._lock.acquire()
        self._completed_jobs += 1
        print("[?] " + str(self._completed_jobs) + " jobs completed so far.")
        # Print the result to the terminal
        print("["+thread_name+"]\tMachine ID: " + data[self.PAYLOAD_ID]
              + "\n\t\tPassword: " + data[self.PAYLOAD_JOB]
              + "\n\t\tHash: " + data[self.PAYLOAD_RESULT])
        self._lock.release()
    
    """
    Send the jobs to the server for processing in batches of size
    batch_size.

    @param batch_size - the number of jobs to send in one hit.
    """
    def send_jobs(self):
        if len(self._jobs) < 1:
            print("[!] No jobs exist.")
            return

        print("[?] " + str(len(self._jobs)) + " jobs loaded.")
        print("[?] Sending jobs in batch of max. size: " + str(self._batch_size))

        batch_count = 0
        
        # Force the client to initiate a send
        raw_input("\tPress <Enter> to send a batch of jobs.")

        for job in self._jobs:
            if batch_count > self._batch_size-1:
                print("[?] Batch sent.")
                raw_input("\tPress <Enter> to continue...\n")
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
    parser.add_option("-j", action="store", type="string", dest="job_file",
                      help="File of jobs separated by newlines.")

    # Parse and check the arguments
    (options, args) = parser.parse_args()
    if not options.address:
        parser.error("Server IP address was not provided.")
    if not options.job_file:
        parser.error("Job file was not provided.")

    # Start the client sender
    KDFClient(options.address, options.job_file)

