#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#

# Modules
from optparse import OptionParser
from urllib2 import urlopen
import json
import signal
import socket
import sys

class KDFClientSender():
    
    # Constants
    JOB_FILE = "./jobs.txt"
    MSG_START = "Starting KDFClient Job Sender..."
    PAYLOAD_JOB = "password"
    PAYLOAD_SRC = "source"
    SERVER_PORT = 9001
    SCKT_TIMEOUT = 2

    def __init__(self, server_address, batch_size=5):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)

        # Welcome message
        print(self.MSG_START + "\n" + len(self.MSG_START)*"=")
        
        # Initialise fields
        self._client_ip = urlopen('http://ip.42.pl/raw').read()
        self._server_ip = server_address
        self._jobs = []
        self._batch_size = batch_size

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
            data = str(json.dumps({self.PAYLOAD_SRC:self._client_ip,
                                   self.PAYLOAD_JOB:job}))
            try:
                print("[?] Sending data to server...")
                sckt_out.sendall(data)
                print("[+] Data sent to server successfully.")
            except:
                print("[-] Unable to send data to server.")

            # Close the socket
            sckt_out.close()

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

