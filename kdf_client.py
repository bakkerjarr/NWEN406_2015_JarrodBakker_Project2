#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#

# Modules
import json
import signal
import socket
import sys

class KDFClient():
    # TODO - 1. one thread sends jobs
    # TODO - 2. another thread listens for completed work to be sent back
    
    # Constants
    JOB_FILE = "./jobs.txt"
    PAYLOAD_NAME = "password"
    SERVER_PORT = 9001
    SCKT_TIMEOUT = 2

    # Fields
    _jobs = []
    _server_ip = "127.0.0.1"

    def __init__(self):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)

        self.load_jobs()
        self.send_jobs()
    
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
            data = str(json.dumps({self.PAYLOAD_NAME:job}))
            try:
                print("[?] Sending data to server...")
                sckt_out.sendall(data)
                print("[+] Data sent to server successfully.")
            except:
                print("[-] Unable to send data to server.")

            # Close the socket
            sckt_out.close()
    

    """
    Catch the SIGINT call (made by Ctrl-C) and clean up the server's
    listening socket.
    """
    def signal_handler(self, signal, frame):
        print("[+] Closing program.")
        # Error code for Ctrl-C should be 130 but I'm treating this as
        # a valid way to close the program.
        sys.exit(0)


if __name__ == "__main__":
    # TODO server IP as an argument
    KDFClient()

