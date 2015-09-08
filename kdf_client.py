#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#

# Modules
import signal
import sys

class KDFClient():
    # TODO - 1. one thread sends jobs
    # TODO - 2. another thread listens for completed work to be sent back
    
    # Constants
    JOB_FILE = "./jobs.txt"

    # Fields
    _jobs = []

    def __init__(self):
        # Catch Ctrl-C from the user
        signal.signal(signal.SIGINT, self.signal_handler)

        #self.main_loop()
        self.load_jobs()
        print self._jobs

    def main_loop(self):
        while(True):
            pass
    
    """
    Load the jobs from a file into a list of jobs.
    """
    def load_jobs(self):
        try:
            f = open(self.JOB_FILE)
        except:
            print("[-] Unable to open file " + str(self.JOB_FILE))
        
        for line in f:
            if line[0] == "#" or not line.strip():
                continue # skip comments and empty lines
            self._jobs.append(line.strip("\n"))
        f.close()

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
    KDFClient()

