#
# Author: Jarrod N. Bakker
# NWEN406 T2 2015, Project 2
#


# Modules
import binascii
import hashlib
import os
import socket

class KDFComputer():

    HASH_FUNCTION = "sha512"
    NUM_ROUNDS = 1000000 # Add an extra 0 to increase CPU load,
                         # although this should be sufficient.

    """
    Securely hash a password using PKCS#5 password-based key derivation
    function 2 with HMAC as a pseudorandom function.

    @param password - the password to hash with the KDF
    @param salt - to season the hash
    @return - the derived key
    """
    def compute_kdf(self, password, salt): 
        bpassword = bytearray(password)
        bsalt = bytearray(salt)
        derived_key = hashlib.pbkdf2_hmac(self.HASH_FUNCTION, bpassword,
                                          bsalt, self.NUM_ROUNDS)
        print "[+] " + str(socket.gethostbyname(socket.gethostname()))
        print "[+] " + str(derived_key)
        print "[+] " + str(binascii.hexlify(derived_key))

if __name__ == "__main__":
    pass_bytes = bytearray("password")
    salt_bytes = bytearray(os.urandom(512))
    KDFComputer().compute_kdf(pass_bytes,salt_bytes)

