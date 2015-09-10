# NWEN406_2015_JarrodBakker_Project2
Contains the code for NWEN406 Project 2 where the task was to explore Elastic Load Balancing using AWS.

## Outline
Securely hashing passwords using key derivation functions (KDFs)) can be an expensive task for a single machine. This task can be completed faster by using cloud computing architectures to distribute the load across multiple virtual machines. The aim of the project was to gain experience using AWS Elastic Load Balancers therefore KDFs were used to impose a load on a system.

## Contents of this repo
- jobs.txt - This file contains a series of passwords that need to be hashed by KDFCompute.
- kdf_client.py - This program sends batches of jobs out to a server specified by a CLI argument. It then listens for the results to be returned and displays them on the terminal.
- kdf_client_debug.py - A verbose version of the above client. Messages regarding the status of network connections are printed to the terminal.
- kdf_computer.py - This program runs on an instance to accept and process incoming work.
