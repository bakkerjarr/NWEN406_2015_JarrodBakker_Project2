# NWEN406_2015_JarrodBakker_Project2
Contains the code for NWEN406 Project 2 where the task was to explore Elastic Load Balancing using AWS.

## Outline
Securely hashing passwords using key derivation functions (KDFs)) can be an expensive task for a single machine. This task can be completed faster by using cloud computing architectures to distribute the load across multiple virtual machines. The aim of the project was to gain experience using AWS Elastic Load Balancers therefore KDFs were used to impose a load on a system.

## Contents of this repo
- jobs.txt - This file contains a series of passwords that need to be hashed by KDFCompute.
- kdf_client.py - This program sends passwords to KDFCompute to be hashed and receives the completed jobs and displays them on screen.
- kdf_computer.py - This program runs on an instance to accept and process incoming work.
