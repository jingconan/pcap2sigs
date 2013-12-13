Convert Pcap file to Social Interaction Graphs (SIGs)

Definition of Social Interaction Graph:
=======================

First, we divide the pcap file into several segments sequentially according
timestamp of packets. Each segment contains packets between a interval with
length **interval_length**. Suppose the total number of segements is **N**,
then there are N SIGs. Each SIG corresponds to the traffic in one segment. 

All SIGs share the node set, which is the set of IP addresses in this pcap
file. For the *kth* SIG, if there is packet in segment *k* whose source is
node i and the destination is node j, then edge (i, j) \in G_k.


Usage
=======================
    $ ./pcap2sigs <infile> <interval_size> [-debug]
    $ ./pcap2sigs ./dosattack.pcap 0.0083

The SIGs will be printed in standard output


Output Format
========================
The first line is set of all the ip addresses in the pcap file. IP addresses are separated
by space.
The following lines are the SIGs. For each SIG, the format is:

    G<graph no>
    <from node ID> -> <to node ID>

The ID of a node is the sequence of its ip addresses in the set defined by the first line. The ID is zero-based.

Example
-----------------
254.64.206.11 255.31.232.95 240.28.34.117
G0
0 -> 1
G1
1 -> 2
2 -> 0




LICENSE
----------------
GPLv3

Authors
----------------
Jing Conan Wang
hbhzwj AT gmail.com
