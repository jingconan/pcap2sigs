#!/usr/bin/env python
from __future__ import print_function, division
import networkx as nx

def parseToNetworkX(f_name):
    with open(f_name, 'r') as fid:
        line = fid.readline()
        nodes = line.split()
        i = 0
        sigs = []
        g = nx.DiGraph()
        g.add_nodes_from(xrange(len(nodes)))
        line = fid.readline()
        for line in fid:
            if line[0] == 'G':
                sigs.append(g)
                g = nx.DiGraph()
                g.add_nodes_from(xrange(len(nodes)))
                continue

            res = line.split(' -> ')
            from_node = int(res[0])
            to_node = int(res[1])
            g.add_edge(from_node, to_node)
        sigs.append(g)
    return sigs

if __name__ == "__main__":
    # parseToNetworkX
    sigs = parseToNetworkX('./dosattack.sigs')
    # import ipdb;ipdb.set_trace()
    pass

