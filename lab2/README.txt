ANS Lab 2 — Data Center on Your Computer
Group 13 | SS26 | Paderborn University


FILES
-----
topo.py        - Fat-tree graph data structure (k=4: 20 switches, 16 servers)
fat-tree.py    - Mininet topology builder with correct IPs and explicit dpids
ft_routing.py  - Two-level routing controller (Section 3.5, Al-Fares et al.)
sp_routing.py  - Shortest-path routing controller (Dijkstra)
run.sh         - Script to launch the Mininet network

REQUIREMENTS
------------
- Python 3
- Mininet
- Ryu SDN Framework (OpenFlow 1.3)
- Open vSwitch
- matplotlib, numpy (for plot.py)

HOW TO RUN — TWO-LEVEL ROUTING (ft_routing.py)


Open two terminals connected to the VM.

Terminal 1 — start the controller FIRST:
    cd lab2
    ryu-manager ft_routing.py --observe-links

Wait until you see:
    Rules installed on 20/20 switches

Terminal 2 — start the network:
    sudo mn -c
    bash ./run.sh

Wait for the mininet> prompt, then test:
    mininet> pingall
    mininet> pingall

Expected result: 0% dropped (240/240 received)

Additional tests:
    mininet> h0 ping h15 -c4     # cross-pod ping
    mininet> h1 ping h9 -c4      # cross-pod ping
    mininet> iperf h0 h4         # inter-pod throughput

HOW TO RUN — SHORTEST-PATH ROUTING (sp_routing.py)

Terminal 1:
    ryu-manager sp_routing.py --observe-links

Terminal 2:
    sudo mn -c
    bash ./run.sh

    mininet> pingall
    mininet> pingall

Expected result: 0% dropped (240/240 received)



TOPOLOGY DETAILS (k=4)

- 4 pods
- 4 core switches (c0-c3), dpid 17-20
- 8 aggregation switches (a00-a31), dpid 3-16
- 8 edge switches (e00-e31), dpid 1-8
- 16 servers (h0-h15)
- Link bandwidth: 15 Mbps, latency: 5 ms
- Total links: 48




Clean up if something goes wrong:
    sudo mn -c

