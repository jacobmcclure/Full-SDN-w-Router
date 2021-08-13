Jacob McClure
jatmcclu@ucsc.edu


Repository files and their details:


1) controller.py:
This file contains the controller I made, which implements…
The following rules for ICMP: trusted host can communicate with any of the other hosts, the untrusted host can only communicate with the trusted host, h10/h20/h30 and the server can communicate with all other hosts except for the untrusted host. 
My controller implements the following rules for TCP: all hosts can exchange TCP packets with each other; the only exception is that the *untrusted host cannot communicate with the server.*
For ARP packets, there are no restrictions (uses flooding).


2) topology.py:
This file contains the topology I built: 
h10 (port 0) connects to floor 1 switch (s1) (on port 1), which connects to the core switch (s4) (port 11 to connecting to port 7 on the core switch). 
h20 and h30 connect to the core switch analogously to how h10 connects to the core switch, but on different ports of course. 
The Trusted/Untrusted hosts (h4 and h5 respectively) are directly linked to the core switch, which allows connectivity to the other hosts (at the mercy of ICMP and TCP restrictions, of course).
The server (h6) connects to the data center switch, which connects to the core switch, thus allowing connectivity to the rest of the hosts.

USAGE:
To use this application, you will need to install a MiniNet VM and boot into it. From there, you'll
want to open the command line and store a local copy of both the controller and topology files on
the VM. Store both files in a new directory called pox/pox.py, located in ~ (so the path will be
~/pox/pox.py). Once the files are in this directory, you can run the program!
Now, go to the command line and enter: 
> sudo ~/pox/pox.py misc.controller
followed by:
> sudo python ~/topology.py

Now, you can test the firewall using basic commands such as iperf, ping, pingall, dump, etc.