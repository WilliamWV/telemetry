# In-Band Telemetry

The objective of this project is to implement the class project of 
Protocolos de Comunicação - UFRGS whose definition is on 
`Trabalho Extra-Classe v2.pdf` 

To a simple test follow:

1) Open two terminals in the directory of this project
2) On the first terminal execute 'make', this will set the network structure
3) On the second terminal execute './controller.py', this will install rules on switch tables
4) On the second terminal execute 'simple_switch_CLI' this will open a command line interface to interact with the switchs
5) Use this command line interface to create mirroring sessions that are used to direct a cloned packet to some egress port, type the commands 'mirroring_add 3 3', 'mirriring_add 4 3', 'mirriring_add 5 3', this creates three sections identified by the ids 3, 4 and 5
and direct all of the cloned packets of these sections to the egress port 3 of its switches (the port being 3 was a coincidence for this network)
6) Back on the first terminal type xterm h99
7) On the opened terminal for h99 execute './stat.py', this will start the execution of the statistical controller
8) Execute 'h1 ping h2' on the first terminal

The statistical controller may capture the packets and display a congestion report


The code is based on the MRI excercise from p4lang repository:
`https://github.com/p4lang/tutorials/tree/master/exercises/mri`