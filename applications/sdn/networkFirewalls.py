from baseFirewall import Firewall


# Here we implement our network firewalls. All network firewalls are inherited from Firewall class.

# Rules parameters are:
# index 0: Determines the hardware port of the incoming packet.
# index 1: Determines the TCP layer protocol. (possible values: TCP, UDP, any)
# index 2: Determine the source IP address of the incoming packet. It should be either "any" or a subnet with "IP/Subnet" format (e.g, 100.0.0.40/32).
# index 3: Determine the TCP layer source port number of the incoming packet. (possible values: any, an integer as the port number)
# index 4: Determine the destination IP address of the incoming packet. Same format as the source IP.
# index 5: Determine the TCP layer destination port number of the incoming packet. Same format as the source port.
# index 6: To allow or block the matched packet. (possible values: allow, block)

# Note that the Firewall trace the rules from 0 to n and make the decision based on first matched rule.

# Hardware ports:
# public-zone --------- 1 FW1 2 ------------ DmZ
# DmZ ----------------- 1 FW2 2 ------------ private-zone

class FW1 (Firewall):

    def __init__(self, connection):

        """
        Initialize Firewall class and set rules!
        The following is just a sample to give you the idea.
        """

        ### COMPLETE THIS PART ###
        ##[硬件端口号；协议；源ip；TCP/UDP源端口号；目的ip；TCP/UDP目的端口号；允许或禁止]
        Firewall.__init__(self, connection, "FW1")
        self.rules = [
            #webserver - pbz
            [1, 'TCP', 'any', 'any', '100.0.0.45', '80', 'allow'], 
            [1, 'ICMP', 'any', 'any', '100.0.0.45', 'any', 'allow'], 
            [1, 'any', 'any', 'any', '100.0.0.45', 'any', 'block'], 
            [1, 'any', 'any', 'any', 'any', 'any', 'allow'], 
              
            [2, 'any', 'any', 'any', 'any', 'any', 'allow']
        ]


class FW2 (Firewall):
    def __init__(self, connection):

        """
        Initialize Firewall class and set rules!
        The following is just a sample to give you the idea.
        """

        ### COMPLETE THIS PART ###
        ##[硬件端口号；协议；源ip；TCP/UDP源端口号；目的ip；TCP/UDP目的端口号；允许或禁止]
        Firewall.__init__(self, connection, "FW2", True)
        self.rules = [
            ## prz - webserver
            [2, 'TCP', 'any', 'any', '100.0.0.45', '80', 'allow'], 
            [2, 'ICMP', 'any', 'any', '100.0.0.45', 'any', 'allow'], 
            [2, 'any', 'any', 'any', '100.0.0.45', 'any', 'block'], 
            [2, 'any', 'any', 'any', 'any', 'any', 'allow'],

            [1, 'TCP', '100.0.0.45', 'any', 'any', 'any', 'allow'],
            [1, 'any', 'any', 'any', 'any', 'any', 'block']

            
        ]
