
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing


topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):
    # You can automate some tests here

    # TODO: How to get the hosts from the net??
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    sw1 = net.get('sw1')
    sw2  = net.get('sw2')
    sw3 = net.get('sw3')
    sw4  = net.get('sw4')
    fw1 = net.get('fw1')
    fw2 = net.get('fw2')
    ws1  = net.get('ws1')
    ws2  = net.get('ws2')
    ws3 = net.get('ws3')
    napt = net.get('napt')
    lb = net.get('lb1')
    ids = net.get('ids')
    insp = net.get('insp')



    #Launch some tests
    print(f"-----ping test------")
    print(f"-----h1------")
    testing.ping(h1, h2, True)
    testing.ping(h1, h3, False)
    testing.ping(h1, h4, False)
    print(f"-----h1------")
    testing.ping(h2, h1, True)
    testing.ping(h2, h3, False)
    testing.ping(h2, h4, False)
    print(f"-----h3------")
    testing.ping(h3, h1, True)
    testing.ping(h3, h2, True)
    testing.ping(h3, h4, True)
    print(f"-----h4------")
    testing.ping(h4, h1, True)
    testing.ping(h4, h2, True)
    testing.ping(h4, h3, True)
    print("\n")
    print(f"-----webserver------")

    print(f"-----ws1------")
    testing.ping(h1, ws1, False)
    testing.ping(h2, ws1, False)
    testing.ping(h3, ws1, False)
    testing.ping(h4, ws1, False)
    print(f"-----ws2------")
    testing.ping(h1, ws2, False)
    testing.ping(h2, ws2, False)
    testing.ping(h3, ws2, False)
    testing.ping(h4, ws2, False)
    print(f"-----ws3------")
    testing.ping(h1, ws3, False)
    testing.ping(h2, ws3, False)
    testing.ping(h3, ws3, False)
    testing.ping(h4, ws3, False)
    print("\n")

    print(f"------ping virtual IP------")
    testing.ping_virtual(h1, True)
    testing.ping_virtual(h2, True)
    testing.ping_virtual(h3, True)
    testing.ping_virtual(h4, True)
    print("\n")

    # print(f"-----curl test------")
    # testing.curl(h1, ws1, expected=200)
    # testing.curl(h1, ws2, expected=200)
    # testing.curl(h1, ws3, expected=200)
    # testing.curl(h2, ws1, expected=200)
    # testing.curl(h2, ws2, expected=200)
    # testing.curl(h2, ws3, expected=200)
    # testing.curl(h3, ws1, expected=200)
    # testing.curl(h3, ws2, expected=200)
    # testing.curl(h3, ws3, expected=200)
    # testing.curl(h4, ws1, expected=200)
    # testing.curl(h4, ws2, expected=200)
    # testing.curl(h4, ws3, expected=200)
    # print("\n")

    print("-----HTTP method Test-----")
    testing.http_test(h3, "GET", False)
    testing.http_test(h3, "POST", True)
    testing.http_test(h3, "HEAD", False)
    testing.http_test(h3, "OPTIONS", False)
    testing.http_test(h3, "TRACE", False)
    testing.http_test(h3, "PUT", True)
    testing.http_test(h3, "DELETE", False)
    testing.http_test(h3, "CONNECT",  False)
    print("\n")

    print("-----Linux and SQL code injection Test-----")
    testing.keyword_test(h3, "cat /etc/passwd", False)
    testing.keyword_test(h3, "cat /var/log/", False)
    testing.keyword_test(h3, "INSERT", False)
    testing.keyword_test(h3, "UPDATE", False)
    testing.keyword_test(h3, "DELETE", False)
    print("\n")
if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)
    
    net.get("h3").cmd("ip route add default via 10.0.0.1 dev h3-eth0")
    net.get("h4").cmd("ip route add default via 10.0.0.1 dev h4-eth0")
    net.get("ws1").cmd("ip route add default via 100.0.0.45 dev ws1-eth0")
    net.get("ws2").cmd("ip route add default via 100.0.0.45 dev ws2-eth0")
    net.get("ws3").cmd("ip route add default via 100.0.0.45 dev ws3-eth0")

    # Start the network
    net.start()
    for ws in ["ws1", "ws2", "ws3"]:
        print("Starting web server %s on port 80" % ws.upper()) 
        server = net.get(ws)
        server.cmd("python3 -m http.server 80 &")
    for insp in ["insp"]:
        print( "tcpdump on insp start")
        net.get(insp).cmd("tcpdump -i insp-eth0 -w insp.pcap &")



    run_tests(net)

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###
    for link in net.links:
        net.delLink(link)
        
    net.stop()
