// Load Balancer: 
// 1. ARP request: generate ARP reply from ARPResponder
// 2. ARP response: ARPQuerier
// 3. IP packets: load balancing
// 4. others: discard

define($PORT1 lb1-eth1, $PORT2 lb1-eth2)
define($VIRTUAL_SERVICE_IP 100.0.0.45)
define($VIRTUAL_MAC)

// counters
cnt_in1, cnt_in2, cnt_out1, cnt_out2 :: AverageCounter; 
arp_req1, arp_req2, arp_res1, arp_res2 :: Counter;
cnt_serv1, cnt_serv2, cnt_icmp1, cnt_icmp2 :: Counter;
drop1, drop2, drop3, drop4 :: Counter;

// interfaces
from_ids :: FromDevice($PORT2, METHOD LINUX, SNIFFER false);
from_ws :: FromDevice($PORT1, METHOD LINUX, SNIFFER false);
to_ws :: Queue -> cnt_out1 -> Print("lb: out to ws", -1) -> ToDevice($PORT1, METHOD LINUX);
to_ids :: Queue -> cnt_out2 -> Print("lb: out to ids", -1) -> ToDevice($PORT2, METHOD LINUX);


// classifier
classifier_from_ws :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, - );
classifier_from_ids :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

// IP classifier
ip_classifier_from_ids :: IPClassifier(
    tcp dst port 80 and dst ip $VIRTUAL_SERVICE_IP, //TCP
    icmp and dst ip $VIRTUAL_SERVICE_IP,  //ICMP
    -);

ip_classifier_from_ws :: IPClassifier(
    tcp and src port 80,
    icmp type echo and dst $VIRTUAL_SERVICE_IP,  //ICMP to lb
    -);

// IP rewrite
ipRewrite :: IPRewriter (roundRobin);

roundRobin :: RoundRobinIPMapper(
    100.0.0.45 - 100.0.0.40 - 0 1,
    100.0.0.45 - 100.0.0.41 - 0 1,
    100.0.0.45 - 100.0.0.42 - 0 1);

arp_req_ids :: ARPQuerier($VIRTUAL_SERVICE_IP, 12:34:56:12:34:56);
arp_req_ws :: ARPQuerier($VIRTUAL_SERVICE_IP, 65:43:21:65:43:21);
arp_res_ids :: ARPResponder($VIRTUAL_SERVICE_IP 12:34:56:12:34:56);
arp_res_ws :: ARPResponder($VIRTUAL_SERVICE_IP 65:43:21:65:43:21);

to_ws_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp_req_ws -> to_ws;
to_ids_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp_req_ids -> to_ids;

ipRewrite[0] -> to_ws_queue;
ipRewrite[1] -> to_ids_queue;

//from ids

from_ids -> Print("packet from client", -1) -> cnt_in1 -> classifier_from_ids

classifier_from_ids[0] -> Print("lb: get ARP request", -1) -> arp_req2 -> arp_res_ids -> to_ids;
classifier_from_ids[1] -> arp_res2 -> [1]arp_req_ids;
classifier_from_ids[2] -> cnt_serv2 -> Strip(14) -> CheckIPHeader -> ip_classifier_from_ids;
classifier_from_ids[3] -> drop2 -> Discard;

ip_classifier_from_ids[0] -> [0]ipRewrite;
ip_classifier_from_ids[1] -> cnt_icmp2 -> Print("lb: get ICMP request", -1) -> ICMPPingResponder -> to_ids_queue;
ip_classifier_from_ids[2] -> drop4 -> Discard;

//from server
from_ws -> Print("packet from server", -1) -> cnt_in2 -> classifier_from_ws;

classifier_from_ws[0] -> arp_req1 -> arp_res_ws -> to_ws;
classifier_from_ws[1] -> arp_res1 -> [1]arp_req_ws;
classifier_from_ws[2] -> cnt_serv1 -> Strip(14) -> CheckIPHeader -> ip_classifier_from_ws;
classifier_from_ws[3] -> drop1 -> Discard;

ip_classifier_from_ws[0] -> [0]ipRewrite;
ip_classifier_from_ws[1] -> cnt_icmp1 -> ICMPPingResponder -> to_ws_queue;
ip_classifier_from_ws[2] -> drop3 -> Discard;


DriverManager(
    wait, 
    print > /opt/pox/ext/results/lb1.report "
     =================== LB1 Report ===================
        Input Packet rate (pps): $(add $(cnt_in1.rate) $(cnt_in2.rate))
        Output Packet rate (pps): $(add $(cnt_out1.rate) $(cnt_out2.rate))
        
        Total # of   input packets: $(add $(cnt_in1.count) $(cnt_in2.count))
        Total # of  output packets: $(add $(cnt_out1.count) $(cnt_out2.count))
      
        Total # of   ARP  requests: $(add $(arp_req1.count) $(arp_req2.count))
        Total # of   ARP responses: $(add $(arp_res1.count) $(arp_res2.count))
      
        Total # of service packets: $(add $(cnt_serv1.count) $(cnt_serv2.count))
        Total # of    ICMP packets:  $(add $(cnt_icmp1.count) $(cnt_icmp2.count))
        Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count) $(drop4.count))  

     =================================================
     " 
, stop);