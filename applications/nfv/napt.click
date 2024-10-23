define($PORT1 napt-eth1, $PORT2 napt-eth2)
define($PRZ_IP 10.0.0.1)
define($DMZ_IP 100.0.0.1)

// counters
cnt_in1, cnt_in2, cnt_out1, cnt_out2 :: AverageCounter; 
arp_req1, arp_req2, arp_res1, arp_res2 :: Counter;
cnt_tcp1, cnt_tcp2, cnt_icmp1, cnt_icmp2, cnt_icmp3 :: Counter;
drop1, drop2, drop3, drop4 :: Counter;

// interfaces
from_prz :: FromDevice($PORT2, METHOD LINUX, SNIFFER false);
from_dmz :: FromDevice($PORT1, METHOD LINUX, SNIFFER false);
to_prz :: Queue -> Print("napt: prz-out", -1) -> cnt_out1 -> ToDevice($PORT2);
to_dmz :: Queue -> Print("napt: dmz-out", -1) -> cnt_out2 -> ToDevice($PORT1);

//ARP
arp_req_prz :: ARPQuerier($PRZ_IP, 11:22:33:11:22:33);
arp_req_dmz :: ARPQuerier($DMZ_IP, 44:55:66:44:55:66);
arp_res_prz :: ARPResponder($PRZ_IP 10.0.0.0/24 11:22:33:11:22:33);
arp_res_dmz :: ARPResponder($DMZ_IP 100.0.0.0/24 44:55:66:44:55:66);

// IP rewrite
ip_rw :: IPRewriter(pattern $DMZ_IP - - - 0 1);
icmp_rw :: ICMPPingRewriter(pattern $DMZ_IP - - - 0 1);

packet_classifier_prz :: Classifier(
    12/0806 20/0001, // ARP request
    12/0806 20/0002, // ARP reply
    12/0800, // IP
    -
);

packet_classifier_dmz :: Classifier(
    12/0806 20/0001, // ARP request
    12/0806 20/0002, // ARP reply
    12/0800, // IP
    - 
);

ip_classifier_prz :: IPClassifier(
    tcp,
    icmp type 0, //ICMP response
    icmp type 8,
    -
);

ip_classifier_dmz :: IPClassifier(
    tcp,
    icmp type 0,
    icmp type 8,
    -
);

from_prz -> cnt_in1 -> packet_classifier_prz;
from_dmz -> cnt_in2 -> packet_classifier_dmz;

packet_classifier_prz[0] -> Print("napt-prz: ARP request", -1) -> arp_req1 -> arp_res_prz -> to_prz;
packet_classifier_prz[1] -> Print("napt-prz: ARP response", -1) -> arp_res1 -> [1]arp_req_prz;
packet_classifier_prz[2] -> Print("napt-prz: IP packet", -1) -> Strip(14) -> CheckIPHeader -> ip_classifier_prz;
packet_classifier_prz[3] -> drop1 -> Discard;

packet_classifier_dmz[0] -> Print("napt-dmz: ARP request", -1) -> arp_req2 -> arp_res_dmz -> to_dmz;
packet_classifier_dmz[1] -> Print("napt-dmz: ARP response", -1) -> arp_res2 -> [1]arp_req_dmz;
packet_classifier_dmz[2] -> Print("IP packet") -> Strip(14) -> CheckIPHeader -> ip_classifier_dmz;
packet_classifier_dmz[3] -> drop2 -> Discard;

// prz -> dmz
ip_classifier_prz[0] -> Print("napt: TCP", -1) -> cnt_tcp1 -> ip_rw[0] -> [0]arp_req_dmz -> to_dmz;
ip_classifier_prz[1] -> Print("napt: ICMP response from prz to dmz", -1) -> Discard;
ip_classifier_prz[2] -> cnt_icmp1 -> Print("napt: ICMP request", -1) -> icmp_rw[0] -> Print("ICMP rewrite", -1) -> [0]arp_req_dmz -> to_dmz;
ip_classifier_prz[3] -> drop3 -> Discard;

// dmz -> prz
ip_classifier_dmz[0] -> Print("napt: TCP", -1) -> cnt_tcp2 -> ip_rw[1] -> [0]arp_req_prz -> to_prz;
ip_classifier_dmz[1] -> cnt_icmp2 -> Print("napt: ICMP response from dmz to prz", -1) -> icmp_rw[1] -> [0]arp_req_prz -> to_prz;
ip_classifier_dmz[2] -> cnt_icmp3 -> Print("napt: ICMP request from dmz to prz", -1) -> ICMPPingResponder -> [0]arp_req_dmz -> to_dmz;
ip_classifier_dmz[3] -> drop4 -> Discard;

DriverManager(
    wait, 
    print > /opt/pox/ext/results/napt.report  "
     =================== NAPT Report ===================
      Input Packet rate (pps): $(add $(cnt_in1.rate) $(cnt_in2.rate))
      Output Packet rate (pps): $(add $(cnt_out1.rate) $(cnt_out2.rate))

      Total # of   input packets: $(add $(cnt_in1.count) $(cnt_in2.count))
      Total # of  output packets: $(add $(cnt_out1.count) $(cnt_out2.count))
   
      Total # of   ARP  requests: $(add $(arp_req1.count) $(arp_req2.count))
      Total # of   ARP responses: $(add $(arp_res1.count) $(arp_res2.count))

      Total # of     TCP packets: $(add $(cnt_tcp1.count) $(cnt_tcp2.count))
      Total # of    ICMP packets: $(add $(cnt_icmp1.count) $(cnt_icmp2.count)$(cnt_icmp3.count))   
      Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count) $(drop4.count) )   
     =================================================
    " 
, stop);
