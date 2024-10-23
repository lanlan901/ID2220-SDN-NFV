import topology


# def ping(client, server, expected, count=1, wait=1):

#     # TODO: What if ping fails? How long does it take? Add a timeout to the command!
#     cmd = f"ping {server} -c {count}  >/dev/null 2>&1; echo $?"
#     ret = client.cmd(cmd)
#     # TODO: Here you should compare the return value "ret" with the expected value
#     # (consider both failures
#     return True  # True means "everyhing went as expected"/
def ping(client, server, expected, count=1, wait=1,timeout=3):
    """
    Executes a ping command from a client to a server, while capturing packets on the specified interface.

    :param client: The client host from which the ping is sent.
    :param server: The target host to be pinged.
    :param interface: Network interface on which to capture packets.
    :param expected: Expected boolean result (True if expecting success, False otherwise).
    :param count: Number of ICMP packets to send.
    :param wait: Time in seconds to wait between packets.
    :param timeout: Total time in seconds to allow the ping command to run.
    :param pcap_file: Filename to save the captured packets.
    :return: True if the actual result matches the expected result, False otherwise.
    """
    # Build the tcpdump command to capture ICMP packets related to the ping
    # capture_cmd = f"tcpdump -i {interface} icmp and host {server} -w {pcap_file} &"
    # client.cmd(capture_cmd)

    # Build the ping command with timeout
    ping_cmd = f"ping -c {count} -W {wait} -w {timeout} {server.IP()} >/dev/null 2>&1; echo $?"
    

    # Execute the ping command
    ret = client.cmd(ping_cmd).strip()

    # Return True if the outcome matches what was expected, False otherwise
    success = (ret == "0" and expected) or (ret != "0" and not expected)
    if success:
        print(f"{client.name} ping to {server.name}: Expected {expected}, Result: Success")
        print("\n")
    else:
        print(f"{client.name} ping to {server.name}: Expected {expected}, Result: Failure")
        print("\n")

    return success

    
def curl(client, server, method="GET", payload="test", port=80, expected=200):
    """
    Run curl for HTTP request. Request method and payload should be specified.
    Server can either be a host or a string.
    Return True in case of success, False if not.
    """
    if isinstance(server, str):
        server_ip = server
    else:
        server_ip = server.IP()

    # Build curl command with HTTP method, data payload, and output format for HTTP status code
    cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -X {method} -d '{payload}' http://{server_ip}:{port}"
    ret = client.cmd(cmd).strip()

    # Compare the returned HTTP status code with the expected status code
    if int(ret) == expected:
        print(f"{client.name} curl to {server_ip}:{port}: Expected HTTP {expected}, Result: Success")
        return True
    else:
        print(f"{client.name} curl to {server_ip}:{port}: Expected HTTP {expected}, Result: Failure, Received: {ret}")
        return False


def ping_virtual(client, expected, count=5, wait=1):
    cmd = f"ping 100.0.0.45 -c {count} -W {wait} >/dev/null 2>&1; echo $?"
    ret = client.cmd(cmd)
    success = (int(ret) == 0 and expected) or (int(ret) !=0 and expected == False)
    if success:
        print(f"{client.name} ping to 100.0.0.45: Expected {expected}, Result: Success")
        print("\n")
    else:
        print(f"{client.name} ping to 100.0.0.45: Expected {expected}, Result: Failure")
        print("\n")

def http_test(client, method, expected):
    cmd = f"curl --connect-timeout 3 --max-time 3 -X {method} -s 100.0.0.45 > /dev/null 2>&1; echo $? "
    ret = client.cmd(cmd).strip()
    if ret == "0" and expected == True or (int(ret) !=0 and expected == False):
        print(client.name, "HTTP method:", method, f", Expected {expected}, Result: Success")
        return True
    else:
        print(client.name, "HTTP method:", method, f", Expected {expected}, Result: Failure")
        return False
    
def keyword_test(client, payload, expected):

    cmd = f"curl --connect-timeout 3 --max-time 3 -X PUT -d '{payload}' -s 100.0.0.45/put > /dev/null 2>&1; echo $? "

    ret = client.cmd(cmd).strip()
    if (int(ret) !=0 and expected == False):
        print(client.name,f"keyword found {payload}, expected {expected}, Result: Success")
        return True
    else:
        print(client.name,f"Linux and SQL injection detection failure")
        return False    