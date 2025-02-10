# Networking test
# As the RNDIS way of working does not allow any external device to "send the first hello", it needs to act as a webserver.
# Other things such as receiving / sending ethernet frames are not possible to test this far (because of, again, RNDIS).
# Covering:
#   -> ICMP
#   -> UDP
#   -> DNS
#   -> TCP
#   -> HTTP
# Again, it only tests that the InternetCE library handles tricky cases correctly.
# Test results are sent via an TCP link between the webserver and the calculator.
#
# Timeline:
#   -> Calculator sends a TCP SYN packet to port 8080, indicating its IP address.
#   -> Repeat:
#       -> Webserver sends the test case number through TCP to port 0x1111
#       -> The calculator does what the test case wants
#       -> Webserver responds to the calculator requests according to the test case
#       -> Once the calculator has finished, it sends data to the webserver through TCP to port 8080
#   -> Repeat until there is no more test to run
#   -> Webserver sends an TCP "stop" packet to port 8080

from typing import List
from scapy.all import Ether, UDP, IP, TCP, ICMP, send, sniff
import re
import sys

# Constants
WS_STATE_LISTEN = 1
WS_STATE_STARTING = 2
WS_STATE_TESTING = 3
WS_STATE_WAIT_TEST_RESULT = 4
WS_STATE_RECEIVED_TEST_RESULT = 5
WS_STATE_CLOSING = 6

ASSERT_IN_ORDER = 1
ASSERT_LIST = 2
ASSERT_ONE = 3


# TODO tester cette première version en local
# malheureusement j'ai l'impression que comme le port d'écoute n'est pas vraiment ouvert les packets n'arrivent pas jusque là
# On peut l'ouvrir manuellement avec socket et envoyer du scapy par dessus peut-être ?

class TestContext():
    '''
        Context class for all networking tests.
        Some methods are wrappers of scapy's (in case I choose to change the library)
    '''
    ws_state = WS_STATE_LISTEN
    server_ip = "127.0.0.1"
    server_port = 80  # For HTTP, InternetCE does not allow other IPs yet
    src_ctrl_port = 8080

    def __init__(self):
        ''''''
        all_test_classes = [TestICMPLayer]
        self.all_test_cases = {}
        for test_class in all_test_classes:
            self.all_test_cases[test_class] = []
            for inspected_attr in dir(test_class):
                if callable(getattr(test_class, inspected_attr)) and inspected_attr.startswith("test_"):
                    self.all_test_cases[test_class].append(inspected_attr)

    def control_link_handler(self, datagram):
        '''Fetch incoming control messages'''
        # Precondition: This is an TCP datagram sent to the webserver (see filter)
        if self.ws_state == WS_STATE_LISTEN and datagram[TCP].flags == "S":
            self.calc_ip = datagram[IP].src
            self.dst_ctrl_port = datagram[TCP].sport
            print(f"Device at {self.calc_ip}:{self.dst_ctrl_port}")
            self.ws_state = WS_STATE_STARTING
        elif self.ws_state == WS_STATE_WAIT_TEST_RESULT and datagram[TCP].payload.startswith("result:"):
            self.test_result = datagram[TCP].payload[len("result:"):]
            self.ws_state = WS_STATE_RECEIVED_TEST_RESULT
        else:
            print("Invalid control message:")
            print(datagram)

    def assert_one(self, logs: List[str], search: str) -> bool:
        for idx, log in enumerate(logs):
            if re.search(pattern=search, string=log) is not None:
                print(f"\t\tFound \"{search}\" -> \"{log}\"")
                return (True, logs[idx:])
        print(f"\t\tNOT FOUND: \"{search}\"")
        return (False, logs)

    def fetch_test_result(self, expected):
        ''''''
        self.ws_state = WS_STATE_WAIT_TEST_RESULT
        while self.ws_state == WS_STATE_WAIT_TEST_RESULT:
            self.receive_control_msg()
        
        logs = self.test_result.decode("ascii").split(b'\x00')
        is_ok = True
        for assert_type, assert_logs in expected:
            if assert_type == ASSERT_IN_ORDER:
                print("\tAssert in order:")
                current_logs = logs
                for assert_log in assert_logs:
                    current_logs, is_tmp_ok = self.assert_one(current_logs, assert_log)
                    is_ok &= is_tmp_ok
            elif assert_type == ASSERT_LIST:
                print("\tAssert list:")
                for assert_log in assert_logs:
                    is_ok &= self.assert_one(logs, assert_log)[0]
            elif assert_type == ASSERT_ONE:
                print("\tAssert one:")
                is_ok &= self.assert_one(logs, assert_logs)[0]
        if not is_ok:
            print("\tA log was not found for the current test")

    def run_tests(self, tests_name):
        '''Run every test in tests_name
        @param tests_name  [str] Contains the name of the test to run, or '*' to run all tests'''
        # Step 1: Wait for "start" message
        print("Waiting for the device start... ", end="")
        while self.ws_state == WS_STATE_LISTEN:
            self.receive_control_msg()
        print("Done!")

        # Step 2: Run tests
        for test_class, test_cases in self.all_test_cases.items():
            for test_name in tests_name:
                if test_name in test_cases:
                    # Step 2.1: Send test case to the calculator
                    self.ws_state = WS_STATE_TESTING
                    self.send_control_msg(payload=f"tc:{test_name}")

                    # Step 2.2: Run the scenario
                    print(f"{test_name}: ", end="")
                    try:
                        class_object = test_class()
                        expected_test_result = getattr(class_object, test_name)(test_context=self)
                        print("OK")
                    except AssertionError:
                        print("KO")

                    # Step 2.3: Get & check the test result
                    self.fetch_test_result(expected=expected_test_result)
        
        # Step 3: Send a "close" message to the calculator
        self.ws_state = WS_STATE_CLOSING
        self.send_control_msg(payload="close")

    def send(self, **kwargs):
        '''Send something to the device'''
        send(**kwargs)

    def send_control_msg(self, payload):
        ''''''
        self.send(x=IP(src=self.server_ip, dst=self.calc_ip) / TCP(sport=self.src_ctrl_port, dport=self.dst_ctrl_port) / payload)

    def receive(self, filter=None, timeout=10, count=1, **kwargs):
        '''Receive something from the device'''
        default_filter = f"src {self.server_ip} and src port {self.server_port}"
        all_filter = f"{default_filter} and {filter}" if filter is not None else default_filter
        response = sniff(filter=all_filter, timeout=timeout, count=count, **kwargs)
        return response[0] if response is not None else None
    
    def receive_control_msg(self):
        ''''''
        sniff(count=1,
              timeout=10,
              filter=f"tcp and src {self.server_ip} and src port {self.src_ctrl_port}",
              prn=self.control_link_handler)


class TestCommon():
    '''Common test class for all tests'''

    def __init__(self, test_context):
        super()
        self.test_context = test_context


class TestICMPLayer(TestCommon):
    ''''''

    def test_icmp_nominal(self, test_context : TestContext):
        ''''''
        packet = test_context.receive(filter="icmp")
        assert packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet[ICMP].code == 0
        reply = IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq) / packet[ICMP].payload
        test_context.send(reply)
        return [(ASSERT_ONE, r"I: Received ping reply from 0xc0a8[0-9a-f]{4}")]


def main():
    if len(sys.argv) == 1:
        tests = "*"
    else:
        tests = sys.argv[1:]
    test_context = TestContext()
    test_context.run_tests(tests_name=tests)

if __name__ == "__main__":
    main()
