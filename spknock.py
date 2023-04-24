#!/bin/python3
import socket

from getpass import getpass
from hashlib import sha256
from time import sleep
from os import mkdir
from os.path import exists, expanduser

class Port(object):
    """ Represents a single port to be knocked on """

    def __init__(self, number : int, protocol : str) -> None:
        self.__number = number
        self.__protocol = protocol
    
    @property
    def number(self):
        return self.__number
    
    @property
    def protocol(self):
        return self.__protocol


class Target(object):
    """ Represents a host and the ports to be knocked on """

    def __init__(self, host : str, ports : list) -> None:
        self.__host = host
        self.__ports = ports

    @property
    def host(self):
        return self.__host
    
    @property
    def ports(self):
        return self.__ports

    def knock(self) -> None:
        """ Perform the port knock sequence """

        for port in self.ports:
            # Setup UDP socket and send datagram to firewall
            if port.protocol == 'udp':
                # Enter passphrase to be hashed
                passwd = getpass(f" Enter passphrase ({port.number}/{port.protocol}): ")
                hash = sha256(passwd.encode()).hexdigest()
                udp = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                udp.sendto(str.encode(hash), (self.host, port.number))
            # Setup TCP socket and send segment to firewall
            elif port.protocol == 'tcp':
                tcp = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
                tcp.settimeout(0.25)
                tcp.connect_ex((self.host, port.number))
                tcp.close()

def parse_target(input : str) -> Target:
    """ Parse a line read from the saved target file """

    # input = 'host.example.com:123/udp,234/udp,345/udp'

    # Remove all white space characters inside the string
    input = "".join(input.split())

    # Ignore comments and empty lines
    if input.startswith('#') or len(input) == 0:
        return None

    # Split string into a host and a target ports portion
    data = input.split(sep=':')
    if len(data) == 2:
        host = data[0]      # 'host.example.com'
        ports = data[1]     # '123/udp,234/udp,345/udp'

        port_list = list()

        # Split the ports into a list
        for port_proto in ports.split(sep=','):
            port_data = port_proto.split(sep='/')
            
            # Make sure the input is valid
            try:
                port = int(port_data[0])
    
                # Check that port number is valid
                if not (port > 0 and port < 65536):
                    raise ValueError

                # Use 'udp' if explicitly set, otherwise default to 'tcp'
                proto = 'udp' if len(port_data) == 2 and port_data[1] == 'udp' else 'tcp'
                new_port = Port(number=port, protocol=proto)

                port_list.append(new_port)
            except ValueError:
                print(f" * Parse error: Invalid port number '{port_data[0]}' in line '{input}'.")

        # Return a Target object when parsing is complete
        return Target(host, port_list)
    else:
        print(f" * Parse error: Unable to parse line '{input}'.")
        return None

def load_targets(target_file : str) -> list:
    """ Load targets stored in file """
    target_list = list()

    # Read targets from file and store in target_list
    with open(target_file) as targets:
        for line in targets.readlines():
            target = parse_target(line)
            if target: target_list.append(target)
    
    return target_list

def save_target(target : Target, filename : str) -> None:
    """ Save a target to file in the format """
    ports = str()

    # Enumerate the ports/protocols inside a string object
    for port in target.ports:
        ports += f"{port.number}/{port.protocol},"

    # Writing data to a file
    with open(filename, "a") as out_file:
        out_file.write(f"{target.host}:{ports.rstrip(',')}\n")

def input_host(text : str) -> str:
    """ Read hostname or IP address from terminal """
    while True:
        value = input(text).strip()
        if len(value) > 1: 
            return value
        else:
            print(" * Enter a hostname or an IPv4 address.")

def input_port(text : str) -> int:
    """ Read port number from terminal """
    while True:
        try:
            value = int(input(text).strip())
            if value > 0 and value < 65536:
                return value
            else:
                raise ValueError
        except ValueError:
            print(" * Enter a port number between 1-65535.")

def input_protocol(text : str) -> str:
    """ Read layer 4 protocol from terminal """
    while True:
        try:
            value = input(text).strip().lower()
            if value == 'tcp' or value == 'udp':
                return value
            else:
                raise ValueError
        except ValueError:
            print(" * Enter layer 4 protocol to use: 'tcp' or 'udp'.")

def input_count(text : str) -> str:
    """ Read number of port knocks to perform from terminal """
    while True:
        try:
            value = int(input(text).strip())
            if value > 0 and value < 10:
                return value
            else:
                raise ValueError
        except ValueError:
            print(" * Enter number of ports to knock on (1-9).")

def main():

    target_dir  = expanduser('~/.secrets/')
    target_file = 'spknock-targets.conf'
    target_path = target_dir + target_file

    # Make sure ~/.secrets/ directory exists
    if not exists(target_dir):
        mkdir(target_dir)

    targets = []

    print(f"----------------------------------------")
    print(f"          Secret Port Knocker")
    print(f"----------------------------------------")

    if exists(target_path):
        targets = load_targets(target_path)
        print(f" Loaded {len(targets)} port knock target{'s' if len(targets) > 1 else ''} from file.")
    print()

    while True:
        count = 1
        if len(targets) > 0:
            print(f" Select existing target:")
            print(f" -----------------------")
        for target in targets:
            print(f" [{count}] Knock on {target.host}")
            count += 1
        print()
        print(f" Select option:")
        print(f" -----------------------")
        print(f" [A] Add new target")
        print(f" [H] Generate SHA256 hash")
        print(f" [X] Exit")
        print()
        try:
            action = input(" Choice: ").upper()
        except KeyboardInterrupt:
            print()
            return
        print()

        if action == 'X':
            print("Bye bye...")
            break
        elif action == 'A':
            print("Add new target host")
            print("-------------------")
            port_list = list()
            host  = input_host (" Hostname or IP     : ")
            count = input_count(" Knock count (1-9)  : ")
            for index in range(1, count+1):
                port  = input_port    (f" Port number {index}      : ")
                proto = input_protocol(f" Protocol (tcp/udp) : ")
                new_port = Port(port, proto)
                port_list.append(new_port)
            target = Target(host, port_list)
            targets.append(target)
    
            # Save the new target host to file
            save_target(target, target_path)
            print()
            print(f"Target added and saved to file: {target_path}")
            print()
            input('Press <Enter> to continue...')
            print()

            continue
        elif action == 'H':
            print("Generate SHA256 hash")
            print("--------------------")
            passwd = getpass(" Enter passphrase: ")
            hash = sha256(passwd.encode()).hexdigest()
            print(f" Hash: {hash}")
            print()
            input('Press <Enter> to continue...')
            print()
            continue
        
        try:
            action = int(action)
            if not action in range(1, count):
                raise ValueError()
            
            targets[action-1].knock()
            print()
            print("Port knock sequence completed.")
            print()
            return 0

        except ValueError:
            print("Invalid selection!")

if __name__ == "__main__":
    main()
