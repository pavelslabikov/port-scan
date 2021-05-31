import argparse

from port_scan.portchecker import PortChecker


def prepare_args():
    arg_parser.add_argument('host', default='127.0.0.1', type=str)
    arg_parser.add_argument('-u', action='store_true', dest='udp')
    arg_parser.add_argument('-t', action='store_true', dest='tcp')
    arg_parser.add_argument('-p', '--ports', nargs='+', dest='ports')


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    prepare_args()
    args = arg_parser.parse_args()
    checker = PortChecker(args.host, args.udp, args.tcp, args.ports)
    checker.start_scanning()
