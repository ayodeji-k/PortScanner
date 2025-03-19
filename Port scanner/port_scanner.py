#!/usr/bin/env python3
import argparse
import socket
import threading
from queue import Queue, Empty
from datetime import datetime
import sys
from typing import Optional, List, Dict
from scanner_utils import (
    validate_target,
    parse_port_range,
    get_common_ports,
    SERVICE_MAP,
    scan_port,
    ScanResult
)
from logger import Logger

class PortScanner:
    def __init__(self, target: str, ports: List[int], num_threads: int = 10):
        self.target = target
        self.ports = ports
        self.num_threads = min(num_threads, len(ports))  # Prevent excess threads
        self.queue = Queue()
        self.results: List[ScanResult] = []
        self.lock = threading.Lock()
        self.logger = Logger()

    def worker(self):
        while True:
            try:
                port = self.queue.get_nowait()
            except Empty:
                break

            result = scan_port(self.target, port)
            if result:
                with self.lock:
                    self.results.append(result)
            self.queue.task_done()

    def run_scan(self) -> List[ScanResult]:
        start_time = datetime.now()
        self.logger.log(f"Starting scan of {self.target} at {start_time}")

        # Fill queue with ports
        for port in self.ports:
            self.queue.put(port)

        # Create and start threads
        threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for all threads to complete
        for t in threads:
            t.join()

        end_time = datetime.now()
        duration = end_time - start_time
        self.logger.log(f"Scan completed in {duration}")
        
        return sorted(self.results, key=lambda x: x.port)

def main():
    parser = argparse.ArgumentParser(description='Multi-threaded Port Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 20-1000)')
    parser.add_argument('--common-ports', action='store_true', help='Scan common ports')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--output', help='Output file for results')

    args = parser.parse_args()

    try:
        target = validate_target(args.target)
        
        if args.common_ports:
            ports = get_common_ports()
        else:
            ports = parse_port_range(args.ports or "1-1024")

        scanner = PortScanner(target, ports, args.threads)
        results = scanner.run_scan()

        # Print results
        print(f"\nScan Results for {target}")
        print("-" * 60)
        for result in results:
            print(f"Port {result.port}: {result.service} "
                  f"(Response time: {result.response_time:.3f}s)")
        
        print(f"\nFound {len(results)} open ports")

        if args.output:
            scanner.logger.save_to_file(args.output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 