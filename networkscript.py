
#used python version 3.12.7

import subprocess
import argparse
import sys
import os
import time
from datetime import datetime

class WindowsPacketCapture:
    def __init__(self):
        self.process = None
    
    def check_admin_privileges(self):
        try:
            test_file = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'temp_test.txt')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return True
        except PermissionError:
            return False
    
    def get_network_interfaces(self):
        try:
            cmd = ['powershell', '-Command', 'Get-NetAdapter | Select-Object Name, InterfaceDescription, Status']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("Available network interfaces:")
            print(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error getting interfaces: {e}")
            return False
        
    def start_netsh_capture(self, interface=None, output_file="capture.etl", max_size=100):
        if not self.check_admin_privileges():
            print("Error: Administrator privileges required for packet capture")
            print("Please run the script as Administrator")
            return False
        
        print("Stopping any existing trace sessions...")
        subprocess.run(['netsh', 'trace', 'stop'], capture_output=True)
        
        cmd = ['netsh', 'trace', 'start']
        
        if interface:
            cmd.append(f'interface={interface}')
        
        cmd.extend([
            'capture=yes',
            'persistent=yes',
            'filemode=circular',
            f'maxsize={max_size}',
            f'tracefile={output_file}'
        ])
        
        print(f"Starting netsh capture: {' '.join(cmd)}")
        print("This will capture ALL network traffic on the interface")
        print("Use Ctrl+C to stop capture")
        
        try:
            self.process = subprocess.Popen(cmd)
            print(f"Capture started. Output file: {output_file}")
            print("Press Ctrl+C to stop capture...")
            try:
                self.process.wait()
            except KeyboardInterrupt:
                self.stop_capture()
                
        except Exception as e:
            print(f"Error starting capture: {e}")
            return False
        
        return True
    
    def stop_capture(self):
        if self.process:
            print("\nStopping capture...")
            subprocess.run(['netsh', 'trace', 'stop'], capture_output=True)
            self.process = None
            print("Capture stopped.")
        else:
            subprocess.run(['netsh', 'trace', 'stop'], capture_output=True)
    
    def convert_etl_to_text(self, etl_file, output_text_file=None):
        if not output_text_file:
            output_text_file = etl_file.replace('.etl', '_converted.txt')
        
        print(f"Converting {etl_file} to text format...")
        
        try:
            cmd = ['netsh', 'trace', 'convert', etl_file]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("Conversion completed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error converting file: {e}")
            return False

def monitor_connections():
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"Active Connections - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 80)
            print("\nTCP Connections:")
            subprocess.run(['netstat', '-n', '-p', 'tcp'])
            print("\nUDP Connections:")
            subprocess.run(['netstat', '-n', '-p', 'udp'])
            print("\nPress Ctrl+C to stop monitoring...")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

def main():
    parser = argparse.ArgumentParser(
        description="Windows Packet Capture Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --interfaces                     
  %(prog)s --capture                         
  %(prog)s --capture --interface "Ethernet" --output my_capture.etl
  %(prog)s --monitor                         
  %(prog)s --stop                            
        """
    )
    
    parser.add_argument("--interfaces", action="store_true",
                       help="List network interfaces")
    parser.add_argument("--capture", action="store_true",
                       help="Start packet capture")
    parser.add_argument("--interface", 
                       help="Specific interface to capture on")
    parser.add_argument("--output", default="capture.etl",
                       help="Output file for capture")
    parser.add_argument("--max-size", type=int, default=100,
                       help="Maximum capture size in MB")
    parser.add_argument("--monitor", action="store_true",
                       help="Monitor active connections")
    parser.add_argument("--stop", action="store_true",
                       help="Stop any running capture")
    
    args = parser.parse_args()
    
    capture_tool = WindowsPacketCapture()
    
    if args.interfaces:
        capture_tool.get_network_interfaces()
    
    elif args.capture:
        capture_tool.start_netsh_capture(
            interface=args.interface,
            output_file=args.output,
            max_size=args.max_size
        )
    
    elif args.monitor:
        monitor_connections()
    
    elif args.stop:
        capture_tool.stop_capture()
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
