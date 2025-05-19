# List available network interfaces using pyshark
import pyshark

def list_interfaces():
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    print("Available interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")

if __name__ == "__main__":
    list_interfaces()
