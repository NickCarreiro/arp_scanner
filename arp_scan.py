import tkinter as tk
import subprocess
import json
import socket
import psutil
from scapy.all import sniff, IP


# Function to perform ARP scan and save results to a file
def arp_scan_and_save():
    target_ip = target_ip_entry.get()
    output_file = "arp_scan_results.json"
    try:
        result = subprocess.check_output(['arp', '-a'], universal_newlines=True)
        arp_output = result.splitlines()
        arp_devices = [line.split() for line in arp_output if line.strip()]

        # Create a formatted string to display in the GUI
        arp_result_str = "ARP Scan Results:\n"
        arp_result_str += "{:<20} {:<20}\n".format("IP Address", "MAC Address")
        arp_result_str += "-" * 40 + "\n"

        # Open the JSON file in append mode to add newline at the end of each field
        with open(output_file, 'a') as file:
            for device in arp_devices:
                if len(device) >= 2:
                    arp_result_str += "{:<20} {:<20}\n".format(device[0], device[1])
                    json.dump({"IP Address": device[0], "MAC Address": device[1]}, file)
                    file.write('\n')  # Add a newline at the end of each field

        result_text.insert(tk.END, arp_result_str)
        return "ARP scan completed and results saved."
    except Exception as e:
        return str(e)


# Function to perform port scanning
def port_scan():
    target_ip = target_ip_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        result_text.insert(tk.END, f"Open Ports: {open_ports}\n")
        return "Port scan completed."
    except Exception as e:
        return str(e)


# Function to start traffic analysis on the selected interface
def start_traffic_analysis():
    selected_interface = interface_var.get()
    print(f"Starting traffic analysis on interface: {selected_interface}")
    sniff(iface=selected_interface, prn=analyze_traffic)


# Function to analyze network traffic
def analyze_traffic(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto  # IP protocol (6 for TCP, 17 for UDP)
        result_text.insert(tk.END, f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}\n")


# Function to display network adapter usage
def show_network_usage(interface):
    network_info = psutil.net_io_counters(pernic=True)

    result_text.delete(1.0, tk.END)  # Clear previous results

    if interface in network_info:
        stats = network_info[interface]
        result_text.insert(tk.END, f"Interface: {interface}\n")
        result_text.insert(tk.END, f"Bytes Sent: {stats.bytes_sent}\n")
        result_text.insert(tk.END, f"Bytes Received: {stats.bytes_recv}\n")
        result_text.insert(tk.END, f"Packets Sent: {stats.packets_sent}\n")
        result_text.insert(tk.END, f"Packets Received: {stats.packets_recv}\n")
        result_text.insert(tk.END, "-" * 40 + "\n")
    else:
        result_text.insert(tk.END, f"No data available for interface: {interface}\n")


# Function to update the selected interface and show network usage
def update_selected_interface(*args):
    selected_interface = interface_var.get()
    show_network_usage(selected_interface)


# Create a tkinter window
window = tk.Tk()
window.title("Network Tools")

# Configure window size
window.geometry("800x600")

# Create and configure widgets
frame = tk.Frame(window, padx=10, pady=10)
frame.pack()

target_ip_label = tk.Label(frame, text="Target IP Address:")
target_ip_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

target_ip_entry = tk.Entry(frame)
target_ip_entry.grid(row=0, column=1, padx=5, pady=5)

arp_scan_and_save_button = tk.Button(frame, text="ARP Scan and Save", command=arp_scan_and_save)
arp_scan_and_save_button.grid(row=0, column=2, padx=5, pady=5)

start_port_label = tk.Label(frame, text="Start Port:")
start_port_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

start_port_entry = tk.Entry(frame)
start_port_entry.grid(row=1, column=1, padx=5, pady=5)

end_port_label = tk.Label(frame, text="End Port:")
end_port_label.grid(row=1, column=2, padx=5, pady=5, sticky="w")

end_port_entry = tk.Entry(frame)
end_port_entry.grid(row=1, column=3, padx=5, pady=5)

port_scan_button = tk.Button(frame, text="Port Scan", command=port_scan)
port_scan_button.grid(row=1, column=4, padx=5, pady=5)

interface_label = tk.Label(frame, text="Select Network Interface:")
interface_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")

# Get a list of available network interfaces using psutil
network_interfaces = [iface for iface, addrs in psutil.net_if_addrs().items()]

interface_var = tk.StringVar()
interface_var.set(network_interfaces[0])  # Set default interface
interface_dropdown = tk.OptionMenu(frame, interface_var, *network_interfaces)
interface_dropdown.grid(row=2, column=1, padx=5, pady=5)

show_usage_button = tk.Button(frame, text="Show Network Adapter Usage", command=update_selected_interface)
show_usage_button.grid(row=2, column=2, padx=5, pady=5)

result_text = tk.Text(frame, height=10, width=60)
result_text.grid(row=3, column=0, columnspan=5, padx=5, pady=5)

# Bind the dropdown menu selection to update the selected interface
interface_var.trace("w", update_selected_interface)

# Start the tkinter main loop
window.mainloop()
