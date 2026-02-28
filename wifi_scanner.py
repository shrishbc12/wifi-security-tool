#!/usr/bin/env python3
import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt


class WiFiScanner:
    def __init__(self, iface, tree):
        self.iface = iface
        self.tree = tree
        self.nets = {}

    def handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            elt = pkt[Dot11Elt]
            ssid = "<Hidden>"

            while elt:
                if elt.ID == 0:
                    ssid = elt.info.decode('utf-8', errors='ignore') or "<Hidden>"
                    break
                elt = elt.payload

            signal = getattr(pkt, 'dBm_AntSignal', 'N/A')
            enc = "WPA2" if pkt[Dot11Beacon].cap.privacy else "Open"

            if bssid not in self.nets:
                self.nets[bssid] = ssid
                self.tree.insert("", "end", values=(ssid, bssid, signal, enc))

    def scan(self, sec):
        sniff(iface=self.iface, prn=self.handler, timeout=sec, store=0)


# ---------------- GUI ---------------- #

import threading

def start_scan():
    if os.geteuid() != 0:
        messagebox.showerror("Error", "Run with sudo!")
        return

    selected_iface = iface_var.get()
    duration = duration_entry.get()

    if not selected_iface:
        messagebox.showerror("Error", "Select interface")
        return

    try:
        sec = int(duration)
    except:
        messagebox.showerror("Error", "Invalid duration")
        return

    for row in tree.get_children():
        tree.delete(row)

    def run_scan():
        scanner = WiFiScanner(selected_iface, tree)
        scanner.scan(sec)

    threading.Thread(target=run_scan, daemon=True).start()

# Main Window
root = tk.Tk()
root.title("WiFi Scanner GUI")
root.geometry("700x400")

# Get Interfaces
result = subprocess.run(['iwconfig'], capture_output=True, text=True)
ifaces = [l.split()[0] for l in result.stdout.split('\n') if 'IEEE 802.11' in l]

iface_var = tk.StringVar()

# Top Frame
top_frame = tk.Frame(root)
top_frame.pack(pady=10)

tk.Label(top_frame, text="Interface:").grid(row=0, column=0)
iface_menu = ttk.Combobox(top_frame, textvariable=iface_var, values=ifaces)
iface_menu.grid(row=0, column=1)

tk.Label(top_frame, text="Duration (sec):").grid(row=0, column=2)
duration_entry = tk.Entry(top_frame, width=5)
duration_entry.insert(0, "30")
duration_entry.grid(row=0, column=3)

tk.Button(top_frame, text="Start Scan", command=start_scan).grid(row=0, column=4, padx=10)

# Table
columns = ("SSID", "BSSID", "Signal", "Encryption")
tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

tree.pack(fill="both", expand=True, pady=10)

root.mainloop()
