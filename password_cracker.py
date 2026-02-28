#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import threading
import os
import re


# ------------------- FUNCTIONS ------------------- #

def browse_cap():
    file = filedialog.askopenfilename(filetypes=[("Capture Files", "*.cap")])
    if file:
        cap_entry.delete(0, tk.END)
        cap_entry.insert(0, file)


def browse_wordlist():
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file:
        wordlist_entry.delete(0, tk.END)
        wordlist_entry.insert(0, file)


def start_crack():
    if os.geteuid() != 0:
        messagebox.showerror("Error", "Run with sudo!")
        return

    cap = cap_entry.get()
    wordlist = wordlist_entry.get()

    if not os.path.exists(cap):
        messagebox.showerror("Error", "Capture file not found")
        return
    if not os.path.exists(wordlist):
        messagebox.showerror("Error", "Wordlist not found")
        return

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, "=== WPA/WPA2 PASSWORD CRACKER ===\n\n")
    output_box.insert(tk.END, f"[*] Analyzing {cap}...\n")

    def crack_process():
        # Analyze handshake
        result = subprocess.run(['aircrack-ng', cap],
                                capture_output=True,
                                text=True)

        bssid_match = re.search(r'([0-9A-Fa-f:]{17})', result.stdout)

        if not bssid_match:
            output_box.insert(tk.END, "[!] No handshake found in capture\n")
            return

        bssid = bssid_match.group(1)
        output_box.insert(tk.END, f"[*] Target BSSID: {bssid}\n")
        output_box.insert(tk.END, f"\n[*] Cracking with wordlist: {wordlist}\n\n")

        # Run cracking and stream output live
        process = subprocess.Popen(
            ['aircrack-ng', '-w', wordlist, '-b', bssid, cap],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in process.stdout:
            output_box.insert(tk.END, line)
            output_box.see(tk.END)

    threading.Thread(target=crack_process, daemon=True).start()


def on_close():
    root.destroy()
    os._exit(0)


# ------------------- GUI ------------------- #

root = tk.Tk()
root.title("WPA/WPA2 Password Cracker GUI")
root.geometry("700x500")

# Capture File
tk.Label(root, text="Capture File (.cap):").pack(pady=5)
cap_entry = tk.Entry(root, width=60)
cap_entry.pack()
tk.Button(root, text="Browse", command=browse_cap).pack(pady=5)

# Wordlist
tk.Label(root, text="Wordlist (.txt):").pack(pady=5)
wordlist_entry = tk.Entry(root, width=60)
wordlist_entry.pack()
tk.Button(root, text="Browse", command=browse_wordlist).pack(pady=5)

# Start Button
tk.Button(root, text="Start Cracking", command=start_crack).pack(pady=10)

# Output Box
output_box = scrolledtext.ScrolledText(root, width=80, height=15)
output_box.pack(pady=10)

root.protocol("WM_DELETE_WINDOW", on_close)

root.mainloop()
