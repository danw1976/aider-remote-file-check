#!/usr/bin/env python3
"""
GUI for Remote server inode usage checker.

Provides a graphical interface to connect to a remote server and check inode usage.
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path

import paramiko

from inode_checker import get_ssh_client, get_directory_inodes


class InodeCheckerGUI:
    """GUI application for checking remote server inode usage."""

    def __init__(self, root):
        """Initialize the GUI application."""
        self.root = root
        self.root.title("Remote Inode Checker")
        self.root.geometry("700x600")
        self.client = None
        self.is_connected = False

        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface."""
        # Connection Frame
        connection_frame = ttk.LabelFrame(self.root, text="Connection Settings", padding=10)
        connection_frame.pack(fill=tk.X, padx=10, pady=10)

        # Host
        ttk.Label(connection_frame, text="Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.host_entry = ttk.Entry(connection_frame, width=30)
        self.host_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)

        # Port
        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        self.port_entry = ttk.Entry(connection_frame, width=10)
        self.port_entry.insert(0, "22")
        self.port_entry.grid(row=0, column=3, sticky=tk.EW, padx=5)

        # Username
        ttk.Label(connection_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(connection_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky=tk.EW, padx=5)

        # Authentication Frame
        auth_frame = ttk.LabelFrame(connection_frame, text="Authentication", padding=5)
        auth_frame.grid(row=2, column=0, columnspan=4, sticky=tk.EW, pady=10)

        self.auth_var = tk.StringVar(value="password")

        ttk.Radiobutton(auth_frame, text="Password", variable=self.auth_var, value="password").pack(anchor=tk.W)
        ttk.Radiobutton(auth_frame, text="SSH Key", variable=self.auth_var, value="key").pack(anchor=tk.W)

        # Password
        ttk.Label(auth_frame, text="Password:").pack(anchor=tk.W, pady=(5, 0))
        self.password_entry = ttk.Entry(auth_frame, width=30, show="*")
        self.password_entry.pack(anchor=tk.W, padx=20)

        # Key File
        ttk.Label(auth_frame, text="Key File:").pack(anchor=tk.W, pady=(5, 0))
        key_frame = ttk.Frame(auth_frame)
        key_frame.pack(anchor=tk.W, padx=20, fill=tk.X)
        self.key_entry = ttk.Entry(key_frame, width=25)
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(key_frame, text="Browse", command=self.browse_key_file).pack(side=tk.LEFT, padx=5)

        connection_frame.columnconfigure(1, weight=1)

        # Path Frame
        path_frame = ttk.LabelFrame(self.root, text="Path Settings", padding=10)
        path_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(path_frame, text="Remote Path:").pack(anchor=tk.W, pady=5)
        self.path_entry = ttk.Entry(path_frame, width=50)
        self.path_entry.insert(0, "/")
        self.path_entry.pack(anchor=tk.W, fill=tk.X, pady=5)

        # Button Frame
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        self.connect_button = ttk.Button(button_frame, text="Connect & Check", command=self.check_inodes)
        self.connect_button.pack(side=tk.LEFT, padx=5)

        self.disconnect_button = ttk.Button(button_frame, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Clear", command=self.clear_results).pack(side=tk.LEFT, padx=5)

        # Status Label
        self.status_label = ttk.Label(self.root, text="Status: Disconnected", relief=tk.SUNKEN)
        self.status_label.pack(fill=tk.X, padx=10, pady=5)

        # Results Frame
        results_frame = ttk.LabelFrame(self.root, text="Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Results Text
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80, state=tk.DISABLED)
        self.results_text.pack(fill=tk.BOTH, expand=True)

    def browse_key_file(self):
        """Browse for SSH key file."""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select SSH Private Key",
            filetypes=[("All Files", "*.*"), ("PEM Files", "*.pem"), ("Key Files", "*.key")]
        )
        if filename:
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, filename)

    def check_inodes(self):
        """Check inode usage on remote server."""
        # Validate inputs
        host = self.host_entry.get().strip()
        username = self.username_entry.get().strip()
        path = self.path_entry.get().strip()
        port_str = self.port_entry.get().strip()

        if not host or not username or not path:
            messagebox.showerror("Input Error", "Please fill in Host, Username, and Path")
            return

        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Input Error", "Port must be a valid number")
            return

        # Get authentication details
        auth_method = self.auth_var.get()
        if auth_method == "password":
            password = self.password_entry.get()
            key_file = None
            if not password:
                messagebox.showerror("Input Error", "Please enter a password")
                return
        else:
            key_file = self.key_entry.get().strip()
            password = None
            if not key_file:
                messagebox.showerror("Input Error", "Please select a key file")
                return

        # Run check in separate thread to avoid freezing UI
        thread = threading.Thread(
            target=self._check_inodes_thread,
            args=(host, username, password, key_file, port, path)
        )
        thread.daemon = True
        thread.start()

    def _check_inodes_thread(self, host, username, password, key_file, port, path):
        """Thread function to check inodes."""
        try:
            self.update_status("Connecting...")
            self.connect_button.config(state=tk.DISABLED)

            # Connect to server
            self.client = get_ssh_client(host, username, password, key_file, port)
            self.is_connected = True
            self.disconnect_button.config(state=tk.NORMAL)

            self.update_status(f"Connected to {host}. Checking inodes...")

            # Get inode usage
            inodes = get_directory_inodes(self.client, path)

            if not inodes:
                self.display_results("No directories found.")
                self.update_status("Ready")
                return

            # Sort by inode count (descending)
            sorted_inodes = sorted(inodes.items(), key=lambda x: x[1], reverse=True)

            # Format results
            results = f"Directory Inode Usage for: {path}\n"
            results += "=" * 60 + "\n"
            results += f"{'Directory':<45} {'Inodes':>12}\n"
            results += "-" * 60 + "\n"

            for dir_name, inode_count in sorted_inodes:
                results += f"{dir_name:<45} {inode_count:>12,}\n"

            results += "-" * 60 + "\n"
            results += f"{'Total':<45} {sum(inodes.values()):>12,}\n"

            self.display_results(results)
            self.update_status(f"Ready - Connected to {host}")

        except Exception as e:
            self.display_results(f"Error: {str(e)}")
            self.update_status("Error occurred")
            self.is_connected = False
            self.disconnect_button.config(state=tk.DISABLED)
        finally:
            self.connect_button.config(state=tk.NORMAL)

    def disconnect(self):
        """Disconnect from remote server."""
        if self.client:
            self.client.close()
            self.client = None
            self.is_connected = False
        self.disconnect_button.config(state=tk.DISABLED)
        self.connect_button.config(state=tk.NORMAL)
        self.update_status("Disconnected")

    def display_results(self, text):
        """Display results in the text widget."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, text)
        self.results_text.config(state=tk.DISABLED)

    def clear_results(self):
        """Clear the results display."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)

    def update_status(self, status):
        """Update the status label."""
        self.status_label.config(text=f"Status: {status}")
        self.root.update_idletasks()


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    app = InodeCheckerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
