import tkinter as tk #GUI
from tkinter import ttk, messagebox, filedialog #GUI
import csv #export data
import psutil # my own computer monitor
from scapy.all import sniff #send, sniff, dissect and forge network packets, for probing and scanning networks
import os #interact with the underlying operating system, provides functions to perform tasks like creating and managing files.
import json #storing and transporting data

# Import functions from encrypt_data.py
from encrypt_data import generate_key, encrypt_data, decrypt_data, read_word_document

# Function to fetch business information (mocked for now)
def fetch_business_info():
    try:
        # Example data (replace with actual business info if available)
        return [
            {'name': 'My Computer', 'system_info': f'{psutil.cpu_percent()}% CPU usage', 'network_status': 'Monitoring...'}
        ]
    except Exception as e:
        raise RuntimeError(f"Error fetching business info: {e}")

# Function to fetch network activity
def fetch_network_activity(business_name):
    activity_log = []

    def packet_callback(packet):
        activity_log.append({
            'type': packet.summary(),
            'source': packet.src,
            'action': 'monitored'
        })

    try:
        sniff(prn=packet_callback, count=10, timeout=10)  # Capture 10 packets or timeout after 10 seconds
        return activity_log
    except Exception as e:
        raise RuntimeError(f"Error fetching network activity: {e}")

# Function to determine if an activity is malicious
def is_malicious(activity):
    malicious_types = ['malware', 'phishing', 'ddos']
    return any(mal_type in activity['type'].lower() for mal_type in malicious_types)

class AdminMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Monitor")
        self.geometry("1200x700")  # Updated window size

        # Apply a ttk theme
        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        # General Styling
        self.option_add("*Font", "Helvetica 10")
        self.option_add("*TButton.Font", "Helvetica 10 bold")
        self.option_add("*TLabel.Font", "Helvetica 10")
        self.option_add("*TEntry.Font", "Helvetica 10")

        # Generate encryption key
        self.encryption_key = generate_key()

        # Create the main frame
        self.main_frame = ttk.Frame(self, padding="10 10 10 10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create the business list frame
        self.business_list_frame = ttk.Frame(self.main_frame, padding="5 5 5 5", relief="groove")
        self.business_list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.business_list_label = ttk.Label(self.business_list_frame, text="Businesses", font="Helvetica 12 bold")
        self.business_list_label.pack(pady=5)

        self.business_listbox = tk.Listbox(self.business_list_frame, relief="sunken", borderwidth=2)
        self.business_listbox.pack(fill=tk.BOTH, expand=True)
        self.business_listbox.bind('<<ListboxSelect>>', self.on_business_select)

        # Create the business details frame
        self.business_details_frame = ttk.Frame(self.main_frame, padding="5 5 5 5", relief="groove")
        self.business_details_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.system_info_label = ttk.Label(self.business_details_frame, text="System Info:", font="Helvetica 12 bold")
        self.system_info_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.system_info_value = ttk.Label(self.business_details_frame, text="")
        self.system_info_value.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.network_status_label = ttk.Label(self.business_details_frame, text="Network Status:", font="Helvetica 12 bold")
        self.network_status_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.network_status_value = ttk.Label(self.business_details_frame, text="")
        self.network_status_value.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Create the network activity frame
        self.network_activity_frame = ttk.Frame(self.main_frame, padding="5 5 5 5", relief="groove")
        self.network_activity_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

        self.network_activity_label = ttk.Label(self.network_activity_frame, text="Network Activity", font="Helvetica 12 bold")
        self.network_activity_label.pack(pady=5)

        # Adding scrollbars to the network activity listbox
        self.network_activity_listbox = ttk.Treeview(self.network_activity_frame, columns=("Activity", "Status"), show='headings')
        self.network_activity_listbox.heading("Activity", text="Activity")
        self.network_activity_listbox.heading("Status", text="Status")
        self.network_activity_listbox.pack(fill=tk.BOTH, expand=True)

        self.network_activity_scrollbar_y = ttk.Scrollbar(self.network_activity_frame, orient=tk.VERTICAL, command=self.network_activity_listbox.yview)
        self.network_activity_listbox.configure(yscroll=self.network_activity_scrollbar_y.set)
        self.network_activity_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.network_activity_scrollbar_x = ttk.Scrollbar(self.network_activity_frame, orient=tk.HORIZONTAL, command=self.network_activity_listbox.xview)
        self.network_activity_listbox.configure(xscroll=self.network_activity_scrollbar_x.set)
        self.network_activity_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Create the data management frame
        self.data_management_frame = ttk.Frame(self.main_frame, padding="5 5 5 5", relief="groove")
        self.data_management_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        self.data_management_label = ttk.Label(self.data_management_frame, text="Data Management & Encryption", font="Helvetica 12 bold")
        self.data_management_label.grid(row=0, column=0, columnspan=2, pady=5)

        self.data_fields_listbox_label = ttk.Label(self.data_management_frame, text="Data Fields:")
        self.data_fields_listbox_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.data_fields_listbox = tk.Listbox(self.data_management_frame, selectmode=tk.MULTIPLE, relief="sunken", borderwidth=2)
        self.data_fields_listbox.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Populate data fields listbox (example fields)
        self.data_fields = ["system_info", "network_status"]
        self.file_contents = {}  # Dictionary to store file contents
        for field in self.data_fields:
            self.data_fields_listbox.insert(tk.END, field)

        self.add_file_button = ttk.Button(self.data_management_frame, text="Add File to Data Fields", command=self.add_file_to_data_fields)
        self.add_file_button.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.encrypt_button = ttk.Button(self.data_management_frame, text="Encrypt Selected Data", command=self.encrypt_selected_data)
        self.encrypt_button.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        self.decrypt_button = ttk.Button(self.data_management_frame, text="Decrypt Selected Data", command=self.decrypt_selected_data)
        self.decrypt_button.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.encrypted_data_label = ttk.Label(self.data_management_frame, text="Encrypted Data:")
        self.encrypted_data_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")

        self.encrypted_data_value = ttk.Label(self.data_management_frame, text="", wraplength=400)
        self.encrypted_data_value.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        self.decrypted_data_label = ttk.Label(self.data_management_frame, text="Decrypted Data:")
        self.decrypted_data_label.grid(row=5, column=0, padx=5, pady=5, sticky="w")

        self.decrypted_data_value = ttk.Label(self.data_management_frame, text="", wraplength=400)
        self.decrypted_data_value.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        # Export button
        self.export_button = ttk.Button(self.main_frame, text="Export Data", command=self.export_data)
        self.export_button.grid(row=2, column=2, padx=10, pady=10, sticky="e")

        # Adjust grid weights
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(2, weight=1)
        self.network_activity_frame.grid_rowconfigure(0, weight=1)
        self.network_activity_frame.grid_columnconfigure(0, weight=1)
        self.data_management_frame.grid_rowconfigure(3, weight=1)
        self.data_management_frame.grid_columnconfigure(1, weight=1)

        # Load business data
        self.load_business_data()

        # Start real-time updates
        self.update_network_activity()

    def load_business_data(self):
        try:
            businesses = fetch_business_info()
            for business in businesses:
                self.business_listbox.insert(tk.END, business['name'])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load business data: {e}")

    def on_business_select(self, event):
        selected_index = self.business_listbox.curselection()
        if selected_index:
            selected_business = self.business_listbox.get(selected_index)
            self.display_business_details(selected_business)
            self.load_network_activity(selected_business)

    def display_business_details(self, business_name):
        try:
            businesses = fetch_business_info()
            for business in businesses:
                if business['name'] == business_name:
                    self.system_info_value.config(text=business['system_info'])
                    self.network_status_value.config(text=business['network_status'])
                    break
        except Exception as e:
            messagebox.showerror("Error", f"Failed to display business details: {e}")

    def load_network_activity(self, business_name):
        try:
            self.network_activity_listbox.delete(*self.network_activity_listbox.get_children())
            activities = fetch_network_activity(business_name)
            for activity in activities:
                status = "Malicious" if is_malicious(activity) else "Secure"
                self.network_activity_listbox.insert("", tk.END, values=(f"{activity['type']} from {activity['source']} {activity['action']}", status))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load network activity: {e}")

    def update_network_activity(self):
        selected_index = self.business_listbox.curselection()
        if selected_index:
            selected_business = self.business_listbox.get(selected_index)
            self.load_network_activity(selected_business)
        # Repeat the update every 5 seconds
        self.after(5000, self.update_network_activity)

    def add_file_to_data_fields(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("Word documents", "*.docx")])
        if file_path:
            display_name = os.path.basename(file_path)
            self.data_fields.append(display_name)
            self.data_fields_listbox.insert(tk.END, display_name)
            # Read and store the file content
            if file_path.endswith('.docx'):
                content = read_word_document(file_path)
            else:
                with open(file_path, 'r') as file:
                    content = file.read()
            self.file_contents[display_name] = content

    def encrypt_selected_data(self):
        try:
            selected_indices = self.data_fields_listbox.curselection()
            selected_fields = [self.data_fields[i] for i in selected_indices]
            data = {field: self.file_contents.get(field, "") for field in selected_fields}
            encrypted_data = {field: encrypt_data(value, self.encryption_key) for field, value in data.items()}
            self.encrypted_data_value.config(text=json.dumps(encrypted_data))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt data: {e}")

    def decrypt_selected_data(self):
        try:
            encrypted_data = json.loads(self.encrypted_data_value.cget("text"))
            decrypted_data = {field: decrypt_data(value, self.encryption_key) for field, value in encrypted_data.items()}
            self.decrypted_data_value.config(text=json.dumps(decrypted_data))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt data: {e}")

    def export_data(self):
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if file_path:
                with open(file_path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Activity", "Status"])
                    for row_id in self.network_activity_listbox.get_children():
                        row = self.network_activity_listbox.item(row_id)['values']
                        writer.writerow(row)
                messagebox.showinfo("Success", "Data exported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {e}")

if __name__ == "__main__":
    app = AdminMonitorApp()
    app.mainloop()