import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from watchdog.observers import Observer
from encryption_handler import EncryptionHandler
from decryption_handler import DecryptionHandler

class CreateToolTip(object):
    """
    Create a tooltip for a given widget
    """
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.tooltip = None

    def enter(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=self.text, background="yellow", relief="solid", borderwidth=1)
        label.pack(ipadx=1)

    def leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
        self.tooltip = None

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption and Decryption Monitor")
        self.root.geometry("800x600")

        # Load and set the background image
        self.background_image_path = r"C:\Users\bluco\Downloads\background_image.png"
        self.background_image = Image.open(self.background_image_path)
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.background_label = tk.Label(self.root, image=self.background_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Create frames with a 5px border
        self.create_frames()

        # Set up encryption frame widgets
        self.setup_encryption_frame()

        # Set up decryption frame widgets
        self.setup_decryption_frame()

    def create_frames(self):
        self.encryption_frame = tk.Frame(self.root, bg="white", bd=5, relief="groove")
        self.encryption_frame.place(x=10, y=10, width=380, height=580)

        self.decryption_frame = tk.Frame(self.root, bg="white", bd=5, relief="groove")
        self.decryption_frame.place(x=410, y=10, width=380, height=580)

    def setup_encryption_frame(self):
        self.label1 = tk.Label(self.encryption_frame, text="Encryption Settings", font=("Helvetica", 16), bg="white")
        self.label1.pack(pady=10)

        self.label2 = tk.Label(self.encryption_frame, text="Select directory to monitor:", font=("Helvetica", 12), bg="white")
        self.label2.pack()

        self.select_directory_button = tk.Button(self.encryption_frame, text="Select Directory", command=self.select_directory, font=("Helvetica", 12))
        self.select_directory_button.pack(pady=10)
        CreateToolTip(self.select_directory_button, "Select the directory to monitor for encryption")

        self.label3 = tk.Label(self.encryption_frame, text="Select encryption key file:", font=("Helvetica", 12), bg="white")
        self.label3.pack()

        self.select_key_button = tk.Button(self.encryption_frame, text="Select Key File", command=self.select_key, font=("Helvetica", 12))
        self.select_key_button.pack(pady=10)
        CreateToolTip(self.select_key_button, "Select the encryption key file")

        self.label4 = tk.Label(self.encryption_frame, text="Select encryption trigger:", font=("Helvetica", 12), bg="white")
        self.label4.pack()

        self.encrypt_trigger = tk.StringVar()
        self.encrypt_trigger.set("Create")
        self.encrypt_trigger_menu = tk.OptionMenu(self.encryption_frame, self.encrypt_trigger, "Create", "Delete", "Modify")
        self.encrypt_trigger_menu.config(font=("Helvetica", 12), width=17)
        self.encrypt_trigger_menu.pack(pady=10)
        CreateToolTip(self.encrypt_trigger_menu, "Select when encryption should trigger")

        self.label5 = tk.Label(self.encryption_frame, text="Select encryption mode:", font=("Helvetica", 12), bg="white")
        self.label5.pack()

        self.encrypt_mode = tk.StringVar()
        self.encrypt_mode.set("Individual")
        self.encrypt_mode_menu = tk.OptionMenu(self.encryption_frame, self.encrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry)
        self.encrypt_mode_menu.config(font=("Helvetica", 12), width=17)
        self.encrypt_mode_menu.pack(pady=10)
        CreateToolTip(self.encrypt_mode_menu, "Select how files should be encrypted")

        self.label6 = tk.Label(self.encryption_frame, text="Enter group paths (comma-separated):", font=("Helvetica", 12), bg="white")
        self.label6.pack()

        self.group_paths_entry = tk.Entry(self.encryption_frame, width=50, font=("Helvetica", 12))
        self.group_paths_entry.pack(pady=10)
        self.group_paths_entry.config(state=tk.DISABLED)
        CreateToolTip(self.group_paths_entry, "Enter paths for group encryption (comma-separated)")

        self.encrypt_label = tk.Label(self.encryption_frame, text="Encryption Handler Status: Idle", font=("Helvetica", 12), bg="white")
        self.encrypt_label.pack(pady=10)

        self.start_button = tk.Button(self.encryption_frame, text="Start Monitoring", command=self.start_monitoring, font=("Helvetica", 12), width=20)
        self.start_button.pack(pady=10)
        CreateToolTip(self.start_button, "Start monitoring the selected directory for encryption")

        self.stop_button = tk.Button(self.encryption_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED, font=("Helvetica", 12), width=20)
        self.stop_button.pack(pady=10)
        CreateToolTip(self.stop_button, "Stop monitoring the selected directory for encryption")

    def setup_decryption_frame(self):
        self.label7 = tk.Label(self.decryption_frame, text="Decryption Settings", font=("Helvetica", 16), bg="white")
        self.label7.pack(pady=10)

        self.label8 = tk.Label(self.decryption_frame, text="Select directory to monitor:", font=("Helvetica", 12), bg="white")
        self.label8.pack()

        self.select_directory_button_dec = tk.Button(self.decryption_frame, text="Select Directory", command=self.select_directory_dec, font=("Helvetica", 12))
        self.select_directory_button_dec.pack(pady=10)
        CreateToolTip(self.select_directory_button_dec, "Select the directory to monitor for decryption")

        self.label3_dec = tk.Label(self.decryption_frame, text="Select decryption key file:", font=("Helvetica", 12), bg="white")
        self.label3_dec.pack()

        self.select_key_button_dec = tk.Button(self.decryption_frame, text="Select Key File", command=self.select_key_dec, font=("Helvetica", 12))
        self.select_key_button_dec.pack(pady=10)
        CreateToolTip(self.select_key_button_dec, "Select the decryption key file")

        self.label4_dec = tk.Label(self.decryption_frame, text="Select decryption trigger:", font=("Helvetica", 12), bg="white")
        self.label4_dec.pack()

        self.decrypt_trigger = tk.StringVar()
        self.decrypt_trigger.set("Create")
        self.decrypt_trigger_menu = tk.OptionMenu(self.decryption_frame, self.decrypt_trigger, "Create", "Delete", "Modify")
        self.decrypt_trigger_menu.config(font=("Helvetica", 12), width=17)
        self.decrypt_trigger_menu.pack(pady=10)
        CreateToolTip(self.decrypt_trigger_menu, "Select when decryption should trigger")

        self.label9 = tk.Label(self.decryption_frame, text="Select decryption mode:", font=("Helvetica", 12), bg="white")
        self.label9.pack()

        self.decrypt_mode = tk.StringVar()
        self.decrypt_mode.set("Individual")
        self.decrypt_mode_menu = tk.OptionMenu(self.decryption_frame, self.decrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry_dec)
        self.decrypt_mode_menu.config(font=("Helvetica", 12), width=17)
        self.decrypt_mode_menu.pack(pady=10)
        CreateToolTip(self.decrypt_mode_menu, "Select how files should be decrypted")

        self.label10 = tk.Label(self.decryption_frame, text="Enter group paths (comma-separated):", font=("Helvetica", 12), bg="white")
        self.label10.pack()

        self.group_paths_entry_dec = tk.Entry(self.decryption_frame, width=50, font=("Helvetica", 12))
        self.group_paths_entry_dec.pack(pady=10)
        self.group_paths_entry_dec.config(state=tk.DISABLED)
        CreateToolTip(self.group_paths_entry_dec, "Enter paths for group decryption (comma-separated)")

        self.decrypt_label = tk.Label(self.decryption_frame, text="Decryption Handler Status: Idle", font=("Helvetica", 12), bg="white")
        self.decrypt_label.pack(pady=10)

        self.start_button_dec = tk.Button(self.decryption_frame, text="Start Monitoring", command=self.start_monitoring_dec, font=("Helvetica", 12), width=20)
        self.start_button_dec.pack(pady=10)
        CreateToolTip(self.start_button_dec, "Start monitoring the selected directory for decryption")

        self.stop_button_dec = tk.Button(self.decryption_frame, text="Stop Monitoring", command=self.stop_monitoring_dec, state=tk.DISABLED, font=("Helvetica", 12), width=20)
        self.stop_button_dec.pack(pady=10)
        CreateToolTip(self.stop_button_dec, "Stop monitoring the selected directory for decryption")

    def select_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory_to_monitor = directory
            messagebox.showinfo("Directory Selected", f"Selected directory: {directory}")

    def select_key(self):
        key_file = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if key_file:
            self.encryption_key_file = key_file
            messagebox.showinfo("Key File Selected", f"Selected key file: {key_file}")

    def select_directory_dec(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory_to_monitor_dec = directory
            messagebox.showinfo("Directory Selected", f"Selected directory: {directory}")

    def select_key_dec(self):
        key_file = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if key_file:
            self.decryption_key_file = key_file
            messagebox.showinfo("Key File Selected", f"Selected key file: {key_file}")

    def toggle_group_entry(self, mode):
        if mode == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.delete(0, tk.END)
            self.group_paths_entry.config(state=tk.DISABLED)

    def toggle_group_entry_dec(self, mode):
        if mode == "Group":
            self.group_paths_entry_dec.config(state=tk.NORMAL)
        else:
            self.group_paths_entry_dec.delete(0, tk.END)
            self.group_paths_entry_dec.config(state=tk.DISABLED)

    def start_monitoring(self):
        # Add logic to start the encryption monitoring
        self.encrypt_label.config(text="Encryption Handler Status: Running")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_monitoring(self):
        # Add logic to stop the encryption monitoring
        self.encrypt_label.config(text="Encryption Handler Status: Idle")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def start_monitoring_dec(self):
        # Add logic to start the decryption monitoring
        self.decrypt_label.config(text="Decryption Handler Status: Running")
        self.start_button_dec.config(state=tk.DISABLED)
        self.stop_button_dec.config(state=tk.NORMAL)

    def stop_monitoring_dec(self):
        # Add logic to stop the decryption monitoring
        self.decrypt_label.config(text="Decryption Handler Status: Idle")
        self.start_button_dec.config(state=tk.NORMAL)
        self.stop_button_dec.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()