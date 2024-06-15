import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import os

# Tooltip class
class CreateToolTip(object):
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event=None):
        self.show_tooltip()

    def leave(self, event=None):
        self.hide_tooltip()

    def show_tooltip(self):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, background="yellow", relief='solid', borderwidth=1)
        label.pack(ipadx=1)

    def hide_tooltip(self):
        tw = self.tooltip_window
        if tw:
            tw.destroy()

# EncryptionHandler class definition
class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups

    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.encrypt_file(file_path)
        elif self.mode == "All":
            self.encrypt_all_files()

    def is_group(self, file_path):
        if self.groups:
            for group_path in self.groups:
                if group_path.strip() in file_path:
                    return True
        return False

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path + ".encrypted", "wb") as f:
            f.write(encrypted_data)
        os.remove(file_path)

    def encrypt_all_files(self):
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not file_path.endswith(".encrypted"):
                    self.encrypt_file(file_path)

class DecryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups):
        super().__init__()
        self.key = key
        self.fernet = Fernet(self.key)
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups

    def on_created(self, event):
        if not event.is_directory and self.trigger == "Create":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_deleted(self, event):
        if not event.is_directory and self.trigger == "Delete":
            file_path = event.src_path
            if not file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def on_modified(self, event):
        if not event.is_directory and self.trigger == "Modify":
            file_path = event.src_path
            if file_path.endswith(".encrypted"):
                self.handle_file(file_path)

    def handle_file(self, file_path):
        if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
            self.decrypt_file(file_path)
        elif self.mode == "All":
            self.decrypt_all_files()

    def is_group(self, file_path):
        if self.groups:
            for group_path in self.groups:
                if group_path.strip() in file_path:
                    return True
        return False

    def decrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        decrypted_data = self.fernet.decrypt(data)
        with open(file_path[:-len(".encrypted")], "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)

    def decrypt_all_files(self):
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith(".encrypted"):
                    self.decrypt_file(file_path)

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Labyrinth - Encryption & Decryption")

        # Load background image
        self.background_image_path = "C:/Users/bluco/Downloads/background_image.png"
        self.background_image = Image.open(self.background_image_path)
        self.background_photo = ImageTk.PhotoImage(self.background_image)

        # Create a label with the background image
        self.background_label = tk.Label(master, image=self.background_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.encryption_frame = tk.Frame(master, bg="white", bd=5)
        self.encryption_frame.pack(side="left", padx=20, pady=(20, 10))

        self.label1 = tk.Label(self.encryption_frame, text="Select a directory to monitor:", font=("Helvetica", 12), bg="white")
        self.label1.pack()

        self.directory_button = tk.Button(self.encryption_frame, text="Select Directory", command=self.select_directory, font=("Helvetica", 12), width=20)
        self.directory_button.pack(pady=10)
        CreateToolTip(self.directory_button, "Click to select the directory to monitor")

        self.label2 = tk.Label(self.encryption_frame, text="Select a key file:", font=("Helvetica", 12), bg="white")
        self.label2.pack()

        self.key_button = tk.Button(self.encryption_frame, text="Select Key File", command=self.select_key, font=("Helvetica", 12), width=20)
        self.key_button.pack(pady=10)
        CreateToolTip(self.key_button, "Click to select the key file")

        self.label3 = tk.Label(self.encryption_frame, text="Select trigger for encryption:", font=("Helvetica", 12), bg="white")
        self.label3.pack()

        self.encrypt_trigger = tk.StringVar()
        self.encrypt_trigger.set("Create")
        self.encrypt_trigger_menu = tk.OptionMenu(self.encryption_frame, self.encrypt_trigger, "Create", "Delete", "Modify")
        self.encrypt_trigger_menu.config(font=("Helvetica", 12), width=17)
        self.encrypt_trigger_menu.pack(pady=10)
        CreateToolTip(self.encrypt_trigger_menu, "Select when encryption should trigger")

        self.label4 = tk.Label(self.encryption_frame, text="Select encryption mode:", font=("Helvetica", 12), bg="white")
        self.label4.pack()

        self.encrypt_mode = tk.StringVar()
        self.encrypt_mode.set("Individual")
        self.encrypt_mode_menu = tk.OptionMenu(self.encryption_frame, self.encrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry)
        self.encrypt_mode_menu.config(font=("Helvetica", 12), width=17)
        self.encrypt_mode_menu.pack(pady=10)
        CreateToolTip(self.encrypt_mode_menu, "Select how files should be encrypted")

        self.label5 = tk.Label(self.encryption_frame, text="Enter group paths (comma-separated):", font=("Helvetica", 12), bg="white")
        self.label5.pack()

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

        self.decryption_frame = tk.Frame(master, bg="white", bd=5)
        self.decryption_frame.pack(side="right", padx=20, pady=(20, 10))

        self.label6 = tk.Label(self.decryption_frame, text="Select a directory to monitor:", font=("Helvetica", 12), bg="white")
        self.label6.pack()

        self.directory_button_dec = tk.Button(self.decryption_frame, text="Select Directory", command=self.select_directory_dec, font=("Helvetica", 12), width=20)
        self.directory_button_dec.pack(pady=10)
        CreateToolTip(self.directory_button_dec, "Click to select the directory to monitor")

        self.label7 = tk.Label(self.decryption_frame, text="Select a key file:", font=("Helvetica", 12), bg="white")
        self.label7.pack()

        self.key_button_dec = tk.Button(self.decryption_frame, text="Select Key File", command=self.select_key_dec, font=("Helvetica", 12), width=20)
        self.key_button_dec.pack(pady=10)
        CreateToolTip(self.key_button_dec, "Click to select the key file")

        self.label8 = tk.Label(self.decryption_frame, text="Select trigger for decryption:", font=("Helvetica", 12), bg="white")
        self.label8.pack()

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

        self.observer = None
        self.observer_dec = None

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        self.encrypt_label.config(text=f"Selected Directory: {self.directory}")

    def select_key(self):
        self.key_file = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        self.encrypt_label.config(text=f"Selected Key File: {self.key_file}")

    def select_directory_dec(self):
        self.directory_dec = filedialog.askdirectory()
        self.decrypt_label.config(text=f"Selected Directory: {self.directory_dec}")

    def select_key_dec(self):
        self.key_file_dec = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        self.decrypt_label.config(text=f"Selected Key File: {self.key_file_dec}")

    def toggle_group_entry(self, value):
        if value == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.config(state=tk.DISABLED)

    def toggle_group_entry_dec(self, value):
        if value == "Group":
            self.group_paths_entry_dec.config(state=tk.NORMAL)
        else:
            self.group_paths_entry_dec.config(state=tk.DISABLED)

    def start_monitoring(self):
        if not hasattr(self, 'directory') or not hasattr(self, 'key_file'):
            messagebox.showerror("Error", "Please select both a directory and a key file before starting monitoring.")
            return

        self.key = open(self.key_file, "rb").read()
        self.groups = self.group_paths_entry.get().split(",") if self.encrypt_mode.get() == "Group" else None
        event_handler = EncryptionHandler(self.key, self.encrypt_trigger.get(), self.encrypt_mode.get(), self.directory, self.groups)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.directory, recursive=True)
        self.observer.start()

        self.encrypt_label.config(text="Encryption Handler Status: Monitoring")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

        self.encrypt_label.config(text="Encryption Handler Status: Idle")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def start_monitoring_dec(self):
        if not hasattr(self, 'directory_dec') or not hasattr(self, 'key_file_dec'):
            messagebox.showerror("Error", "Please select both a directory and a key file before starting monitoring.")
            return

        self.key_dec = open(self.key_file_dec, "rb").read()
        self.groups_dec = self.group_paths_entry_dec.get().split(",") if self.decrypt_mode.get() == "Group" else None
        event_handler_dec = DecryptionHandler(self.key_dec, self.decrypt_trigger.get(), self.decrypt_mode.get(), self.directory_dec, self.groups_dec)
        self.observer_dec = Observer()
        self.observer_dec.schedule(event_handler_dec, self.directory_dec, recursive=True)
        self.observer_dec.start()

        self.decrypt_label.config(text="Decryption Handler Status: Monitoring")
        self.start_button_dec.config(state=tk.DISABLED)
        self.stop_button_dec.config(state=tk.NORMAL)

    def stop_monitoring_dec(self):
        if self.observer_dec:
            self.observer_dec.stop()
            self.observer_dec.join()

        self.decrypt_label.config(text="Decryption Handler Status: Idle")
        self.start_button_dec.config(state=tk.NORMAL)
        self.stop_button_dec.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()