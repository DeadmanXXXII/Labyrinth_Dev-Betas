import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import os

class CreateToolTip(object):
    """
    Create a tooltip for a given widget.
    """
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.tw = None

    def enter(self, event=None):
        x = y = 0
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tw, text=self.text, justify='left',
                         background="#ffffe0", relief='solid', borderwidth=1,
                         font=("tahoma", "10", "normal"))
        label.pack(ipadx=1)

    def leave(self, event=None):
        if self.tw:
            self.tw.destroy()

class EncryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups=None):
        self.key = key
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups
        self.fernet = Fernet(self.key)

    def on_any_event(self, event):
        if event.event_type == self.trigger.lower():
            if self.mode == "Individual":
                self.encrypt_file(event.src_path)
            elif self.mode == "Group" and self.groups:
                for group in self.groups:
                    if os.path.commonpath([event.src_path, group]) == group:
                        self.encrypt_file(event.src_path)
            elif self.mode == "All":
                self.encrypt_file(event.src_path)

    def encrypt_file(self, file_path):
        if os.path.isfile(file_path):
            with open(file_path, "rb") as file:
                file_data = file.read()
            encrypted_data = self.fernet.encrypt(file_data)
            with open(file_path, "wb") as file:
                file.write(encrypted_data)

class DecryptionHandler(FileSystemEventHandler):
    def __init__(self, key, trigger, mode, directory, groups=None):
        self.key = key
        self.trigger = trigger
        self.mode = mode
        self.directory = directory
        self.groups = groups
        self.fernet = Fernet(self.key)

    def on_any_event(self, event):
        if event.event_type == self.trigger.lower():
            if self.mode == "Individual":
                self.decrypt_file(event.src_path)
            elif self.mode == "Group" and self.groups:
                for group in self.groups:
                    if os.path.commonpath([event.src_path, group]) == group:
                        self.decrypt_file(event.src_path)
            elif self.mode == "All":
                self.decrypt_file(event.src_path)

    def decrypt_file(self, file_path):
        if os.path.isfile(file_path):
            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            with open(file_path, "wb") as file:
                file.write(decrypted_data)

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryption & Decryption App")
        self.master.geometry("800x600")

        self.background_image_path = r"C:\Users\bluco\Downloads\background_image.png"
        self.background_image = Image.open(self.background_image_path)
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.background_label = tk.Label(master, image=self.background_photo)
        self.background_label.place(relwidth=1, relheight=1)

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

        self.directory = None
        self.key = None
        self.directory_dec = None
        self.key_dec = None
        self.encrypt_observer = None
        self.decrypt_observer = None

    def toggle_group_entry(self, *args):
        if self.encrypt_mode.get() == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.config(state=tk.DISABLED)

    def toggle_group_entry_dec(self, *args):
        if self.decrypt_mode.get() == "Group":
            self.group_paths_entry_dec.config(state=tk.NORMAL)
        else:
            self.group_paths_entry_dec.config(state=tk.DISABLED)

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        if self.directory:
            messagebox.showinfo("Selected Directory", f"Selected directory: {self.directory}")

    def select_key(self):
        key_file = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if key_file:
            with open(key_file, "rb") as f:
                self.key = f.read()
            messagebox.showinfo("Selected Key", f"Selected key file: {key_file}")

    def select_directory_dec(self):
        self.directory_dec = filedialog.askdirectory()
        if self.directory_dec:
            messagebox.showinfo("Selected Directory", f"Selected directory: {self.directory_dec}")

    def select_key_dec(self):
        key_file = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if key_file:
            with open(key_file, "rb") as f:
                self.key_dec = f.read()
            messagebox.showinfo("Selected Key", f"Selected key file: {key_file}")

    def start_monitoring(self):
        if not self.directory or not self.key:
            messagebox.showerror("Error", "Please select both a directory and a key file before starting.")
            return

        if self.encrypt_mode.get() == "Group":
            groups = [group.strip() for group in self.group_paths_entry.get().split(',')]
        else:
            groups = None

        handler = EncryptionHandler(self.key, self.encrypt_trigger.get(), self.encrypt_mode.get(), self.directory, groups)
        self.encrypt_observer = Observer()
        self.encrypt_observer.schedule(handler, self.directory, recursive=True)
        self.encrypt_observer.start()

        self.encrypt_label.config(text="Encryption Handler Status: Active")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_monitoring(self):
        if self.encrypt_observer:
            self.encrypt_observer.stop()
            self.encrypt_observer.join()

        self.encrypt_label.config(text="Encryption Handler Status: Idle")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def start_monitoring_dec(self):
        if not self.directory_dec or not self.key_dec:
            messagebox.showerror("Error", "Please select both a directory and a key file before starting.")
            return

        if self.decrypt_mode.get() == "Group":
            groups = [group.strip() for group in self.group_paths_entry_dec.get().split(',')]
        else:
            groups = None

        handler = DecryptionHandler(self.key_dec, self.decrypt_trigger.get(), self.decrypt_mode.get(), self.directory_dec, groups)
        self.decrypt_observer = Observer()
        self.decrypt_observer.schedule(handler, self.directory_dec, recursive=True)
        self.decrypt_observer.start()

        self.decrypt_label.config(text="Decryption Handler Status: Active")
        self.start_button_dec.config(state=tk.DISABLED)
        self.stop_button_dec.config(state=tk.NORMAL)

    def stop_monitoring_dec(self):
        if self.decrypt_observer:
            self.decrypt_observer.stop()
            self.decrypt_observer.join()

        self.decrypt_label.config(text="Decryption Handler Status: Idle")
        self.start_button_dec.config(state=tk.NORMAL)
        self.stop_button_dec.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
