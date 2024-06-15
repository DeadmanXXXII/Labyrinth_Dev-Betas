import tkinter as tk
from tkinter import filedialog, messagebox
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import os
from PIL import Image, ImageTk

# Set up logging
logging.basicConfig(filename='encryption_tool.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        try:
            if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
                self.encrypt_file(file_path)
            elif self.mode == "All":
                self.encrypt_all_files()
        except Exception as e:
            logging.error(f"Error encrypting file {file_path}: {str(e)}")

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
        for root, _, files in os.walk(self.directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if not file_path.endswith(".encrypted"):
                    self.encrypt_file(file_path)

# DecryptionHandler class definition
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
        try:
            if self.mode == "Individual" or (self.mode == "Group" and self.is_group(file_path)):
                self.decrypt_file(file_path)
            elif self.mode == "All":
                self.decrypt_all_files()
        except Exception as e:
            logging.error(f"Error decrypting file {file_path}: {str(e)}")

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
        for root, _, files in os.walk(self.directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if file_path.endswith(".encrypted"):
                    self.decrypt_file(file_path)

# EncryptionApp class definition
class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Labyrinth - Encryption & Decryption")

        self.encryption_frame = tk.Frame(master)
        self.encryption_frame.pack(side="left", padx=20, pady=(20, 10))

        self.label1 = tk.Label(self.encryption_frame, text="Select a directory to monitor:", font=("Helvetica", 12))
        self.label1.pack()

        self.directory_button = tk.Button(self.encryption_frame, text="Select Directory", command=self.select_directory, font=("Helvetica", 12), width=20)
        self.directory_button.pack(pady=10)
        CreateToolTip(self.directory_button, "Click to select the directory to monitor")

        self.label2 = tk.Label(self.encryption_frame, text="Select a key file:", font=("Helvetica", 12))
        self.label2.pack()

        self.key_button = tk.Button(self.encryption_frame, text="Select Key File", command=self.select_key, font=("Helvetica", 12), width=20)
        self.key_button.pack(pady=10)
        CreateToolTip(self.key_button, "Click to select the key file")

        self.label3 = tk.Label(self.encryption_frame, text="Select trigger for encryption:", font=("Helvetica", 12))
        self.label3.pack()

        self.encrypt_trigger = tk.StringVar()
        self.encrypt_trigger.set("Create")
        self.encrypt_trigger_menu = tk.OptionMenu(self.encryption_frame, self.encrypt_trigger, "Create", "Delete", "Modify")
        self.encrypt_trigger_menu.config(font=("Helvetica", 12), width=17)
        self.encrypt_trigger_menu.pack(pady=10)
        CreateToolTip(self.encrypt_trigger_menu, "Select when encryption should trigger")

        self.label4 = tk.Label(self.encryption_frame, text="Select encryption mode:", font=("Helvetica", 12))
        self.label4.pack()

        self.encrypt_mode = tk.StringVar()
        self.encrypt_mode.set("Individual")
        self.encrypt_mode_menu = tk.OptionMenu(self.encryption_frame, self.encrypt_mode, "Individual", "Group", "All", command=self.toggle_group_entry)
        self.encrypt_mode_menu.config(font=("Helvetica", 12), width=17)
        self.encrypt_mode_menu.pack(pady=10)
        CreateToolTip(self.encrypt_mode_menu, "Select how files should be encrypted")

        self.label5 = tk.Label(self.encryption_frame, text="Enter group paths (comma-separated):", font=("Helvetica", 12))
        self.label5.pack()

        self.group_paths_entry = tk.Entry(self.encryption_frame, width=50, font=("Helvetica", 12))
        self.group_paths_entry.pack(pady=10)
        self.group_paths_entry.config(state=tk.DISABLED)
        CreateToolTip(self.group_paths_entry, "Enter paths for group encryption (comma-separated)")

        self.encrypt_label = tk.Label(self.encryption_frame, text="Encryption Handler Status: Idle", font=("Helvetica", 12))
        self.encrypt_label.pack(pady=10)

        self.start_button = tk.Button(self.encryption_frame, text="Start Monitoring", command=self.start_monitoring, font=("Helvetica", 12), width=20)
        self.start_button.pack(pady=10)
        CreateToolTip(self.start_button, "Start monitoring the selected directory for encryption")

        self.stop_button = tk.Button(self.encryption_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED, font=("Helvetica", 12), width=20)
        self.stop_button.pack(pady=10)
        CreateToolTip(self.stop_button, "Stop monitoring the selected directory")

        # Load and display background image
        self.load_background_image()

    def toggle_group_entry(self, mode):
        if mode == "Group":
            self.group_paths_entry.config(state=tk.NORMAL)
        else:
            self.group_paths_entry.delete(0, tk.END)
            self.group_paths_entry.config(state=tk.DISABLED)

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        logging.info(f"Selected directory: {self.directory}")

    def select_key(self):
        key_file = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if key_file:
            with open(key_file, "rb") as f:
                self.key = f.read()
            logging.info("Key file selected")

    def start_monitoring(self):
        try:
            trigger = self.encrypt_trigger.get()
            mode = self.encrypt_mode.get()
            groups = [group.strip() for group in self.group_paths_entry.get().split(",")] if self.group_paths_entry.get() else []
            
            if not hasattr(self, 'directory') or not hasattr(self, 'key'):
                messagebox.showerror("Error", "Please select directory and key file.")
                return
            
            handler = EncryptionHandler(self.key, trigger, mode, self.directory, groups)
            observer = Observer()
            observer.schedule(handler, path=self.directory if mode != "Group" else "/", recursive=True)
            observer.start()
            
            self.encrypt_label.config(text=f"Encryption Handler Status: Monitoring {self.directory}")
            self.directory_button.config(state=tk.DISABLED)
            self.key_button.config(state=tk.DISABLED)
            self.encrypt_trigger_menu.config(state=tk.DISABLED)
            self.encrypt_mode_menu.config(state=tk.DISABLED)
            self.group_paths_entry.config(state=tk.DISABLED)
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL, command=lambda: self.stop_monitoring(observer))
        
        except Exception as e:
            logging.error(f"Error starting monitoring: {str(e)}")
            messagebox.showerror("Error", f"Error starting monitoring: {str(e)}")

    def stop_monitoring(self, observer=None):
        try:
            if observer and isinstance(observer, Observer):
                observer.stop()
                observer.join()
            self.encrypt_label.config(text="Encryption Handler Status: Idle")
            self.directory_button.config(state=tk.NORMAL)
            self.key_button.config(state=tk.NORMAL)
            self.encrypt_trigger_menu.config(state=tk.NORMAL)
            self.encrypt_mode_menu.config(state=tk.NORMAL)
            self.group_paths_entry.config(state=tk.NORMAL)
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
        except Exception as e:
            logging.error(f"Error stopping monitoring: {str(e)}")
            messagebox.showerror("Error", f"Error stopping monitoring: {str(e)}")

    def load_background_image(self):
        try:
            background_path = r"C:\Users\bluco\Downloads\background_image.png"
            img = Image.open(background_path)
            img = img.resize((400, 400), Image.ANTIALIAS)  # Resize image to fit the window
            img = ImageTk.PhotoImage(img)

            panel = tk.Label(self.master, image=img)
            panel.image = img  # Keep a reference to avoid garbage collection
            panel.pack(side="right", fill="both", expand="yes")
        except Exception as e:
            logging.error(f"Error loading background image: {str(e)}")
            messagebox.showwarning("Warning", "Failed to load background image. Check file path.")

# Main function
def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
