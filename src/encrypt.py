#!/usr/bin/env python3
"""
Decrypto - Modern File Encryption Tool
🔒 Secure AES-256-GCM encryption with adaptive UI
"""

import os
import sys
import json
import struct
import base64
import hashlib
import secrets
import string
from pathlib import Path
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Constants
MAGIC = b"DECRY2"
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 100000

class ModernEncryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Decrypto - Secure File Encryption")
        
        # Adaptive window size
        self.setup_window_size()
        self.root.configure(fg_color="#0f0f23")
        
        # Initialize variables
        self.selected_files = []
        self.setup_ui()
        
    def setup_window_size(self):
        """Setup adaptive window size based on screen resolution"""
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        if screen_width >= 2560:  # 1440p and above
            window_width, window_height = 1400, 800
        elif screen_width >= 1920:  # 1080p
            window_width, window_height = 1200, 700
        else:  # Lower resolutions
            window_width, window_height = 1000, 600
            
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.minsize(900, 500)
        
    def setup_ui(self):
        # Main container
        self.main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Header
        self.create_header()
        
        # Content area with responsive grid
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, pady=15)
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.columnconfigure(1, weight=1)
        self.content_frame.rowconfigure(0, weight=1)
        
        # Panels
        self.left_panel = ctk.CTkFrame(self.content_frame, corner_radius=12)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        
        self.right_panel = ctk.CTkFrame(self.content_frame, corner_radius=12)
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        
        # UI components
        self.create_file_section()
        self.create_options_section()
        self.create_actions_section()
        self.create_log_section()
        
        self.log("🚀 Decrypto initialized successfully!")
        self.log("💫 Ready to encrypt your files securely")
        
    def create_header(self):
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=60)
        header_frame.pack(fill="x", pady=(0, 10))
        header_frame.pack_propagate(False)
        
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(expand=True)
        
        ctk.CTkLabel(
            title_frame,
            text="🔒 DECRYPTO",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#8B5FBF"
        ).pack()
        
        ctk.CTkLabel(
            title_frame,
            text="Advanced File Encryption Tool",
            font=ctk.CTkFont(size=11),
            text_color="#888"
        ).pack(pady=(2, 0))
        
    def create_file_section(self):
        file_frame = ctk.CTkFrame(self.left_panel, corner_radius=10)
        file_frame.pack(fill="x", pady=(0, 10))
        
        # Section title
        ctk.CTkLabel(
            file_frame,
            text="📁 Files to Encrypt",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=15, pady=(12, 8))
        
        # Drop area
        drop_frame = ctk.CTkFrame(
            file_frame, 
            corner_radius=8,
            fg_color="#1a1a2e",
            border_width=2,
            border_color="#8B5FBF"
        )
        drop_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(
            drop_frame,
            text="🎯 Drag & Drop Files/Folders Here\nor Use Browse Buttons",
            font=ctk.CTkFont(size=10),
            text_color="#aaa",
            justify="center"
        ).pack(pady=15)
        
        # Browse buttons
        button_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkButton(
            button_frame,
            text="📁 Browse Files",
            command=self.browse_files,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            height=30
        ).pack(side="left", padx=(0, 5))
        
        ctk.CTkButton(
            button_frame,
            text="📂 Browse Folder",
            command=self.browse_folder,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            height=30
        ).pack(side="left", padx=(0, 5))
        
        ctk.CTkButton(
            button_frame,
            text="🗑️ Clear",
            command=self.clear_files,
            fg_color="#555",
            hover_color="#666",
            height=30
        ).pack(side="left")
        
        # File list
        list_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        list_frame.pack(fill="both", expand=True, padx=15, pady=(0, 12))
        
        ctk.CTkLabel(list_frame, text="Selected Files:", font=ctk.CTkFont(size=11)).pack(anchor="w")
        
        self.file_listbox = ctk.CTkTextbox(
            list_frame,
            height=70,
            fg_color="#1a1a2e",
            border_width=1,
            border_color="#333",
            font=ctk.CTkFont(family="Consolas", size=10)
        )
        self.file_listbox.pack(fill="both", pady=(3, 0))
        
    def create_options_section(self):
        options_frame = ctk.CTkFrame(self.left_panel, corner_radius=10)
        options_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(
            options_frame,
            text="⚙️ Encryption Options",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=15, pady=(12, 8))
        
        # Password section
        password_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        password_frame.pack(fill="x", padx=15, pady=8)
        
        ctk.CTkLabel(password_frame, text="Encryption Password:", font=ctk.CTkFont(size=11)).pack(anchor="w")
        
        pass_input_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        pass_input_frame.pack(fill="x", pady=(5, 0))
        
        self.password_entry = ctk.CTkEntry(
            pass_input_frame,
            placeholder_text="Enter strong password...",
            show="•",
            height=34,
            fg_color="#1a1a2e",
            border_color="#8B5FBF"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        
        ctk.CTkButton(
            pass_input_frame,
            text="🎲 Generate",
            command=self.generate_password,
            width=80,
            height=34,
            fg_color="#FF6B9D",
            hover_color="#E55A8A",
            font=ctk.CTkFont(size=10)
        ).pack(side="right")
        
        # Options
        options_grid = ctk.CTkFrame(options_frame, fg_color="transparent")
        options_grid.pack(fill="x", padx=15, pady=10)
        
        self.delete_var = ctk.BooleanVar(value=False)
        self.compression_var = ctk.BooleanVar(value=True)
        self.metadata_var = ctk.BooleanVar(value=True)
        
        ctk.CTkCheckBox(
            options_grid,
            text="🗑️ Delete originals after encryption",
            variable=self.delete_var,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            font=ctk.CTkFont(size=11)
        ).pack(anchor="w", pady=3)
        
        ctk.CTkCheckBox(
            options_grid,
            text="🗜️ Enable compression",
            variable=self.compression_var,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            font=ctk.CTkFont(size=11)
        ).pack(anchor="w", pady=3)
        
        ctk.CTkCheckBox(
            options_grid,
            text="📊 Preserve file metadata",
            variable=self.metadata_var,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            font=ctk.CTkFont(size=11)
        ).pack(anchor="w", pady=3)
        
    def create_actions_section(self):
        actions_frame = ctk.CTkFrame(self.left_panel, corner_radius=10)
        actions_frame.pack(fill="x")
        
        action_buttons = ctk.CTkFrame(actions_frame, fg_color="transparent")
        action_buttons.pack(fill="x", padx=15, pady=15)
        
        # Main encrypt button
        self.encrypt_btn = ctk.CTkButton(
            action_buttons,
            text="🔒 ENCRYPT FILES",
            command=self.encrypt_files,
            height=42,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            corner_radius=20
        )
        self.encrypt_btn.pack(fill="x", pady=(0, 8))
        
        # Secondary buttons
        secondary_frame = ctk.CTkFrame(action_buttons, fg_color="transparent")
        secondary_frame.pack(fill="x")
        
        ctk.CTkButton(
            secondary_frame,
            text="📂 Open Output Folder",
            command=self.open_output_folder,
            height=32,
            fg_color="#444",
            hover_color="#555"
        ).pack(side="left", padx=(0, 5))
        
        ctk.CTkButton(
            secondary_frame,
            text="❓ Help",
            command=self.show_help,
            height=32,
            fg_color="#444",
            hover_color="#555"
        ).pack(side="right")
        
    def create_log_section(self):
        log_frame = ctk.CTkFrame(self.right_panel, corner_radius=10)
        log_frame.pack(fill="both", expand=True)
        
        ctk.CTkLabel(
            log_frame,
            text="📝 Activity Log",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=15, pady=(12, 8))
        
        # Log text area
        self.log_text = ctk.CTkTextbox(
            log_frame,
            fg_color="#1a1a2e",
            border_width=1,
            border_color="#333",
            font=ctk.CTkFont(family="Consolas", size=10),
            wrap="word"
        )
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Status bar
        self.status_var = ctk.StringVar(value="🟢 Ready to encrypt files")
        status_label = ctk.CTkLabel(
            log_frame,
            textvariable=self.status_var,
            font=ctk.CTkFont(size=10),
            text_color="#8B5FBF"
        )
        status_label.pack(anchor="w", padx=15, pady=(0, 12))
    
    def browse_files(self):
        files = filedialog.askopenfilenames(title="Select files to encrypt")
        for file in files:
            if file not in self.selected_files:
                self.selected_files.append(file)
        if files:
            self.update_file_list()
            self.log(f"📁 Added {len(files)} file(s)")
            self.update_status(f"📁 {len(files)} files selected")
    
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select folder to encrypt")
        if folder and folder not in self.selected_files:
            self.selected_files.append(folder)
            self.update_file_list()
            self.log(f"📂 Added folder: {Path(folder).name}")
            self.update_status("📁 Folder selected")
    
    def update_file_list(self):
        self.file_listbox.delete("1.0", "end")
        for file in self.selected_files:
            display_name = Path(file).name
            if Path(file).is_dir():
                display_name = f"[Folder] {display_name}"
            self.file_listbox.insert("end", f"• {display_name}\n")
    
    def clear_files(self):
        self.selected_files.clear()
        self.file_listbox.delete("1.0", "end")
        self.log("🗑️ File list cleared")
        self.update_status("🗑️ File list cleared")
    
    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        self.log("🎲 Generated strong password")
        self.update_status("🔑 Password generated")
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.root.update()
    
    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()
    
    def derive_key(self, password, salt):
        return PBKDF2(password.encode(), salt, KEY_SIZE, PBKDF2_ITERATIONS)
    
    def encrypt_files(self):
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select files or folders to encrypt.")
            return
        
        password = self.password_entry.get().strip()
        if not password:
            messagebox.showwarning("No Password", "Please enter an encryption password.")
            return
        
        output_file = filedialog.asksaveasfilename(
            defaultextension=".decry",
            filetypes=[("Decrypto Container", "*.decry"), ("All files", "*.*")]
        )
        if not output_file:
            return
        
        try:
            self.update_status("🔐 Starting encryption...")
            self.log("🔐 Starting encryption process...")
            
            salt = get_random_bytes(SALT_SIZE)
            key = self.derive_key(password, salt)
            
            all_files = self.gather_files(self.selected_files)
            if not all_files:
                messagebox.showinfo("No Files", "No valid files found to encrypt.")
                return
            
            self.log(f"📦 Found {len(all_files)} file(s) to encrypt")
            
            self.create_container(key, salt, all_files, output_file)
            
            key_file = output_file + '.key'
            with open(key_file, 'w') as f:
                f.write(base64.b64encode(key).decode())
            
            self.log(f"✅ Encryption successful!")
            self.log(f"📁 Output: {Path(output_file).name}")
            self.log(f"🔑 Key saved: {Path(key_file).name}")
            self.update_status("✅ Encryption completed!")
            
            self.show_success_dialog(output_file, key_file)
            
            if self.delete_var.get():
                self.delete_originals(all_files)
                
        except Exception as e:
            self.log(f"❌ Encryption failed: {str(e)}")
            self.update_status("❌ Encryption failed")
            messagebox.showerror("Encryption Error", f"Encryption failed:\n{str(e)}")
    
    def gather_files(self, paths):
        all_files = []
        for path_str in paths:
            path = Path(path_str)
            if path.is_file():
                all_files.append(path)
            elif path.is_dir():
                for file_path in path.rglob('*'):
                    if file_path.is_file():
                        all_files.append(file_path)
        return all_files
    
    def create_container(self, key, salt, files, output_path):
        metadata = {
            'version': 2,
            'created': datetime.now().isoformat(),
            'file_count': len(files),
            'files': [str(f) for f in files],
            'compression': self.compression_var.get()
        }
        
        with open(output_path, 'wb') as out_file:
            out_file.write(MAGIC)
            out_file.write(salt)
            
            metadata_json = json.dumps(metadata).encode('utf-8')
            encrypted_metadata = self.encrypt_data(key, metadata_json)
            out_file.write(struct.pack('>Q', len(encrypted_metadata)))
            out_file.write(encrypted_metadata)
            
            for file_path in files:
                self.log(f"🔒 Encrypting: {file_path.name}")
                file_data = file_path.read_bytes()
                
                if self.compression_var.get():
                    import zlib
                    file_data = zlib.compress(file_data)
                
                encrypted_data = self.encrypt_data(key, file_data)
                out_file.write(struct.pack('>Q', len(encrypted_data)))
                out_file.write(encrypted_data)
    
    def encrypt_data(self, key, data):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext
    
    def delete_originals(self, files):
        deleted_count = 0
        for file_path in files:
            try:
                file_path.unlink()
                deleted_count += 1
                self.log(f"🗑️ Deleted: {file_path.name}")
            except Exception as e:
                self.log(f"⚠️ Could not delete {file_path.name}: {e}")
        self.log(f"🗑️ Deleted {deleted_count} original file(s)")
    
    def show_success_dialog(self, output_file, key_file):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("✅ Encryption Successful")
        dialog.geometry("450x280")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        ctk.CTkLabel(
            dialog,
            text="🎉 Encryption Completed!",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#8B5FBF"
        ).pack(pady=15)
        
        info_frame = ctk.CTkFrame(dialog, corner_radius=8)
        info_frame.pack(fill="both", expand=True, padx=15, pady=5)
        
        ctk.CTkLabel(
            info_frame,
            text=f"📁 Output: {Path(output_file).name}",
            font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=15, pady=(15, 3))
        
        ctk.CTkLabel(
            info_frame,
            text=f"🔑 Key: {Path(key_file).name}",
            font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=15, pady=3)
        
        warning_label = ctk.CTkLabel(
            info_frame,
            text="⚠️ Save the key file securely! Without it, your files cannot be recovered.",
            font=ctk.CTkFont(size=10),
            text_color="#FF6B9D",
            wraplength=380
        )
        warning_label.pack(anchor="w", padx=15, pady=10)
        
        ctk.CTkButton(
            dialog,
            text="OK",
            command=dialog.destroy,
            height=32,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8"
        ).pack(pady=15)
    
    def open_output_folder(self):
        output_dir = filedialog.askdirectory(title="Select Output Folder")
        if output_dir:
            if sys.platform == "win32":
                os.startfile(output_dir)
            elif sys.platform == "darwin":
                os.system(f'open "{output_dir}"')
            else:
                os.system(f'xdg-open "{output_dir}"')
    
    def show_help(self):
        help_text = """
🔒 DECRYPTO - HOW TO USE

ENCRYPTION:
1. Add files/folders using Browse or Drag & Drop
2. Set a strong encryption password
3. Choose encryption options
4. Click 'ENCRYPT FILES'
5. Save the .decry container and .key file securely

SECURITY FEATURES:
• AES-256-GCM military-grade encryption
• PBKDF2 key derivation for password protection
• Salted hashing for additional security
• File integrity verification

IMPORTANT:
• Never lose your encryption key!
• Keep backups of important files
• Use strong, unique passwords
"""
        messagebox.showinfo("Decrypto Help", help_text)

def main():
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    root = ctk.CTk()
    app = ModernEncryptApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()