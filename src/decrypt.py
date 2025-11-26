#!/usr/bin/env python3
"""
Decrypto - Modern File Decryption Tool
🔓 Secure decryption for .decry containers with beautiful UI
"""

import os
import sys
import json
import struct
import base64
import zlib
from pathlib import Path
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


# Constants
MAGIC = b"DECRY2"
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 100000

# Configure appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ModernDecryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔓 Decrypto - Secure File Decryption")
        self.root.geometry("1400x1000")
        self.root.configure(fg_color="#0f0f23")
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        self.main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        self.create_header()
        
        # Content area
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, pady=20)
        
        # Left panel - Controls
        self.left_panel = ctk.CTkFrame(self.content_frame, corner_radius=15)
        self.left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # Right panel - Preview & Log
        self.right_panel = ctk.CTkFrame(self.content_frame, corner_radius=15)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=(10, 0))
        
        # Build UI
        self.create_input_section()
        self.create_preview_section()
        self.create_log_section()
        
        
        
        self.log("🚀 Decrypto Decoder initialized!")
        self.log("💫 Drop a .decry container to begin...")
        
    def create_header(self):
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=80)
        header_frame.pack(fill="x", pady=(0, 20))
        header_frame.pack_propagate(False)
        
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(expand=True)
        
        ctk.CTkLabel(
            title_frame,
            text="🔓 DECRYPTO DECODER",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#8B5FBF"
        ).pack()
        
        ctk.CTkLabel(
            title_frame,
            text="Secure File Decryption Tool",
            font=ctk.CTkFont(size=14),
            text_color="#888"
        ).pack(pady=(5, 0))
        
    def create_input_section(self):
        # Container selection
        container_frame = ctk.CTkFrame(self.left_panel, corner_radius=12)
        container_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            container_frame,
            text="📦 Encrypted Container",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 10))
        
        self.container_var = ctk.StringVar()
        container_entry = ctk.CTkEntry(
            container_frame,
            textvariable=self.container_var,
            placeholder_text="Select .decry container file...",
            height=40,
            fg_color="#1a1a2e",
            border_color="#8B5FBF"
        )
        container_entry.pack(fill="x", padx=20, pady=(0, 10))
        
        ctk.CTkButton(
            container_frame,
            text="📁 Browse Container",
            command=self.browse_container,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            height=35
        ).pack(anchor="w", padx=20, pady=(0, 15))
        
        # Key input
        key_frame = ctk.CTkFrame(self.left_panel, corner_radius=12)
        key_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            key_frame,
            text="🔑 Decryption Key",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 10))
        
        ctk.CTkLabel(key_frame, text="Password or Key File:").pack(anchor="w", padx=20, pady=(0, 5))
        
        self.key_var = ctk.StringVar()
        self.key_entry = ctk.CTkEntry(
            key_frame,
            textvariable=self.key_var,
            placeholder_text="Enter password or load key file...",
            show="•",
            height=40,
            fg_color="#1a1a2e",
            border_color="#8B5FBF"
        )
        self.key_entry.pack(fill="x", padx=20, pady=(0, 10))
        
        key_button_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        key_button_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        ctk.CTkButton(
            key_button_frame,
            text="📁 Load Key File",
            command=self.load_key_file,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            height=35
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            key_button_frame,
            text="👁️ Show Password",
            command=self.toggle_password_visibility,
            fg_color="#555",
            hover_color="#666",
            height=35
        ).pack(side="left")
        
        # Output location
        output_frame = ctk.CTkFrame(self.left_panel, corner_radius=12)
        output_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            output_frame,
            text="📂 Output Location",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 10))
        
        self.output_var = ctk.StringVar(value=os.path.expanduser("~/Decrypted"))
        output_entry = ctk.CTkEntry(
            output_frame,
            textvariable=self.output_var,
            height=40,
            fg_color="#1a1a2e",
            border_color="#8B5FBF"
        )
        output_entry.pack(fill="x", padx=20, pady=(0, 10))
        
        ctk.CTkButton(
            output_frame,
            text="📁 Browse Output Folder",
            command=self.browse_output,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            height=35
        ).pack(anchor="w", padx=20, pady=(0, 15))
        
        # Action buttons
        action_frame = ctk.CTkFrame(self.left_panel, corner_radius=12)
        action_frame.pack(fill="x")
        
        action_buttons = ctk.CTkFrame(action_frame, fg_color="transparent")
        action_buttons.pack(fill="x", padx=20, pady=20)
        
        # Analyze button
        ctk.CTkButton(
            action_buttons,
            text="🔍 ANALYZE CONTAINER",
            command=self.analyze_container,
            height=45,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#FF6B9D",
            hover_color="#E55A8A",
            corner_radius=22
        ).pack(fill="x", pady=(0, 10))
        
        # Decrypt button
        self.decrypt_btn = ctk.CTkButton(
            action_buttons,
            text="🔓 DECRYPT FILES",
            command=self.decrypt_files,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#8B5FBF",
            hover_color="#7A4FA8",
            corner_radius=25
        )
        self.decrypt_btn.pack(fill="x", pady=(0, 10))
        
        # Help button
        ctk.CTkButton(
            action_buttons,
            text="❓ Help",
            command=self.show_help,
            height=40,
            fg_color="#444",
            hover_color="#555"
        ).pack(fill="x")
        
    def create_preview_section(self):
        preview_frame = ctk.CTkFrame(self.right_panel, corner_radius=12)
        preview_frame.pack(fill="both", expand=True, pady=(0, 15))
        
        ctk.CTkLabel(
            preview_frame,
            text="👁️ Container Preview",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 10))
        
        self.preview_text = ctk.CTkTextbox(
            preview_frame,
            fg_color="#1a1a2e",
            border_width=1,
            border_color="#333",
            font=ctk.CTkFont(family="Consolas", size=11)
        )
        self.preview_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.preview_text.configure(state="disabled")
        
    def create_log_section(self):
        log_frame = ctk.CTkFrame(self.right_panel, corner_radius=12)
        log_frame.pack(fill="both", expand=True)
        
        ctk.CTkLabel(
            log_frame,
            text="📝 Decryption Log",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 10))
        
        self.log_text = ctk.CTkTextbox(
            log_frame,
            fg_color="#1a1a2e",
            border_width=1,
            border_color="#333",
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word"
        )
        self.log_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Status bar
        self.status_var = ctk.StringVar(value="🟢 Ready to decrypt files")
        status_label = ctk.CTkLabel(
            log_frame,
            textvariable=self.status_var,
            font=ctk.CTkFont(size=11),
            text_color="#8B5FBF"
        )
        status_label.pack(anchor="w", padx=20, pady=(0, 15))
    
    def on_drop(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            container_path = files[0]
            if container_path.endswith('.decry'):
                self.container_var.set(container_path)
                self.log(f"📥 Container loaded: {Path(container_path).name}")
                self.update_status("📁 Container loaded via drag & drop")
                self.analyze_container()
    
    def browse_container(self):
        container_path = filedialog.askopenfilename(
            filetypes=[("Decrypto Container", "*.decry"), ("All files", "*.*")]
        )
        if container_path:
            self.container_var.set(container_path)
            self.log(f"📁 Container selected: {Path(container_path).name}")
            self.update_status("📁 Container selected")
            self.analyze_container()
    
    def load_key_file(self):
        key_path = filedialog.askopenfilename(
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if key_path:
            try:
                with open(key_path, 'r') as f:
                    key_data = f.read().strip()
                    self.key_var.set(key_data)
                self.log(f"🔑 Key loaded: {Path(key_path).name}")
                self.update_status("🔑 Key file loaded")
            except Exception as e:
                self.log(f"❌ Failed to load key file: {e}")
                self.update_status("❌ Failed to load key")
    
    def toggle_password_visibility(self):
        current_show = self.key_entry.cget('show')
        if current_show == '•':
            self.key_entry.configure(show='')
        else:
            self.key_entry.configure(show='•')
    
    def browse_output(self):
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if output_dir:
            self.output_var.set(output_dir)
            self.log(f"📂 Output directory: {output_dir}")
            self.update_status("📂 Output directory set")
    
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
    
    def analyze_container(self):
        container_path = self.container_var.get().strip()
        if not container_path or not Path(container_path).exists():
            messagebox.showwarning("Invalid Container", "Please select a valid .decry container file.")
            return
        
        try:
            with open(container_path, 'rb') as f:
                magic = f.read(len(MAGIC))
                if magic != MAGIC:
                    messagebox.showerror("Invalid Container", "This is not a valid Decrypto container.")
                    return
                
                salt = f.read(SALT_SIZE)
                metadata_len = struct.unpack('>Q', f.read(8))[0]
                encrypted_metadata = f.read(metadata_len)
            
            # Update preview
            self.preview_text.configure(state="normal")
            self.preview_text.delete("1.0", "end")
            self.preview_text.insert("end", "🔍 CONTAINER ANALYSIS\n")
            self.preview_text.insert("end", "═" * 50 + "\n\n")
            self.preview_text.insert("end", f"• Format: Decrypto v2\n")
            self.preview_text.insert("end", f"• File: {Path(container_path).name}\n")
            self.preview_text.insert("end", f"• Size: {Path(container_path).stat().st_size:,} bytes\n")
            self.preview_text.insert("end", f"• Metadata: {len(encrypted_metadata):,} bytes\n\n")
            self.preview_text.insert("end", "⚠️ Enter decryption key to view contents\n")
            self.preview_text.configure(state="disabled")
            
            self.log("🔍 Container analyzed successfully")
            self.update_status("🔍 Container analyzed")
            
        except Exception as e:
            self.log(f"❌ Container analysis failed: {e}")
            self.update_status("❌ Analysis failed")
            messagebox.showerror("Analysis Error", f"Failed to analyze container:\n{str(e)}")
    
    def decrypt_files(self):
        container_path = self.container_var.get().strip()
        key_input = self.key_var.get().strip()
        output_dir = self.output_var.get().strip()
        
        if not container_path:
            messagebox.showwarning("No Container", "Please select a .decry container file.")
            return
        
        if not key_input:
            messagebox.showwarning("No Key", "Please enter decryption password or load key file.")
            return
        
        if not output_dir:
            messagebox.showwarning("No Output", "Please select output directory.")
            return
        
        try:
            self.update_status("🔓 Starting decryption...")
            self.log("🔓 Starting decryption process...")
            
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            with open(container_path, 'rb') as f:
                magic = f.read(len(MAGIC))
                if magic != MAGIC:
                    raise ValueError("Invalid container format")
                
                salt = f.read(SALT_SIZE)
                
                try:
                    key = base64.b64decode(key_input)
                    if len(key) != KEY_SIZE:
                        raise ValueError("Invalid key length")
                except:
                    key = self.derive_key(key_input, salt)
                
                metadata_len = struct.unpack('>Q', f.read(8))[0]
                encrypted_metadata = f.read(metadata_len)
                metadata = self.decrypt_data(key, encrypted_metadata)
                metadata = json.loads(metadata.decode('utf-8'))
                
                self.log(f"📦 Container contains {metadata['file_count']} file(s)")
                
                # Update preview with detailed info
                self.preview_text.configure(state="normal")
                self.preview_text.delete("1.0", "end")
                self.preview_text.insert("end", "📁 CONTAINER CONTENTS\n")
                self.preview_text.insert("end", "═" * 50 + "\n\n")
                self.preview_text.insert("end", f"• Created: {metadata['created']}\n")
                self.preview_text.insert("end", f"• Files: {metadata['file_count']}\n")
                self.preview_text.insert("end", f"• Compression: {metadata['compression']}\n\n")
                self.preview_text.insert("end", "FILE LIST:\n")
                self.preview_text.insert("end", "─" * 30 + "\n")
                for file_path in metadata['files']:
                    self.preview_text.insert("end", f"📄 {Path(file_path).name}\n")
                self.preview_text.configure(state="disabled")
                
                success_count = 0
                for i, original_path in enumerate(metadata['files']):
                    try:
                        chunk_len = struct.unpack('>Q', f.read(8))[0]
                        encrypted_data = f.read(chunk_len)
                        
                        file_data = self.decrypt_data(key, encrypted_data)
                        
                        if metadata.get('compression', False):
                            file_data = zlib.decompress(file_data)
                        
                        output_file = output_path / Path(original_path).name
                        counter = 1
                        original_output = output_file
                        while output_file.exists():
                            stem = original_output.stem
                            suffix = original_output.suffix
                            output_file = original_output.parent / f"{stem}_{counter}{suffix}"
                            counter += 1
                        
                        output_file.write_bytes(file_data)
                        success_count += 1
                        self.log(f"✅ Decrypted: {output_file.name}")
                        
                    except Exception as e:
                        self.log(f"❌ Failed to decrypt {Path(original_path).name}: {e}")
                
                self.log(f"🎉 Decryption completed! {success_count}/{metadata['file_count']} files restored")
                self.update_status("✅ Decryption completed!")
                
                self.show_success_summary(success_count, metadata['file_count'], output_path)
                
        except Exception as e:
            self.log(f"❌ Decryption failed: {str(e)}")
            self.update_status("❌ Decryption failed")
            messagebox.showerror("Decryption Error", f"Decryption failed:\n{str(e)}")
    
    def decrypt_data(self, key, encrypted_data):
        nonce = encrypted_data[:NONCE_SIZE]
        tag = encrypted_data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE + TAG_SIZE:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    
    def show_success_summary(self, success_count, total_count, output_path):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("✅ Decryption Successful")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        ctk.CTkLabel(
            dialog,
            text="🎉 Decryption Completed!",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#8B5FBF"
        ).pack(pady=20)
        
        info_frame = ctk.CTkFrame(dialog, corner_radius=10)
        info_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        ctk.CTkLabel(
            info_frame,
            text=f"✅ Successfully decrypted: {success_count}/{total_count} files",
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w", padx=20, pady=(20, 5))
        
        ctk.CTkLabel(
            info_frame,
            text=f"📁 Location: {output_path}",
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w", padx=20, pady=5)
        
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)
        
        ctk.CTkButton(
            button_frame,
            text="📂 Open Folder",
            command=lambda: self.open_folder(output_path),
            height=40,
            fg_color="#8B5FBF",
            hover_color="#7A4FA8"
        ).pack(side="left", padx=20)
        
        ctk.CTkButton(
            button_frame,
            text="OK",
            command=dialog.destroy,
            height=40,
            fg_color="#555",
            hover_color="#666"
        ).pack(side="right", padx=20)
    
    def open_folder(self, folder_path):
        if sys.platform == "win32":
            os.startfile(folder_path)
        elif sys.platform == "darwin":
            os.system(f'open "{folder_path}"')
        else:
            os.system(f'xdg-open "{folder_path}"')
    
    def show_help(self):
        help_text = """
🔓 DECRYPTO DECODER - HOW TO USE

DECRYPTION:
1. Select .decry container file (or drag & drop)
2. Enter decryption password or load .key file
3. Choose output directory
4. Click 'ANALYZE' to view contents
5. Click 'DECRYPT' to restore files

KEY OPTIONS:
• Use the original encryption password, OR
• Load the .key file that was generated during encryption

TROUBLESHOOTING:
• Ensure you're using the correct password/key
• Make sure the container file isn't corrupted
• Check that you have write permissions in output directory
"""
        messagebox.showinfo("Decryption Help", help_text)

def main():
    root = ctk.CTk()
    
    app = ModernDecryptApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()