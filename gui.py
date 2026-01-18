"""
Secure Audio Exchange GUI

A split-panel interface featuring Alice (sender) and Bob (receiver)
for demonstrating secure audio file encryption using:
- Camellia-128 (OFB mode)
- ECDH key exchange
- Schnorr digital signatures
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from pathlib import Path
import threading

from secure_system import SecureSystem
from crypto import ECPoint
from auth.user_auth import UserAuth


class SecureAudioGUI:
    """Main GUI application for secure audio exchange."""
    
    # Color scheme
    COLORS = {
        'bg_dark': '#1a1a2e',
        'bg_panel': '#16213e',
        'accent_alice': '#e94560',
        'accent_bob': '#0f3460',
        'accent_green': '#00d9a5',
        'text_light': '#eaeaea',
        'text_muted': '#8892a0',
        'border': '#2a3f5f'
    }
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Audio Exchange - Alice & Bob")
        self.root.geometry("1100x750")
        self.root.configure(bg=self.COLORS['bg_dark'])
        self.root.resizable(True, True)
        
        # Initialize crypto system
        self.system = SecureSystem()
        
        # User authentication
        self.auth = UserAuth()
        self.alice_authenticated = False
        self.bob_authenticated = False
        self.alice_username = None
        self.bob_username = None
        
        # Key storage
        self.alice_ecdh_priv = None
        self.alice_ecdh_pub = None
        self.alice_sign_priv = None
        self.alice_sign_pub = None
        
        self.bob_ecdh_priv = None
        self.bob_ecdh_pub = None
        
        # File storage
        self.alice_audio_path = None
        self.bob_encrypted_path = None
        
        self._setup_styles()
        self._create_widgets()
    
    def _setup_styles(self):
        """Configure ttk styles for modern look."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure button styles
        style.configure('Alice.TButton',
                       background=self.COLORS['accent_alice'],
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(15, 8))
        style.map('Alice.TButton',
                 background=[('active', '#ff6b6b')])
        
        style.configure('Bob.TButton',
                       background=self.COLORS['accent_bob'],
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(15, 8))
        style.map('Bob.TButton',
                 background=[('active', '#1a5276')])
        
        style.configure('Success.TButton',
                       background=self.COLORS['accent_green'],
                       foreground='black',
                       font=('Segoe UI', 11, 'bold'),
                       padding=(20, 12))
    
    def _create_widgets(self):
        """Create the main UI layout."""
        # Header
        header = tk.Frame(self.root, bg=self.COLORS['bg_dark'])
        header.pack(fill='x', pady=(15, 10))
        
        title = tk.Label(header,
                        text="🔐 Secure Audio Exchange",
                        font=('Segoe UI', 24, 'bold'),
                        fg=self.COLORS['text_light'],
                        bg=self.COLORS['bg_dark'])
        title.pack()
        
        subtitle = tk.Label(header,
                           text="Camellia-128 + ECDH + Schnorr Signatures",
                           font=('Segoe UI', 11),
                           fg=self.COLORS['text_muted'],
                           bg=self.COLORS['bg_dark'])
        subtitle.pack()
        
        # Main container with panels
        container = tk.Frame(self.root, bg=self.COLORS['bg_dark'])
        container.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Configure grid
        container.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=0)  # Arrow column
        container.columnconfigure(2, weight=1)
        container.rowconfigure(0, weight=1)
        
        # Alice panel (left)
        self._create_alice_panel(container)
        
        # Arrow in the middle
        arrow_frame = tk.Frame(container, bg=self.COLORS['bg_dark'])
        arrow_frame.grid(row=0, column=1, padx=10)
        
        arrow_label = tk.Label(arrow_frame,
                              text="➡️\n📦\n🔒",
                              font=('Segoe UI', 24),
                              fg=self.COLORS['text_muted'],
                              bg=self.COLORS['bg_dark'])
        arrow_label.pack(pady=100)
        
        # Bob panel (right)
        self._create_bob_panel(container)
        
        # Bottom status bar
        self._create_status_bar()
    
    def _create_alice_panel(self, parent):
        panel = tk.Frame(parent, bg=self.COLORS['bg_panel'], relief='flat', bd=2)
        panel.grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        
        # Panel header
        header = tk.Frame(panel, bg=self.COLORS['accent_alice'])
        header.pack(fill='x')
        
        tk.Label(header,
                text="👩 ALICE (Sender)",
                font=('Segoe UI', 14, 'bold'),
                fg='white',
                bg=self.COLORS['accent_alice'],
                pady=10).pack()
        
        # Content area
        content = tk.Frame(panel, bg=self.COLORS['bg_panel'])
        content.pack(fill='both', expand=True, padx=15, pady=15)
        
        # --- Embedded Login Section ---
        self._create_section(content, "Login")
        
        login_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        login_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(login_frame, text="Username:", bg=self.COLORS['bg_panel'], fg=self.COLORS['text_light']).grid(row=0, column=0, sticky='w')
        self.alice_login_username = tk.Entry(login_frame)
        self.alice_login_username.grid(row=0, column=1, padx=5)
        
        tk.Label(login_frame, text="Password:", bg=self.COLORS['bg_panel'], fg=self.COLORS['text_light']).grid(row=1, column=0, sticky='w')
        self.alice_login_password = tk.Entry(login_frame, show='*')
        self.alice_login_password.grid(row=1, column=1, padx=5)
        
        self.alice_login_btn = tk.Button(login_frame,
                                         text="Login",
                                         bg=self.COLORS['accent_alice'],
                                         fg='white',
                                         command=self._alice_login)
        self.alice_login_btn.grid(row=2, column=0, columnspan=2, pady=4)
        
        self.alice_login_status = tk.Label(login_frame,
                                          text="",
                                          bg=self.COLORS['bg_panel'],
                                          fg='red')
        self.alice_login_status.grid(row=3, column=0, columnspan=2)
        
        # Step 1: Generate Keys
        self._create_section(content, "Step 1: Generate Keys")
        
        key_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        key_frame.pack(fill='x', pady=(0, 15))
        
        self.alice_keygen_btn = tk.Button(key_frame,
                                         text="🔑 Generate Key Pairs",
                                         font=('Segoe UI', 10, 'bold'),
                                         bg=self.COLORS['accent_alice'],
                                         fg='white',
                                         activebackground='#ff6b6b',
                                         cursor='hand2',
                                         command=self._alice_generate_keys)
        self.alice_keygen_btn.pack(fill='x', pady=5)
        
        self.alice_key_status = tk.Label(key_frame,
                                        text="⏳ Keys not generated",
                                        font=('Segoe UI', 9),
                                        fg=self.COLORS['text_muted'],
                                        bg=self.COLORS['bg_panel'])
        self.alice_key_status.pack(anchor='w')
        
        # Step 2: Select Audio File
        self._create_section(content, "Step 2: Select Audio File")
        
        file_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        file_frame.pack(fill='x', pady=(0, 15))
        
        self.alice_file_btn = tk.Button(file_frame,
                                       text="📂 Choose Audio File",
                                       font=('Segoe UI', 10),
                                       bg=self.COLORS['border'],
                                       fg='white',
                                       activebackground='#3a5070',
                                       cursor='hand2',
                                       command=self._alice_select_file)
        self.alice_file_btn.pack(fill='x', pady=5)
        
        self.alice_file_label = tk.Label(file_frame,
                                        text="No file selected",
                                        font=('Segoe UI', 9),
                                        fg=self.COLORS['text_muted'],
                                        bg=self.COLORS['bg_panel'],
                                        wraplength=350)
        self.alice_file_label.pack(anchor='w')
        
        # Step 3: Sign & Encrypt
        self._create_section(content, "Step 3: Sign & Encrypt")
        
        encrypt_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        encrypt_frame.pack(fill='x', pady=(0, 15))
        
        # Info about Bob's key
        self.alice_bob_key_status = tk.Label(encrypt_frame,
                                            text="⚠️ Need Bob's public key first",
                                            font=('Segoe UI', 9),
                                            fg='#ffd93d',
                                            bg=self.COLORS['bg_panel'])
        self.alice_bob_key_status.pack(anchor='w', pady=(0, 5))
        
        self.alice_encrypt_btn = tk.Button(encrypt_frame,
                                          text="🔒 SIGN & ENCRYPT",
                                          font=('Segoe UI', 12, 'bold'),
                                          bg=self.COLORS['accent_green'],
                                          fg='black',
                                          activebackground='#00ffcc',
                                          cursor='hand2',
                                          state='disabled',
                                          command=self._alice_encrypt)
        self.alice_encrypt_btn.pack(fill='x', pady=5)
        
        # Log area
        self._create_section(content, "📋 Log")
        
        log_frame = tk.Frame(content, bg=self.COLORS['bg_dark'])
        log_frame.pack(fill='both', expand=True)
        
        self.alice_log = tk.Text(log_frame,
                                height=8,
                                font=('Consolas', 9),
                                bg=self.COLORS['bg_dark'],
                                fg=self.COLORS['text_light'],
                                insertbackground='white',
                                relief='flat',
                                state='disabled')
        self.alice_log.pack(fill='both', expand=True)
    
    def _create_bob_panel(self, parent):
        panel = tk.Frame(parent, bg=self.COLORS['bg_panel'], relief='flat', bd=2)
        panel.grid(row=0, column=2, sticky='nsew', padx=(5, 0))
        
        # Panel header
        header = tk.Frame(panel, bg=self.COLORS['accent_bob'])
        header.pack(fill='x')
        
        tk.Label(header,
                text="👨 BOB (Receiver)",
                font=('Segoe UI', 14, 'bold'),
                fg='white',
                bg=self.COLORS['accent_bob'],
                pady=10).pack()
        
        # Content area
        content = tk.Frame(panel, bg=self.COLORS['bg_panel'])
        content.pack(fill='both', expand=True, padx=15, pady=15)
        
        # --- Embedded Login Section ---
        self._create_section(content, "Login")
        
        login_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        login_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(login_frame, text="Username:", bg=self.COLORS['bg_panel'], fg=self.COLORS['text_light']).grid(row=0, column=0, sticky='w')
        self.bob_login_username = tk.Entry(login_frame)
        self.bob_login_username.grid(row=0, column=1, padx=5)
        
        tk.Label(login_frame, text="Password:", bg=self.COLORS['bg_panel'], fg=self.COLORS['text_light']).grid(row=1, column=0, sticky='w')
        self.bob_login_password = tk.Entry(login_frame, show='*')
        self.bob_login_password.grid(row=1, column=1, padx=5)
        
        self.bob_login_btn = tk.Button(login_frame,
                                       text="Login",
                                       bg=self.COLORS['accent_bob'],
                                       fg='white',
                                       command=self._bob_login)
        self.bob_login_btn.grid(row=2, column=0, columnspan=2, pady=4)
        
        self.bob_login_status = tk.Label(login_frame,
                                        text="",
                                        bg=self.COLORS['bg_panel'],
                                        fg='red')
        self.bob_login_status.grid(row=3, column=0, columnspan=2)
        
        # Step 1: Generate Keys
        self._create_section(content, "Step 1: Generate Keys")
        
        key_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        key_frame.pack(fill='x', pady=(0, 15))
        
        self.bob_keygen_btn = tk.Button(key_frame,
                                       text="🔑 Generate Key Pair",
                                       font=('Segoe UI', 10, 'bold'),
                                       bg=self.COLORS['accent_bob'],
                                       fg='white',
                                       activebackground='#1a5276',
                                       cursor='hand2',
                                       command=self._bob_generate_keys)
        self.bob_keygen_btn.pack(fill='x', pady=5)
        
        self.bob_key_status = tk.Label(key_frame,
                                      text="⏳ Keys not generated",
                                      font=('Segoe UI', 9),
                                      fg=self.COLORS['text_muted'],
                                      bg=self.COLORS['bg_panel'])
        self.bob_key_status.pack(anchor='w')
        
        # Step 2: Encrypted Package (auto-loaded from Alice or manual select)
        self._create_section(content, "Step 2: Encrypted Package")
        
        file_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        file_frame.pack(fill='x', pady=(0, 15))
        
        self.bob_file_btn = tk.Button(file_frame,
                                     text="📦 Choose Encrypted File",
                                     font=('Segoe UI', 10),
                                     bg=self.COLORS['border'],
                                     fg='white',
                                     activebackground='#3a5070',
                                     cursor='hand2',
                                     command=self._bob_select_file)
        self.bob_file_btn.pack(fill='x', pady=5)
        
        self.bob_file_label = tk.Label(file_frame,
                                      text="No file selected",
                                      font=('Segoe UI', 9),
                                      fg=self.COLORS['text_muted'],
                                      bg=self.COLORS['bg_panel'],
                                      wraplength=350)
        self.bob_file_label.pack(anchor='w')
        
        # Step 3: Decrypt
        self._create_section(content, "Step 3: Verify & Decrypt")
        
        decrypt_frame = tk.Frame(content, bg=self.COLORS['bg_panel'])
        decrypt_frame.pack(fill='x', pady=(0, 15))
        
        self.bob_decrypt_btn = tk.Button(decrypt_frame,
                                        text="🔓 VERIFY & DECRYPT",
                                        font=('Segoe UI', 12, 'bold'),
                                        bg=self.COLORS['accent_green'],
                                        fg='black',
                                        activebackground='#00ffcc',
                                        cursor='hand2',
                                        state='disabled',
                                        command=self._bob_decrypt)
        self.bob_decrypt_btn.pack(fill='x', pady=5)
        
        # Log area
        self._create_section(content, "📋 Log")
        
        log_frame = tk.Frame(content, bg=self.COLORS['bg_dark'])
        log_frame.pack(fill='both', expand=True)
        
        self.bob_log = tk.Text(log_frame,
                              height=8,
                              font=('Consolas', 9),
                              bg=self.COLORS['bg_dark'],
                              fg=self.COLORS['text_light'],
                              insertbackground='white',
                              relief='flat',
                              state='disabled')
        self.bob_log.pack(fill='both', expand=True)
    
    def _create_section(self, parent, title):
        """Create a section header."""
        label = tk.Label(parent,
                        text=title,
                        font=('Segoe UI', 11, 'bold'),
                        fg=self.COLORS['text_light'],
                        bg=self.COLORS['bg_panel'])
        label.pack(anchor='w', pady=(10, 5))
    
    def _create_status_bar(self):
        """Create bottom status bar."""
        status_bar = tk.Frame(self.root, bg=self.COLORS['bg_dark'])
        status_bar.pack(fill='x', pady=10, padx=20)
        
        self.status_label = tk.Label(status_bar,
                                    text="Ready - Generate keys for both Alice and Bob to begin",
                                    font=('Segoe UI', 10),
                                    fg=self.COLORS['text_muted'],
                                    bg=self.COLORS['bg_dark'])
        self.status_label.pack(side='left')
        
        # Demo button
        demo_btn = tk.Button(status_bar,
                            text="🚀 Run Full Demo",
                            font=('Segoe UI', 10, 'bold'),
                            bg=self.COLORS['accent_green'],
                            fg='black',
                            activebackground='#00ffcc',
                            cursor='hand2',
                            command=self._run_demo)
        demo_btn.pack(side='right')
    
    # =========================================================================
    # ALICE'S ACTIONS
    # =========================================================================
    
    def _alice_login(self):
        username = self.alice_login_username.get()
        password = self.alice_login_password.get()
        if self.auth.authenticate(username, password):
            self.alice_authenticated = True
            self.alice_username = username
            self.alice_login_status.config(text=f"Authenticated as {username} ✔", fg=self.COLORS['accent_green'])
            self.alice_keygen_btn.config(state='normal')
            self.alice_file_btn.config(state='normal')
            self.alice_encrypt_btn.config(state='normal')
        else:
            self.alice_login_status.config(text="Login failed.", fg='red')
            self.alice_authenticated = False
            self.alice_keygen_btn.config(state='disabled')
            self.alice_file_btn.config(state='disabled')
            self.alice_encrypt_btn.config(state='disabled')
    
    def _alice_generate_keys(self):
        if not self.alice_authenticated:
            messagebox.showerror("Authentication Required", "Alice must log in first.")
            return
        
        """Generate Alice's key pairs."""
        self._log_alice("Generating ECDH key pair...")
        self.alice_ecdh_priv, self.alice_ecdh_pub = self.system.generate_ecdh_keypair()
        
        self._log_alice("Generating Schnorr signing key pair...")
        self.alice_sign_priv, self.alice_sign_pub = self.system.generate_signing_keypair()
        
        self.alice_key_status.config(
            text=f"✅ Keys generated (ECDH + Schnorr)",
            fg=self.COLORS['accent_green']
        )
        
        self._log_alice(f"ECDH Public Key: {hex(self.alice_ecdh_pub.x)[:20]}...")
        self._log_alice(f"Signing Public Key: {hex(self.alice_sign_pub.x)[:20]}...")
        self._log_alice("Keys ready!")
        
        self._update_encrypt_button_state()
        self._update_status()
    
    def _alice_select_file(self):
        """Select audio file to encrypt."""
        path = filedialog.askopenfilename(
            title="Select Audio File",
            filetypes=[
                ("Audio files", "*.mp3 *.wav *.m4a *.ogg *.flac"),
                ("All files", "*.*")
            ]
        )
        
        if path:
            self.alice_audio_path = path
            file_size = os.path.getsize(path) / 1024  # KB
            filename = os.path.basename(path)
            
            self.alice_file_label.config(
                text=f"📄 {filename} ({file_size:.1f} KB)",
                fg=self.COLORS['accent_green']
            )
            
            self._log_alice(f"Selected: {filename}")
            self._update_encrypt_button_state()
    
    def _alice_encrypt(self):
        if not self.alice_authenticated:
            messagebox.showerror("Authentication Required", "Alice must log in first.")
            return
        
        """Encrypt the selected audio file."""
        if not all([self.alice_ecdh_priv, self.alice_sign_priv, 
                   self.bob_ecdh_pub, self.alice_audio_path]):
            messagebox.showerror("Error", "Missing keys or file!")
            return
        
        self._log_alice("=" * 40)
        self._log_alice("Starting encryption process...")
        
        # Generate output path
        base_name = Path(self.alice_audio_path).stem
        output_dir = os.path.dirname(self.alice_audio_path)
        output_path = os.path.join(output_dir, f"{base_name}_encrypted.wav")
        
        try:
            self._log_alice("Generating Schnorr signature on plaintext...")
            self._log_alice("Deriving session key via ECDH...")
            self._log_alice("Encrypting with Camellia-128-OFB...")
            
            package = self.system.encrypt_file(
                input_path=self.alice_audio_path,
                output_path=output_path,
                my_ecdh_private=self.alice_ecdh_priv,
                their_ecdh_public=self.bob_ecdh_pub,
                my_signing_private=self.alice_sign_priv
            )
            
            self._log_alice(f"✅ Encryption complete!")
            self._log_alice(f"Output: {os.path.basename(output_path)}")
            self._log_alice(f"Ciphertext: {len(package['ciphertext']):,} bytes")
            self._log_alice("=" * 40)
            
            self.status_label.config(
                text=f"✅ Encrypted → {os.path.basename(output_path)}",
                fg=self.COLORS['accent_green']
            )
            
            # Auto-load in Bob's panel for demo
            self.bob_encrypted_path = output_path
            self.bob_file_label.config(
                text=f"📦 {os.path.basename(output_path)} (auto-loaded)",
                fg=self.COLORS['accent_green']
            )
            self._log_bob("Received encrypted package from Alice!")
            self._update_decrypt_button_state()
            
        except Exception as e:
            self._log_alice(f"❌ Error: {str(e)}")
            messagebox.showerror("Encryption Error", str(e))
    
    # =========================================================================
    # BOB'S ACTIONS
    # =========================================================================
    
    def _bob_login(self):
        username = self.bob_login_username.get()
        password = self.bob_login_password.get()
        if self.auth.authenticate(username, password):
            self.bob_authenticated = True
            self.bob_username = username
            self.bob_login_status.config(text=f"Authenticated as {username} ✔", fg=self.COLORS['accent_green'])
            self.bob_keygen_btn.config(state='normal')
            self.bob_file_btn.config(state='normal')
            self.bob_decrypt_btn.config(state='normal')
        else:
            self.bob_login_status.config(text="Login failed.", fg='red')
            self.bob_authenticated = False
            self.bob_keygen_btn.config(state='disabled')
            self.bob_file_btn.config(state='disabled')
            self.bob_decrypt_btn.config(state='disabled')

    def _bob_generate_keys(self):
        if not self.bob_authenticated:
            messagebox.showerror("Authentication Required", "Bob must log in first.")
            return
        
        """Generate Bob's key pair."""
        self._log_bob("Generating ECDH key pair...")
        self.bob_ecdh_priv, self.bob_ecdh_pub = self.system.generate_ecdh_keypair()
        
        self.bob_key_status.config(
            text=f"✅ ECDH key pair generated",
            fg=self.COLORS['accent_green']
        )
        
        self._log_bob(f"ECDH Public Key: {hex(self.bob_ecdh_pub.x)[:20]}...")
        self._log_bob("Key ready - shared with Alice!")
        
        # Update Alice's panel to show Bob's key is available
        self.alice_bob_key_status.config(
            text="✅ Bob's public key available",
            fg=self.COLORS['accent_green']
        )
        
        self._update_encrypt_button_state()
        self._update_decrypt_button_state()
        self._update_status()
    
    def _bob_select_file(self):
        """Select encrypted file to decrypt."""
        path = filedialog.askopenfilename(
            title="Select Encrypted Package",
            filetypes=[
                ("Encrypted files", "*.bin *.enc *.wav"),
                ("All files", "*.*")
            ]
        )
        
        if path:
            # Check if metadata file exists
            meta_path = path + '.meta'
            if not os.path.exists(meta_path):
                messagebox.showerror("Error", 
                    f"Metadata file not found!\nExpected: {meta_path}")
                return
            
            self.bob_encrypted_path = path
            file_size = os.path.getsize(path) / 1024
            filename = os.path.basename(path)
            
            self.bob_file_label.config(
                text=f"📦 {filename} ({file_size:.1f} KB)",
                fg=self.COLORS['accent_green']
            )
            
            self._log_bob(f"Selected: {filename}")
            self._update_decrypt_button_state()
    
    def _bob_decrypt(self):
        if not self.bob_authenticated:
            messagebox.showerror("Authentication Required", "Bob must log in first.")
            return
        
        """Decrypt the selected file."""
        if not all([self.bob_ecdh_priv, self.bob_encrypted_path, 
                   self.alice_sign_pub]):
            messagebox.showerror("Error", "Missing keys or file!")
            return
        
        self._log_bob("=" * 40)
        self._log_bob("Starting decryption process...")
        
        # Generate output path
        base_name = Path(self.bob_encrypted_path).stem.replace('_encrypted', '')
        output_dir = os.path.dirname(self.bob_encrypted_path)
        output_path = os.path.join(output_dir, f"{base_name}_decrypted.mp3")
        
        try:
            self._log_bob("Deriving session key via ECDH...")
            self._log_bob("Decrypting with Camellia-128-OFB...")
            self._log_bob("Verifying Schnorr signature on plaintext...")
            
            bytes_written = self.system.decrypt_file(
                input_path=self.bob_encrypted_path,
                output_path=output_path,
                my_ecdh_private=self.bob_ecdh_priv,
                their_signing_public=self.alice_sign_pub
            )
            
            self._log_bob(f"✅ Signature verified!")
            self._log_bob(f"✅ Decryption complete!")
            self._log_bob(f"Output: {os.path.basename(output_path)}")
            self._log_bob(f"Size: {bytes_written:,} bytes")
            self._log_bob("=" * 40)
            
            self.status_label.config(
                text=f"✅ Decrypted → {os.path.basename(output_path)}",
                fg=self.COLORS['accent_green']
            )
            
            messagebox.showinfo("Success", 
                f"File decrypted successfully!\n\n{output_path}")
            
        except ValueError as e:
            self._log_bob(f"❌ Verification failed: {str(e)}")
            messagebox.showerror("Verification Error", str(e))
        except Exception as e:
            self._log_bob(f"❌ Error: {str(e)}")
            messagebox.showerror("Decryption Error", str(e))
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _log_alice(self, message):
        """Add message to Alice's log."""
        self.alice_log.config(state='normal')
        self.alice_log.insert('end', message + '\n')
        self.alice_log.see('end')
        self.alice_log.config(state='disabled')
    
    def _log_bob(self, message):
        """Add message to Bob's log."""
        self.bob_log.config(state='normal')
        self.bob_log.insert('end', message + '\n')
        self.bob_log.see('end')
        self.bob_log.config(state='disabled')
    
    def _update_encrypt_button_state(self):
        """Update encrypt button based on prerequisites."""
        if all([self.alice_ecdh_priv, self.alice_sign_priv,
               self.bob_ecdh_pub, self.alice_audio_path]):
            self.alice_encrypt_btn.config(state='normal')
        else:
            self.alice_encrypt_btn.config(state='disabled')
    
    def _update_decrypt_button_state(self):
        """Update decrypt button based on prerequisites."""
        if all([self.bob_ecdh_priv, self.bob_encrypted_path,
               self.alice_sign_pub]):
            self.bob_decrypt_btn.config(state='normal')
        else:
            self.bob_decrypt_btn.config(state='disabled')
    
    def _update_status(self):
        """Update status bar."""
        if self.alice_ecdh_priv and self.bob_ecdh_pub:
            self.status_label.config(
                text="✅ Keys exchanged - Ready for encryption",
                fg=self.COLORS['accent_green']
            )
        elif self.alice_ecdh_priv:
            self.status_label.config(
                text="⏳ Waiting for Bob to generate keys...",
                fg='#ffd93d'
            )
        elif self.bob_ecdh_pub:
            self.status_label.config(
                text="⏳ Waiting for Alice to generate keys...",
                fg='#ffd93d'
            )
    
    def _run_demo(self):
        """Run a complete demo with sample file."""
        # Check if sample file exists
        sample_files = [f for f in os.listdir('.') 
                       if f.endswith(('.mp3', '.wav', '.m4a'))]
        
        if not sample_files:
            messagebox.showinfo("Demo", 
                "Please select an audio file manually.\n\n"
                "1. Click 'Generate Keys' on Alice's side\n"
                "2. Click 'Generate Keys' on Bob's side\n"
                "3. Click 'Choose Audio File' on Alice's side\n"
                "4. Click 'ENCRYPT & SIGN'\n"
                "5. Click 'VERIFY & DECRYPT' on Bob's side")
            return
        
        # Auto-run with first available audio file
        if not self.alice_ecdh_priv:
            self._alice_generate_keys()
        
        if not self.bob_ecdh_priv:
            self._bob_generate_keys()
        
        if not self.alice_audio_path:
            self.alice_audio_path = sample_files[0]
            self.alice_file_label.config(
                text=f"📄 {sample_files[0]} (auto-selected)",
                fg=self.COLORS['accent_green']
            )
            self._log_alice(f"Auto-selected: {sample_files[0]}")
        
        self._update_encrypt_button_state()
        messagebox.showinfo("Demo Ready",
            "Keys generated! Now click:\n\n"
            "1. 'ENCRYPT & SIGN' on Alice's side\n"
            "2. 'VERIFY & DECRYPT' on Bob's side")


def main():
    root = tk.Tk()
    app = SecureAudioGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
