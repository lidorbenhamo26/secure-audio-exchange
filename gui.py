"""
Secure Audio Exchange GUI

A split-panel interface featuring Alice (sender) and Bob (receiver)
for demonstrating secure audio file encryption using:
- Camellia-128 (OFB mode)
- ECDH key exchange
- Schnorr digital signatures

Features dual-login gatekeeper: Both Alice and Bob must authenticate
before accessing the encryption/decryption interface.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from pathlib import Path
import threading

from secure_system import SecureSystem
from crypto import ECPoint
from auth import PaperAuth


class SecureAudioGUI:
    """Main GUI application for secure audio exchange with dual-login gatekeeper."""
    
    # Color scheme
    COLORS = {
        'bg_dark': '#1a1a2e',
        'bg_panel': '#16213e',
        'accent_alice': '#e94560',
        'accent_bob': '#0f3460',
        'accent_green': '#00d9a5',
        'text_light': '#eaeaea',
        'text_muted': '#8892a0',
        'border': '#2a3f5f',
        'warning': '#ffd93d',
        'login_bg': '#0d1b2a'
    }
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Audio Exchange - Alice & Bob")
        self.root.geometry("1100x750")
        self.root.configure(bg=self.COLORS['bg_dark'])
        self.root.resizable(True, True)
        
        # Initialize crypto system
        self.system = SecureSystem()
        
        # Initialize authentication system
        self.auth = PaperAuth()
        
        # Authentication state - CRITICAL for dual-lock gatekeeper
        self.alice_logged_in = False
        self.bob_logged_in = False
        self.alice_session_active = False
        self.bob_session_active = False
        
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
        
        # Panel references (for grid_remove/grid)
        self.alice_login_panel = None
        self.alice_main_panel = None
        self.bob_login_panel = None
        self.bob_main_panel = None
        
        self._setup_styles()
        self._create_widgets()
        
        # Ensure default users exist for demo
        self._ensure_default_users()
    
    def _ensure_default_users(self):
        """Create default Alice and Bob users if they don't exist."""
        try:
            if not self.auth.user_exists('alice'):
                result = self.auth.register_user('alice', 'alice_secret_paper')
                print(f"Created Alice - Salt: {result['salt'][:16]}...")
            if not self.auth.user_exists('bob'):
                result = self.auth.register_user('bob', 'bob_secret_paper')
                print(f"Created Bob - Salt: {result['salt'][:16]}...")
        except Exception as e:
            print(f"Note: {e}")
    
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
        
        style.configure('Login.TButton',
                       background=self.COLORS['accent_green'],
                       foreground='black',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(10, 6))
    
    def _create_widgets(self):
        """Create the main UI layout with dual-login gatekeeper."""
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
        self.container = tk.Frame(self.root, bg=self.COLORS['bg_dark'])
        self.container.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Configure grid
        self.container.columnconfigure(0, weight=1)
        self.container.columnconfigure(1, weight=0)  # Arrow column
        self.container.columnconfigure(2, weight=1)
        self.container.rowconfigure(0, weight=1)
        
        # Create ALL panels (both login and main for each user)
        self._create_alice_login_panel(self.container)
        self._create_alice_main_panel(self.container)
        self._create_bob_login_panel(self.container)
        self._create_bob_main_panel(self.container)
        
        # Arrow in the middle
        self.arrow_frame = tk.Frame(self.container, bg=self.COLORS['bg_dark'])
        self.arrow_frame.grid(row=0, column=1, padx=10)
        
        arrow_label = tk.Label(self.arrow_frame,
                              text="➡️\n📦\n🔒",
                              font=('Segoe UI', 24),
                              fg=self.COLORS['text_muted'],
                              bg=self.COLORS['bg_dark'])
        arrow_label.pack(pady=100)
        
        # Hide main panels initially - CRITICAL for dual-lock gatekeeper
        self.alice_main_panel.grid_remove()
        self.bob_main_panel.grid_remove()
        
        # Bottom status bar
        self._create_status_bar()
        
        # Initial status update
        self._update_status()
    
    # =========================================================================
    # LOGIN PANELS
    # =========================================================================
    
    def _create_alice_login_panel(self, parent):
        """Create Alice's login panel."""
        self.alice_login_panel = tk.Frame(parent, bg=self.COLORS['login_bg'], 
                                          relief='flat', bd=2)
        self.alice_login_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        
        # Panel header
        header = tk.Frame(self.alice_login_panel, bg=self.COLORS['accent_alice'])
        header.pack(fill='x')
        
        tk.Label(header,
                text="👩 ALICE LOGIN",
                font=('Segoe UI', 14, 'bold'),
                fg='white',
                bg=self.COLORS['accent_alice'],
                pady=10).pack()
        
        # Content area
        content = tk.Frame(self.alice_login_panel, bg=self.COLORS['login_bg'])
        content.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Login form centered
        login_frame = tk.Frame(content, bg=self.COLORS['login_bg'])
        login_frame.pack(expand=True)
        
        # Title
        tk.Label(login_frame,
                text="🔐 Authentication Required",
                font=('Segoe UI', 16, 'bold'),
                fg=self.COLORS['text_light'],
                bg=self.COLORS['login_bg']).pack(pady=(0, 20))
        
        tk.Label(login_frame,
                text="Enter your Paper (passphrase) and Salt to authenticate",
                font=('Segoe UI', 10),
                fg=self.COLORS['text_muted'],
                bg=self.COLORS['login_bg']).pack(pady=(0, 20))
        
        # Passphrase input
        tk.Label(login_frame,
                text="Paper (Passphrase):",
                font=('Segoe UI', 10),
                fg=self.COLORS['text_light'],
                bg=self.COLORS['login_bg']).pack(anchor='w', pady=(10, 2))
        
        self.alice_passphrase_entry = tk.Entry(login_frame,
                                               font=('Segoe UI', 11),
                                               bg=self.COLORS['bg_panel'],
                                               fg=self.COLORS['text_light'],
                                               insertbackground='white',
                                               show='●',
                                               width=40)
        self.alice_passphrase_entry.pack(fill='x', pady=(0, 10))
        
        # Salt input
        tk.Label(login_frame,
                text="Salt (from credentials.json):",
                font=('Segoe UI', 10),
                fg=self.COLORS['text_light'],
                bg=self.COLORS['login_bg']).pack(anchor='w', pady=(10, 2))
        
        self.alice_salt_entry = tk.Entry(login_frame,
                                         font=('Consolas', 10),
                                         bg=self.COLORS['bg_panel'],
                                         fg=self.COLORS['text_light'],
                                         insertbackground='white',
                                         width=40)
        self.alice_salt_entry.pack(fill='x', pady=(0, 10))
        
        # Auto-fill salt button
        autofill_btn = tk.Button(login_frame,
                                text="📋 Auto-fill Salt from credentials.json",
                                font=('Segoe UI', 9),
                                bg=self.COLORS['border'],
                                fg='white',
                                activebackground='#3a5070',
                                cursor='hand2',
                                command=lambda: self._autofill_salt('alice'))
        autofill_btn.pack(pady=(0, 20))
        
        # Login button
        self.alice_login_btn = tk.Button(login_frame,
                                        text="🔓 LOGIN",
                                        font=('Segoe UI', 12, 'bold'),
                                        bg=self.COLORS['accent_green'],
                                        fg='black',
                                        activebackground='#00ffcc',
                                        cursor='hand2',
                                        width=20,
                                        command=self._alice_login)
        self.alice_login_btn.pack(pady=10)
        
        # Login status
        self.alice_login_status = tk.Label(login_frame,
                                          text="",
                                          font=('Segoe UI', 10),
                                          fg=self.COLORS['text_muted'],
                                          bg=self.COLORS['login_bg'])
        self.alice_login_status.pack(pady=10)
        
        # Info note
        tk.Label(login_frame,
                text="PBKDF2-HMAC-SHA256 • 100,000 iterations",
                font=('Segoe UI', 9),
                fg=self.COLORS['text_muted'],
                bg=self.COLORS['login_bg']).pack(pady=(20, 0))
    
    def _create_bob_login_panel(self, parent):
        """Create Bob's login panel."""
        self.bob_login_panel = tk.Frame(parent, bg=self.COLORS['login_bg'],
                                        relief='flat', bd=2)
        self.bob_login_panel.grid(row=0, column=2, sticky='nsew', padx=(5, 0))
        
        # Panel header
        header = tk.Frame(self.bob_login_panel, bg=self.COLORS['accent_bob'])
        header.pack(fill='x')
        
        tk.Label(header,
                text="👨 BOB LOGIN",
                font=('Segoe UI', 14, 'bold'),
                fg='white',
                bg=self.COLORS['accent_bob'],
                pady=10).pack()
        
        # Content area
        content = tk.Frame(self.bob_login_panel, bg=self.COLORS['login_bg'])
        content.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Login form centered
        login_frame = tk.Frame(content, bg=self.COLORS['login_bg'])
        login_frame.pack(expand=True)
        
        # Title
        tk.Label(login_frame,
                text="🔐 Authentication Required",
                font=('Segoe UI', 16, 'bold'),
                fg=self.COLORS['text_light'],
                bg=self.COLORS['login_bg']).pack(pady=(0, 20))
        
        tk.Label(login_frame,
                text="Enter your Paper (passphrase) and Salt to authenticate",
                font=('Segoe UI', 10),
                fg=self.COLORS['text_muted'],
                bg=self.COLORS['login_bg']).pack(pady=(0, 20))
        
        # Passphrase input
        tk.Label(login_frame,
                text="Paper (Passphrase):",
                font=('Segoe UI', 10),
                fg=self.COLORS['text_light'],
                bg=self.COLORS['login_bg']).pack(anchor='w', pady=(10, 2))
        
        self.bob_passphrase_entry = tk.Entry(login_frame,
                                             font=('Segoe UI', 11),
                                             bg=self.COLORS['bg_panel'],
                                             fg=self.COLORS['text_light'],
                                             insertbackground='white',
                                             show='●',
                                             width=40)
        self.bob_passphrase_entry.pack(fill='x', pady=(0, 10))
        
        # Salt input
        tk.Label(login_frame,
                text="Salt (from credentials.json):",
                font=('Segoe UI', 10),
                fg=self.COLORS['text_light'],
                bg=self.COLORS['login_bg']).pack(anchor='w', pady=(10, 2))
        
        self.bob_salt_entry = tk.Entry(login_frame,
                                       font=('Consolas', 10),
                                       bg=self.COLORS['bg_panel'],
                                       fg=self.COLORS['text_light'],
                                       insertbackground='white',
                                       width=40)
        self.bob_salt_entry.pack(fill='x', pady=(0, 10))
        
        # Auto-fill salt button
        autofill_btn = tk.Button(login_frame,
                                text="📋 Auto-fill Salt from credentials.json",
                                font=('Segoe UI', 9),
                                bg=self.COLORS['border'],
                                fg='white',
                                activebackground='#3a5070',
                                cursor='hand2',
                                command=lambda: self._autofill_salt('bob'))
        autofill_btn.pack(pady=(0, 20))
        
        # Login button
        self.bob_login_btn = tk.Button(login_frame,
                                      text="🔓 LOGIN",
                                      font=('Segoe UI', 12, 'bold'),
                                      bg=self.COLORS['accent_green'],
                                      fg='black',
                                      activebackground='#00ffcc',
                                      cursor='hand2',
                                      width=20,
                                      command=self._bob_login)
        self.bob_login_btn.pack(pady=10)
        
        # Login status
        self.bob_login_status = tk.Label(login_frame,
                                        text="",
                                        font=('Segoe UI', 10),
                                        fg=self.COLORS['text_muted'],
                                        bg=self.COLORS['login_bg'])
        self.bob_login_status.pack(pady=10)
        
        # Info note
        tk.Label(login_frame,
                text="PBKDF2-HMAC-SHA256 • 100,000 iterations",
                font=('Segoe UI', 9),
                fg=self.COLORS['text_muted'],
                bg=self.COLORS['login_bg']).pack(pady=(20, 0))
    
    # =========================================================================
    # MAIN PANELS (Hidden until dual auth)
    # =========================================================================
    
    def _create_alice_main_panel(self, parent):
        """Create Alice's encryption panel (hidden initially)."""
        self.alice_main_panel = tk.Frame(parent, bg=self.COLORS['bg_panel'], 
                                         relief='flat', bd=2)
        self.alice_main_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        
        # Panel header
        header = tk.Frame(self.alice_main_panel, bg=self.COLORS['accent_alice'])
        header.pack(fill='x')
        
        header_content = tk.Frame(header, bg=self.COLORS['accent_alice'])
        header_content.pack(fill='x', padx=10)
        
        tk.Label(header_content,
                text="👩 ALICE (Sender)",
                font=('Segoe UI', 14, 'bold'),
                fg='white',
                bg=self.COLORS['accent_alice'],
                pady=10).pack(side='left')
        
        # Logout button
        self.alice_logout_btn = tk.Button(header_content,
                                         text="🚪 Logout",
                                         font=('Segoe UI', 9),
                                         bg='#8b0000',
                                         fg='white',
                                         activebackground='#a52a2a',
                                         cursor='hand2',
                                         command=self._alice_logout)
        self.alice_logout_btn.pack(side='right', pady=5)
        
        # Content area
        content = tk.Frame(self.alice_main_panel, bg=self.COLORS['bg_panel'])
        content.pack(fill='both', expand=True, padx=15, pady=15)
        
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
                                         state='disabled',  # Disabled until dual auth
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
    
    def _create_bob_main_panel(self, parent):
        """Create Bob's decryption panel (hidden initially)."""
        self.bob_main_panel = tk.Frame(parent, bg=self.COLORS['bg_panel'],
                                       relief='flat', bd=2)
        self.bob_main_panel.grid(row=0, column=2, sticky='nsew', padx=(5, 0))
        
        # Panel header
        header = tk.Frame(self.bob_main_panel, bg=self.COLORS['accent_bob'])
        header.pack(fill='x')
        
        header_content = tk.Frame(header, bg=self.COLORS['accent_bob'])
        header_content.pack(fill='x', padx=10)
        
        tk.Label(header_content,
                text="👨 BOB (Receiver)",
                font=('Segoe UI', 14, 'bold'),
                fg='white',
                bg=self.COLORS['accent_bob'],
                pady=10).pack(side='left')
        
        # Logout button
        self.bob_logout_btn = tk.Button(header_content,
                                       text="🚪 Logout",
                                       font=('Segoe UI', 9),
                                       bg='#8b0000',
                                       fg='white',
                                       activebackground='#a52a2a',
                                       cursor='hand2',
                                       command=self._bob_logout)
        self.bob_logout_btn.pack(side='right', pady=5)
        
        # Content area
        content = tk.Frame(self.bob_main_panel, bg=self.COLORS['bg_panel'])
        content.pack(fill='both', expand=True, padx=15, pady=15)
        
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
                                       state='disabled',  # Disabled until dual auth
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
                                    text="🔒 Both Alice and Bob must login to proceed",
                                    font=('Segoe UI', 10),
                                    fg=self.COLORS['warning'],
                                    bg=self.COLORS['bg_dark'])
        self.status_label.pack(side='left')
        
        # Demo button
        self.demo_btn = tk.Button(status_bar,
                                 text="🚀 Run Full Demo",
                                 font=('Segoe UI', 10, 'bold'),
                                 bg=self.COLORS['accent_green'],
                                 fg='black',
                                 activebackground='#00ffcc',
                                 cursor='hand2',
                                 state='disabled',  # Disabled until dual auth
                                 command=self._run_demo)
        self.demo_btn.pack(side='right')
    
    # =========================================================================
    # AUTHENTICATION METHODS
    # =========================================================================
    
    def _autofill_salt(self, user: str):
        """Auto-fill salt from credentials.json."""
        try:
            salt = self.auth.get_user_salt(user)
            if user == 'alice':
                self.alice_salt_entry.delete(0, tk.END)
                self.alice_salt_entry.insert(0, salt)
            else:
                self.bob_salt_entry.delete(0, tk.END)
                self.bob_salt_entry.insert(0, salt)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def _alice_login(self):
        """Handle Alice's login attempt."""
        passphrase = self.alice_passphrase_entry.get()
        salt = self.alice_salt_entry.get()
        
        if not passphrase or not salt:
            self.alice_login_status.config(
                text="❌ Please enter both passphrase and salt",
                fg='#ff6b6b'
            )
            return
        
        # Authenticate using PaperAuth with PBKDF2-HMAC-SHA256
        if self.auth.authenticate('alice', passphrase, salt):
            self.alice_logged_in = True
            self.alice_session_active = True
            
            self.alice_login_status.config(
                text="✅ Authentication successful!",
                fg=self.COLORS['accent_green']
            )
            
            # Clear sensitive data from entry
            self.alice_passphrase_entry.delete(0, tk.END)
            
            # Check if both users are authenticated
            self._check_dual_authentication()
        else:
            self.alice_login_status.config(
                text="❌ Authentication failed! Invalid passphrase or salt",
                fg='#ff6b6b'
            )
    
    def _bob_login(self):
        """Handle Bob's login attempt."""
        passphrase = self.bob_passphrase_entry.get()
        salt = self.bob_salt_entry.get()
        
        if not passphrase or not salt:
            self.bob_login_status.config(
                text="❌ Please enter both passphrase and salt",
                fg='#ff6b6b'
            )
            return
        
        # Authenticate using PaperAuth with PBKDF2-HMAC-SHA256
        if self.auth.authenticate('bob', passphrase, salt):
            self.bob_logged_in = True
            self.bob_session_active = True
            
            self.bob_login_status.config(
                text="✅ Authentication successful!",
                fg=self.COLORS['accent_green']
            )
            
            # Clear sensitive data from entry
            self.bob_passphrase_entry.delete(0, tk.END)
            
            # Check if both users are authenticated
            self._check_dual_authentication()
        else:
            self.bob_login_status.config(
                text="❌ Authentication failed! Invalid passphrase or salt",
                fg='#ff6b6b'
            )
    
    def _check_dual_authentication(self):
        """
        CRITICAL: Check if both Alice and Bob are authenticated.
        Only reveal main panels when BOTH are logged in.
        """
        # Update status to reflect current authentication state
        self._update_status()
        
        # DUAL-LOCK TRIGGER: Only proceed when BOTH are authenticated
        if self.alice_logged_in and self.bob_logged_in:
            # Both authenticated - reveal main panels
            self._reveal_main_interface()
        elif self.alice_logged_in:
            # Only Alice logged in
            self.alice_login_status.config(
                text="✅ Logged in. Waiting for Bob...",
                fg=self.COLORS['accent_green']
            )
        elif self.bob_logged_in:
            # Only Bob logged in
            self.bob_login_status.config(
                text="✅ Logged in. Waiting for Alice...",
                fg=self.COLORS['accent_green']
            )
    
    def _reveal_main_interface(self):
        """Reveal the main encryption/decryption interface."""
        # Hide login panels
        self.alice_login_panel.grid_remove()
        self.bob_login_panel.grid_remove()
        
        # Show main panels
        self.alice_main_panel.grid()
        self.bob_main_panel.grid()
        
        # Enable key generation buttons (security persistence check)
        self._verify_session_and_enable_controls()
        
        # Log the successful dual authentication
        self._log_alice("=" * 40)
        self._log_alice("✅ Dual authentication complete!")
        self._log_alice("Session established for Alice")
        self._log_alice("=" * 40)
        
        self._log_bob("=" * 40)
        self._log_bob("✅ Dual authentication complete!")
        self._log_bob("Session established for Bob")
        self._log_bob("=" * 40)
    
    def _verify_session_and_enable_controls(self):
        """
        Security Persistence: Verify both sessions are active
        before enabling controls.
        """
        if self.alice_session_active and self.bob_session_active:
            # Enable key generation buttons
            self.alice_keygen_btn.config(state='normal')
            self.bob_keygen_btn.config(state='normal')
            self.demo_btn.config(state='normal')
        else:
            # Keep buttons disabled if session not verified
            self.alice_keygen_btn.config(state='disabled')
            self.bob_keygen_btn.config(state='disabled')
            self.demo_btn.config(state='disabled')
    
    def _alice_logout(self):
        """Handle Alice's logout."""
        self.alice_logged_in = False
        self.alice_session_active = False
        
        # Reset keys
        self.alice_ecdh_priv = None
        self.alice_ecdh_pub = None
        self.alice_sign_priv = None
        self.alice_sign_pub = None
        self.alice_audio_path = None
        
        # Hide main interface, show login
        self._hide_main_interface()
        
        # Reset login panel
        self.alice_login_status.config(text="", fg=self.COLORS['text_muted'])
        self.alice_passphrase_entry.delete(0, tk.END)
        
        self._update_status()
    
    def _bob_logout(self):
        """Handle Bob's logout."""
        self.bob_logged_in = False
        self.bob_session_active = False
        
        # Reset keys
        self.bob_ecdh_priv = None
        self.bob_ecdh_pub = None
        self.bob_encrypted_path = None
        
        # Hide main interface, show login
        self._hide_main_interface()
        
        # Reset login panel
        self.bob_login_status.config(text="", fg=self.COLORS['text_muted'])
        self.bob_passphrase_entry.delete(0, tk.END)
        
        self._update_status()
    
    def _hide_main_interface(self):
        """Hide main panels and show login panels."""
        # Hide main panels
        self.alice_main_panel.grid_remove()
        self.bob_main_panel.grid_remove()
        
        # Show login panels
        self.alice_login_panel.grid()
        self.bob_login_panel.grid()
        
        # Disable controls
        self.alice_keygen_btn.config(state='disabled')
        self.bob_keygen_btn.config(state='disabled')
        self.alice_encrypt_btn.config(state='disabled')
        self.bob_decrypt_btn.config(state='disabled')
        self.demo_btn.config(state='disabled')
        
        # Reset key status labels
        self.alice_key_status.config(
            text="⏳ Keys not generated",
            fg=self.COLORS['text_muted']
        )
        self.bob_key_status.config(
            text="⏳ Keys not generated",
            fg=self.COLORS['text_muted']
        )
        self.alice_bob_key_status.config(
            text="⚠️ Need Bob's public key first",
            fg='#ffd93d'
        )
    
    # =========================================================================
    # ALICE'S ACTIONS
    # =========================================================================
    
    def _alice_generate_keys(self):
        """Generate Alice's key pairs."""
        # Security check: Verify session is active
        if not self.alice_session_active or not self.bob_session_active:
            messagebox.showerror("Security Error", 
                "Session verification failed. Please re-authenticate.")
            self._hide_main_interface()
            return
        
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
        """Encrypt the selected audio file."""
        # Security check: Verify session is active
        if not self.alice_session_active or not self.bob_session_active:
            messagebox.showerror("Security Error", 
                "Session verification failed. Please re-authenticate.")
            self._hide_main_interface()
            return
        
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
    
    def _bob_generate_keys(self):
        """Generate Bob's key pair."""
        # Security check: Verify session is active
        if not self.alice_session_active or not self.bob_session_active:
            messagebox.showerror("Security Error", 
                "Session verification failed. Please re-authenticate.")
            self._hide_main_interface()
            return
        
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
        """Decrypt the selected file."""
        # Security check: Verify session is active
        if not self.alice_session_active or not self.bob_session_active:
            messagebox.showerror("Security Error", 
                "Session verification failed. Please re-authenticate.")
            self._hide_main_interface()
            return
        
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
        """Update encrypt button based on prerequisites and session."""
        # Security persistence: Check session is active
        if not (self.alice_session_active and self.bob_session_active):
            self.alice_encrypt_btn.config(state='disabled')
            return
        
        if all([self.alice_ecdh_priv, self.alice_sign_priv,
               self.bob_ecdh_pub, self.alice_audio_path]):
            self.alice_encrypt_btn.config(state='normal')
        else:
            self.alice_encrypt_btn.config(state='disabled')
    
    def _update_decrypt_button_state(self):
        """Update decrypt button based on prerequisites and session."""
        # Security persistence: Check session is active
        if not (self.alice_session_active and self.bob_session_active):
            self.bob_decrypt_btn.config(state='disabled')
            return
        
        if all([self.bob_ecdh_priv, self.bob_encrypted_path,
               self.alice_sign_pub]):
            self.bob_decrypt_btn.config(state='normal')
        else:
            self.bob_decrypt_btn.config(state='disabled')
    
    def _update_status(self):
        """Update status bar based on authentication and key state."""
        # Check authentication state first
        if not self.alice_logged_in and not self.bob_logged_in:
            self.status_label.config(
                text="🔒 Both Alice and Bob must login to proceed",
                fg=self.COLORS['warning']
            )
        elif self.alice_logged_in and not self.bob_logged_in:
            self.status_label.config(
                text="✅ Alice logged in, waiting for Bob...",
                fg=self.COLORS['warning']
            )
        elif not self.alice_logged_in and self.bob_logged_in:
            self.status_label.config(
                text="✅ Bob logged in, waiting for Alice...",
                fg=self.COLORS['warning']
            )
        else:
            # Both logged in - check key state
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
            else:
                self.status_label.config(
                    text="🔐 Authenticated - Generate keys to begin",
                    fg=self.COLORS['accent_green']
                )
    
    def _run_demo(self):
        """Run a complete demo with sample file."""
        # Security check: Verify session is active
        if not self.alice_session_active or not self.bob_session_active:
            messagebox.showerror("Security Error", 
                "Session verification failed. Please re-authenticate.")
            self._hide_main_interface()
            return
        
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
