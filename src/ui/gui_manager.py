"""
GUI Manager for Physical Security System
Provides full-screen startup screen, login interface, and dashboard.
Modern themed interface with enhanced visual design.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import os
import string
import secrets
from datetime import datetime
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from ..core.config import Config
from ..utils.security_utils import SecurityUtils
from ..auth.ldap_auth import LDAPAuthenticator
from ..auth.deepface_auth import DeepFaceAuthenticator
from ..auth.biometric_auth import BiometricAuthenticator
import secrets
import string


class SecurityGUI:
    """Main GUI class for the Physical Security System."""
    
    def __init__(self, auth_manager=None, detector_service=None):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.auth_manager = auth_manager
        self.deepface_auth = DeepFaceAuthenticator()
        self.biometric_auth = BiometricAuthenticator()  # Add biometric auth
        self.ldap_auth = LDAPAuthenticator(Config())  # Initialize with config
        self.detector_service = detector_service  # Reference to detection service
        self.is_authenticated = False
        self.current_user = None
        self.current_role = None
        self.current_screen = None
        self.is_minimized = False
        self.detection_running = False
        
        # User management form variables
        self.username_var = tk.StringVar()
        self.first_name_var = tk.StringVar()
        self.last_name_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.role_var = tk.StringVar(value="user")
        self.selected_image_path = ""
        self.ldap_user_var = tk.StringVar()
        self.ldap_pass_var = tk.StringVar()
        
        # Setup modern theme
        self.setup_modern_theme()
        
        # Configure main window
        self.setup_window()
        
    def setup_modern_theme(self):
        """Setup modern theme and colors for the GUI."""
        self.style = ttk.Style()
        
        # Try to use a modern theme
        available_themes = self.style.theme_names()
        preferred_themes = ['vista', 'xpnative', 'winnative', 'clam', 'alt', 'default']
        
        selected_theme = 'clam'  # Default fallback
        for theme in preferred_themes:
            if theme in available_themes:
                selected_theme = theme
                break
        
        self.style.theme_use(selected_theme)
        
        # Modern color scheme
        self.colors = {
            'primary': '#1e3a8a',      # Deep blue
            'primary_light': '#3b82f6', # Light blue
            'secondary': '#0f172a',     # Dark blue/black
            'accent': '#06b6d4',        # Cyan
            'success': '#10b981',       # Green
            'warning': '#f59e0b',       # Orange
            'danger': '#ef4444',        # Red
            'light': '#f8fafc',         # Light gray
            'dark': '#1f2937',          # Dark gray
            'surface': '#ffffff',       # White
            'on_surface': '#374151',    # Text on white
            'background': '#f1f5f9',    # Light background
            'card': '#ffffff',          # Card background
            'border': '#e5e7eb'         # Border color
        }
        
        # Configure modern styles
        self.configure_modern_styles()
    
    def configure_modern_styles(self):
        """Configure modern ttk styles."""
        # Modern button styles
        self.style.configure('Modern.TButton',
                           background=self.colors['primary'],
                           foreground='white',
                           borderwidth=1,
                           focuscolor='none',
                           padding=(20, 10))
        
        self.style.map('Modern.TButton',
                      background=[('active', self.colors['primary_light']),
                                ('pressed', self.colors['secondary'])])
        
        # Success button
        self.style.configure('Success.TButton',
                           background=self.colors['success'],
                           foreground='white',
                           borderwidth=1,
                           focuscolor='none',
                           padding=(20, 10))
        
        # Danger button
        self.style.configure('Danger.TButton',
                           background=self.colors['danger'],
                           foreground='white',
                           borderwidth=1,
                           focuscolor='none',
                           padding=(20, 10))
        
        # Warning button
        self.style.configure('Warning.TButton',
                           background=self.colors['warning'],
                           foreground='white',
                           borderwidth=1,
                           focuscolor='none',
                           padding=(20, 10))
        
        # Modern entry style
        self.style.configure('Modern.TEntry',
                           fieldbackground='white',
                           borderwidth=1,
                           relief='solid',
                           padding=(10, 8))
        
        # Modern frame style
        self.style.configure('Card.TFrame',
                           background=self.colors['card'],
                           relief='flat',
                           borderwidth=1)
        
        # Modern treeview style
        self.style.configure('Modern.Treeview',
                           background=self.colors['surface'],
                           foreground=self.colors['on_surface'],
                           fieldbackground=self.colors['surface'],
                           borderwidth=0,
                           font=('Segoe UI', 9))
        self.style.configure('Modern.Treeview.Heading',
                           background=self.colors['primary'],
                           foreground='white',
                           font=('Segoe UI', 10, 'bold'))
        self.style.map('Modern.Treeview',
                      background=[('selected', self.colors['primary_light'])])
        self.style.map('Modern.Treeview.Heading',
                      background=[('active', self.colors['primary_light'])])
        
        # Modern label style
        self.style.configure('Heading.TLabel',
                           background=self.colors['card'],
                           foreground=self.colors['on_surface'],
                           font=('Segoe UI', 14, 'bold'))
        
        self.style.configure('Body.TLabel',
                           background=self.colors['card'],
                           foreground=self.colors['on_surface'],
                           font=('Segoe UI', 10))
        
        # Modern treeview
        self.style.configure('Modern.Treeview',
                           background='white',
                           foreground=self.colors['on_surface'],
                           fieldbackground='white',
                           borderwidth=1,
                           relief='solid')
        
        self.style.configure('Modern.Treeview.Heading',
                           background=self.colors['primary'],
                           foreground='white',
                           relief='flat',
                           borderwidth=1)
        
    def setup_window(self):
        """Configure the main window properties with modern styling."""
        self.root.title("Physical Security System")
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.configure(bg=self.colors['background'])
        self.root.resizable(False, False)
        
        # Security: Prevent closing
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Disable keyboard shortcuts for security
        self.root.bind('<Alt-F4>', lambda e: None)
        self.root.bind('<Control-c>', lambda e: None)
        self.root.bind('<Control-C>', lambda e: None)
        
        # Setup window event handlers
        self.setup_window_events()
        
    def create_modern_button(self, parent, text, command, style='Modern.TButton', **kwargs):
        """Create a modern styled button."""
        return ttk.Button(parent, text=text, command=command, style=style, **kwargs)
    
    def create_modern_entry(self, parent, textvariable=None, show=None, width=None, **kwargs):
        """Create a modern styled entry widget that returns the actual entry."""        
        # Create the actual entry widget with modern styling
        entry = tk.Entry(parent, 
                        textvariable=textvariable, 
                        show=show,
                        width=width or 40,
                        font=("Segoe UI", 10), 
                        bg=self.colors['surface'], 
                        fg=self.colors['on_surface'], 
                        relief='solid', 
                        bd=1,
                        insertbackground=self.colors['on_surface'],
                        highlightthickness=1,
                        highlightcolor=self.colors['primary'],
                        highlightbackground=self.colors['border'],
                        **kwargs)
        
        # Return the actual entry widget
        return entry
    
    def create_gradient_frame(self, parent, color1, color2, height=100):
        """Create a gradient-like frame using canvas."""
        canvas = tk.Canvas(parent, height=height, highlightthickness=0, bd=0, relief='flat')
        canvas.pack(fill='x')
        
        def hex_to_rgb(hex_color):
            """Convert hex color to RGB tuple."""
            hex_color = hex_color.lstrip('#')
            return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        
        def rgb_to_hex(rgb):
            """Convert RGB tuple to hex color."""
            return "#{:02x}{:02x}{:02x}".format(int(rgb[0]), int(rgb[1]), int(rgb[2]))
        
        def interpolate_color(color1, color2, ratio):
            """Interpolate between two colors."""
            rgb1 = hex_to_rgb(color1)
            rgb2 = hex_to_rgb(color2)
            
            r = rgb1[0] + (rgb2[0] - rgb1[0]) * ratio
            g = rgb1[1] + (rgb2[1] - rgb1[1]) * ratio
            b = rgb1[2] + (rgb2[2] - rgb1[2]) * ratio
            
            return rgb_to_hex((r, g, b))
        
        def draw_gradient():
            width = canvas.winfo_width()
            if width > 1:
                canvas.delete("all")
                # Create smooth gradient with more steps for better quality
                steps = min(height, 100)  # Limit steps for performance
                step_height = height / steps
                
                for i in range(steps):
                    y1 = int(i * step_height)
                    y2 = int((i + 1) * step_height)
                    ratio = i / (steps - 1) if steps > 1 else 0
                    
                    gradient_color = interpolate_color(color1, color2, ratio)
                    canvas.create_rectangle(0, y1, width, y2, 
                                          fill=gradient_color, outline=gradient_color)
        
        # Bind the gradient drawing to canvas configuration
        canvas.bind('<Configure>', lambda e: canvas.after_idle(draw_gradient))
        
        # Draw initial gradient
        canvas.after_idle(draw_gradient)
        
        return canvas
        
    def maintain_security_properties(self):
        """Ensure security properties are maintained - call this periodically."""
        # Reapply security properties in case they were somehow modified
        self.root.attributes("-topmost", True)
        self.root.attributes("-fullscreen", True)
        self.root.resizable(False, False)
        
    def clear_screen(self):
        """Clear all widgets from the root window and maintain security properties."""
        for widget in self.root.winfo_children():
            widget.destroy()
        # Ensure security properties are maintained after clearing screen
        self.maintain_security_properties()
    
    def show_custom_dialog(self, title, message, dialog_type="info", input_field=False, password=False, callback=None):
        """Show a modern custom dialog within the GUI."""
        # Create modern overlay with semi-transparent background
        self.dialog_overlay = tk.Frame(self.root, bg='#000000')
        self.dialog_overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self.dialog_overlay.configure(bg='#404040')  # Dark gray instead of transparent
        
        # Modern dialog frame with rounded appearance
        dialog_frame = tk.Frame(self.dialog_overlay, bg=self.colors['card'], 
                               relief='flat', bd=0)
        dialog_frame.place(relx=0.5, rely=0.5, anchor='center', width=480, height=320)
        
        # Add subtle shadow effect
        shadow_frame = tk.Frame(self.dialog_overlay, bg='#808080', relief='flat', bd=0)
        shadow_frame.place(relx=0.5, rely=0.5, anchor='center', width=485, height=325)
        
        # Bring dialog to front
        dialog_frame.lift()
        
        # Modern header with icon and title
        header_frame = tk.Frame(dialog_frame, bg=self.colors['primary'], height=60)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Dialog icon based on type
        icons = {
            "info": "ℹ️",
            "success": "✅", 
            "warning": "⚠️",
            "error": "❌",
            "question": "❓",
            "yesno": "❓"
        }
        icon = icons.get(dialog_type, "ℹ️")
        
        icon_label = tk.Label(header_frame, text=icon, 
                             bg=self.colors['primary'], fg='white',
                             font=("Segoe UI", 20))
        icon_label.pack(side='left', padx=20, pady=15)
        
        title_label = tk.Label(header_frame, text=title,
                              bg=self.colors['primary'], fg='white',
                              font=("Segoe UI", 14, "bold"))
        title_label.pack(side='left', pady=15)
        
        # Content area
        content_frame = tk.Frame(dialog_frame, bg=self.colors['card'])
        content_frame.pack(fill='both', expand=True, padx=30, pady=20)
        
        # Modern message display
        message_label = tk.Label(content_frame, text=message,
                               fg=self.colors['on_surface'], bg=self.colors['card'],
                               font=("Segoe UI", 11), wraplength=400, justify='left')
        message_label.pack(pady=(0, 20))
        
        # Modern input field if needed
        self.dialog_input = None
        if input_field:
            input_label = tk.Label(content_frame, text="Enter value:",
                                 fg=self.colors['on_surface'], bg=self.colors['card'],
                                 font=("Segoe UI", 10, "bold"))
            input_label.pack(anchor='w', pady=(0, 5))
            
            self.dialog_input = tk.Entry(content_frame,
                                       font=("Segoe UI", 11), bg=self.colors['surface'],
                                       fg=self.colors['on_surface'], relief='flat', bd=0,
                                       insertbackground=self.colors['on_surface'],
                                       show="*" if password else "")
            
            # Style the entry with a border frame
            input_frame = tk.Frame(content_frame, bg=self.colors['border'], 
                                 relief='solid', bd=1)
            input_frame.pack(fill='x', pady=(0, 20))
            self.dialog_input.pack(in_=input_frame, padx=8, pady=6, fill='x')
            self.dialog_input.focus_set()
        
        # Modern buttons frame
        buttons_frame = tk.Frame(content_frame, bg=self.colors['card'])
        buttons_frame.pack(side='bottom', pady=(10, 0))
        
        if dialog_type == "yesno":
            # Modern Yes button
            yes_btn = tk.Button(buttons_frame, text="✓ Yes",
                              command=lambda: self._close_dialog_with_result(True, callback),
                              font=("Segoe UI", 10, "bold"), bg=self.colors['success'], 
                              fg='white', relief='flat', bd=0, padx=20, pady=8)
            yes_btn.pack(side='left', padx=(0, 10))
            
            # Modern No button  
            no_btn = tk.Button(buttons_frame, text="✗ No",
                             command=lambda: self._close_dialog_with_result(False, callback),
                             font=("Segoe UI", 10, "bold"), bg=self.colors['danger'], 
                             fg='white', relief='flat', bd=0, padx=20, pady=8)
            no_btn.pack(side='left')
            
        elif input_field:
            # Modern OK button for input
            ok_btn = tk.Button(buttons_frame, text="✓ Confirm",
                             command=lambda: self._close_dialog_with_input(callback),
                             font=("Segoe UI", 10, "bold"), bg=self.colors['primary'], 
                             fg='white', relief='flat', bd=0, padx=20, pady=8)
            ok_btn.pack(side='left', padx=(0, 10))
            
            # Modern Cancel button
            cancel_btn = tk.Button(buttons_frame, text="✗ Cancel",
                                 command=lambda: self._close_dialog_with_result(None, callback),
                                 font=("Segoe UI", 10, "bold"), bg=self.colors['dark'], 
                                 fg='white', relief='flat', bd=0, padx=20, pady=8)
            cancel_btn.pack(side='left')
            
            # Bind Enter key for quick confirmation
            if self.dialog_input:
                self.dialog_input.bind('<Return>', lambda e: self._close_dialog_with_input(callback))
                self.dialog_input.bind('<Escape>', lambda e: self._close_dialog_with_result(None, callback))
        else:
            # Modern OK button for info/error dialogs
            button_colors = {
                "info": self.colors['primary'],
                "success": self.colors['success'], 
                "warning": self.colors['warning'],
                "error": self.colors['danger']
            }
            button_color = button_colors.get(dialog_type, self.colors['primary'])
            
            ok_btn = tk.Button(buttons_frame, text="✓ OK",
                             command=lambda: self._close_dialog_with_result(True, callback),
                             font=("Segoe UI", 10, "bold"), bg=button_color, 
                             fg='white', relief='flat', bd=0, padx=30, pady=8)
            ok_btn.pack()
    
    def _close_dialog_with_result(self, result, callback):
        """Close dialog and execute callback with result."""
        if hasattr(self, 'dialog_overlay'):
            self.dialog_overlay.destroy()
        if callback:
            callback(result)
    
    def _close_dialog_with_input(self, callback):
        """Close dialog and execute callback with input value."""
        value = self.dialog_input.get() if self.dialog_input else None
        if hasattr(self, 'dialog_overlay'):
            self.dialog_overlay.destroy()
        if callback:
            callback(value)

    def run(self):
        """Run the GUI main loop."""
        self.show_startup_screen()
        self.root.mainloop()
    
    def is_ready_for_detection(self):
        """Check if GUI is ready for detection system to start."""
        return self.is_authenticated
    
    def show_startup_screen(self):
        """Show the modern startup screen with loading animation."""
        self.clear_screen()
        self.current_screen = "startup"
        
        # Main container with solid background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header with modern solid color
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=120)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        header_title = tk.Label(
            header_frame,
            text="🔒 PHYSICAL SECURITY SYSTEM",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 24, "bold")
        )
        header_title.pack(expand=True)
        
        # Center frame for content
        center_frame = tk.Frame(main_frame, bg=self.colors['background'])
        center_frame.pack(expand=True, fill='both')
        
        # Modern logo container
        logo_frame = tk.Frame(center_frame, bg=self.colors['background'])
        logo_frame.pack(expand=True)
        
        # Logo with modern styling
        logo_label = tk.Label(
            logo_frame,
            text="🔒",
            fg=self.colors['primary'],
            bg=self.colors['background'],
            font=("Segoe UI", 100, "bold")
        )
        logo_label.pack(pady=(50, 20))
        
        # Modern title
        title_label = tk.Label(
            logo_frame,
            text="PHYSICAL SECURITY SYSTEM",
            fg=self.colors['on_surface'],
            bg=self.colors['background'],
            font=("Segoe UI", 28, "bold")
        )
        title_label.pack(pady=(0, 5))
        
        # Subtitle with modern typography
        subtitle_label = tk.Label(
            logo_frame,
            text="Advanced Object Detection & Access Control",
            fg=self.colors['primary'],
            bg=self.colors['background'],
            font=("Segoe UI", 14, "normal")
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Modern loading card
        loading_card = self.create_modern_card(logo_frame, "System Status")
        loading_card.pack(pady=20, padx=50, fill='x')
        
        # Loading label with modern font
        self.loading_label = tk.Label(
            loading_card,
            text="Initializing System...",
            fg=self.colors['primary'],
            bg=self.colors['card'],
            font=("Segoe UI", 12, "normal")
        )
        self.loading_label.pack(pady=15)
        
        # Modern progress indicator
        self.progress_frame = tk.Frame(loading_card, bg=self.colors['card'])
        self.progress_frame.pack(pady=(0, 15))
        
        # Progress dots with animation
        self.progress_dots = []
        for i in range(3):
            dot = tk.Label(
                self.progress_frame,
                text="●",
                fg=self.colors['primary_light'],
                bg=self.colors['card'],
                font=("Segoe UI", 16)
            )
            dot.pack(side='left', padx=5)
            self.progress_dots.append(dot)
        
        # Start modern loading animation
        self.animate_modern_loading()

        # Auto-proceed to login after 2.5 seconds
        self.root.after(2500, self.show_login_screen)
        
    def animate_modern_loading(self):
        """Modern loading animation with color-changing dots."""
        def update_dots():
            for cycle in range(6):  # 6 animation cycles
                for i in range(len(self.progress_dots)):
                    # Reset all dots
                    for dot in self.progress_dots:
                        dot.config(fg=self.colors['border'])
                    
                    # Highlight current dot
                    if i < len(self.progress_dots):
                        self.progress_dots[i].config(fg=self.colors['accent'])
                    
                    time.sleep(0.3)
        
        threading.Thread(target=update_dots, daemon=True).start()
        
    def animate_loading(self):
        """Animate loading dots."""
        def update_dots():
            for i in range(4):
                if self.current_screen != "startup":
                    return
                dots = "." * i
                self.progress_label.config(text=dots)
                self.root.update_idletasks()
                time.sleep(0.5)
        
        threading.Thread(target=update_dots, daemon=True).start()
    
    def show_login_screen(self):
        """Show the modern login/authentication screen."""
        self.clear_screen()
        self.current_screen = "login"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header with gradient
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=120)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Header content
        header_content = tk.Frame(header_frame, bg=self.colors['primary'])
        header_content.pack(expand=True, fill='both', padx=40, pady=20)
        
        title_label = tk.Label(
            header_content,
            text="🔐 SYSTEM AUTHENTICATION",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 24, "bold")
        )
        title_label.pack(expand=True)
        
        # Center authentication frame with compact design
        auth_container = tk.Frame(main_frame, bg=self.colors['background'])
        auth_container.pack(expand=True, fill='both')
        
        # Center the cards horizontally and vertically with proper sizing
        cards_frame = tk.Frame(auth_container, bg=self.colors['background'])
        cards_frame.pack(expand=True)
        
        # Welcome card - compact size
        welcome_card = self.create_modern_card(cards_frame, "Welcome")
        welcome_card.pack(pady=(50, 20), padx=50)
        
        welcome_label = tk.Label(
            welcome_card,
            text="Please select your authentication method to access the security system",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 14, "normal"),
            wraplength=500,
            justify='center'
        )
        welcome_label.pack(pady=20, padx=30)
        
        # Authentication methods card - compact size
        methods_card = self.create_modern_card(cards_frame, "Authentication Methods")
        methods_card.pack(pady=10, padx=50)
        
        # Create modern authentication buttons
        self.create_modern_auth_buttons(methods_card)
        
        # Footer with system info
        footer_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=60)
        footer_frame.pack(fill='x', side='bottom')
        footer_frame.pack_propagate(False)
        
        sys_info = SecurityUtils.get_system_info()
        footer_text = f"System: {sys_info['computer_name']} | User: {sys_info['username']} | IP: {sys_info['ip_address']}"
        footer_label = tk.Label(
            footer_frame,
            text=footer_text,
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 10, "normal")
        )
        footer_label.pack(expand=True)
        
    def create_modern_auth_buttons(self, parent):
        """Create modern authentication method buttons."""
        methods_frame = tk.Frame(parent, bg=self.colors['card'])
        methods_frame.pack(pady=20, padx=30)
        
        # Create a compact layout for buttons
        buttons_container = tk.Frame(methods_frame, bg=self.colors['card'])
        buttons_container.pack()
        
        # Email & Password button with icon - compact width
        email_frame = tk.Frame(buttons_container, bg=self.colors['success'], relief='flat', bd=0)
        email_frame.pack(pady=10, fill='x')
        
        email_btn = tk.Button(
            email_frame,
            text="📧  Email & Password Authentication",
            command=lambda: self.select_auth_method("email_password"),
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2',
            width=35
        )
        email_btn.pack()
        
        # Add hover effects
        def on_enter_email(e):
            email_btn.config(bg=self.colors['primary_light'])
        def on_leave_email(e):
            email_btn.config(bg=self.colors['success'])
        
        email_btn.bind("<Enter>", on_enter_email)
        email_btn.bind("<Leave>", on_leave_email)
        
        # Fingerprint button - compact width
        fingerprint_frame = tk.Frame(buttons_container, bg=self.colors['primary'], relief='flat', bd=0)
        fingerprint_frame.pack(pady=10, fill='x')
        
        fingerprint_btn = tk.Button(
            fingerprint_frame,
            text="👆  Fingerprint Authentication",
            command=lambda: self.select_auth_method("fingerprint"),
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['primary'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2',
            width=35
        )
        fingerprint_btn.pack()
        
        # Add hover effects
        def on_enter_finger(e):
            fingerprint_btn.config(bg=self.colors['primary_light'])
        def on_leave_finger(e):
            fingerprint_btn.config(bg=self.colors['primary'])
        
        fingerprint_btn.bind("<Enter>", on_enter_finger)
        fingerprint_btn.bind("<Leave>", on_leave_finger)
        
        # DeepFace button - compact width
        deepface_frame = tk.Frame(buttons_container, bg=self.colors['warning'], relief='flat', bd=0)
        deepface_frame.pack(pady=10, fill='x')
        
        deepface_btn = tk.Button(
            deepface_frame,
            text="🧠  Advanced Face Recognition",
            command=lambda: self.select_auth_method("deepface"),
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['warning'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2',
            width=35
        )
        deepface_btn.pack()
        
        # Add hover effects
        def on_enter_deep(e):
            deepface_btn.config(bg=self.colors['primary_light'])
        def on_leave_deep(e):
            deepface_btn.config(bg=self.colors['warning'])
        
        deepface_btn.bind("<Enter>", on_enter_deep)
        deepface_btn.bind("<Leave>", on_leave_deep)
    
    def select_auth_method(self, method):
        """Handle authentication method selection."""
        if method == "email_password":  # Keep the same method name for compatibility
            self.show_domain_auth_form()
        elif method == "fingerprint":
            self.show_fingerprint_auth()
        elif method == "deepface":
            self.show_deepface_auth()
    
    def show_method_selection(self):
        """Show method selection screen."""
        self.show_login_screen()
    
    def show_domain_auth_form(self):
        """Show modern domain authentication form."""
        self.clear_screen()
        self.current_screen = "password_form"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header with success color
        header_frame = tk.Frame(main_frame, bg=self.colors['success'], height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="📧 EMAIL & PASSWORD AUTHENTICATION",
            fg='white',
            bg=self.colors['success'],
            font=("Segoe UI", 20, "bold")
        )
        title_label.pack(expand=True)
        
        # Center frame for form - compact design
        center_container = tk.Frame(main_frame, bg=self.colors['background'])
        center_container.pack(expand=True, fill='both')
        
        # Form card - centered with pack
        form_frame = tk.Frame(center_container, bg=self.colors['background'])
        form_frame.pack(expand=True)
        
        form_card = self.create_modern_card(form_frame, "Enter your credentials")
        form_card.pack(pady=50, padx=100)
        
        form_content = tk.Frame(form_card, bg=self.colors['card'])
        form_content.pack(padx=40, pady=30)
        
        # Username field
        username_label = tk.Label(
            form_content,
            text="Username:",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 12, "bold")
        )
        username_label.pack(anchor='w', pady=(0, 5))
        
        self.email_entry = self.create_modern_entry(form_content, width=30)
        self.email_entry.pack(pady=(0, 20))
        self.email_entry.focus_set()
        
        # Password field
        password_label = tk.Label(
            form_content,
            text="Password:",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 12, "bold")
        )
        password_label.pack(anchor='w', pady=(0, 5))
        
        self.password_entry = self.create_modern_entry(form_content, show="*", width=30)
        self.password_entry.pack(pady=(0, 30))
        
        # Bind Enter key
        self.password_entry.bind('<Return>', lambda e: self.attempt_password_login())
        
        # Buttons frame
        buttons_frame = tk.Frame(form_content, bg=self.colors['card'])
        buttons_frame.pack(fill='x')
        
        # Login button
        login_btn = tk.Button(
            buttons_frame,
            text="✓ Login",
            command=self.attempt_password_login,
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2'
        )
        login_btn.pack(side='left', padx=(0, 15))
        
        # Back button
        back_btn = tk.Button(
            buttons_frame,
            text="← Back",
            command=self.show_method_selection,
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['dark'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2'
        )
        back_btn.pack(side='left')
        
        # Add hover effects
        def on_enter_login(e):
            login_btn.config(bg=self.colors['primary'])
        def on_leave_login(e):
            login_btn.config(bg=self.colors['success'])
        
        def on_enter_back(e):
            back_btn.config(bg=self.colors['on_surface'])
        def on_leave_back(e):
            back_btn.config(bg=self.colors['dark'])
        
        login_btn.bind("<Enter>", on_enter_login)
        login_btn.bind("<Leave>", on_leave_login)
        back_btn.bind("<Enter>", on_enter_back)
        back_btn.bind("<Leave>", on_leave_back)
    
    def show_fingerprint_auth(self):
        """Show fingerprint authentication screen."""
        self.clear_screen()
        self.current_screen = "fingerprint"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header with primary color
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="👆 FINGERPRINT AUTHENTICATION",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 20, "bold")
        )
        title_label.pack(expand=True)
        
        # Center container - compact design
        center_container = tk.Frame(main_frame, bg=self.colors['background'])
        center_container.pack(expand=True, fill='both')
        
        # Authentication card - centered with pack
        auth_frame = tk.Frame(center_container, bg=self.colors['background'])
        auth_frame.pack(expand=True)
        
        auth_card = self.create_modern_card(auth_frame, "Biometric Authentication")
        auth_card.pack(pady=50, padx=100)
        
        auth_content = tk.Frame(auth_card, bg=self.colors['card'])
        auth_content.pack(padx=50, pady=30)
        
        # Fingerprint icon
        self.fingerprint_icon = tk.Label(
            auth_content,
            text="👆",
            fg=self.colors['primary'],
            bg=self.colors['card'],
            font=("Segoe UI", 80, "bold")
        )
        self.fingerprint_icon.pack(pady=(20, 30))
        
        # Instructions
        instructions_label = tk.Label(
            auth_content,
            text="Place your finger on the sensor\nand wait for authentication",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 16, "normal"),
            justify='center'
        )
        instructions_label.pack(pady=(0, 20))
        
        # Status label
        self.fingerprint_status = tk.Label(
            auth_content,
            text="Initializing sensor...",
            fg=self.colors['primary'],
            bg=self.colors['card'],
            font=("Segoe UI", 14, "bold")
        )
        self.fingerprint_status.pack(pady=10)
        
        # Buttons frame
        buttons_frame = tk.Frame(auth_content, bg=self.colors['card'])
        buttons_frame.pack(pady=(30, 0))
        
        # Cancel button
        cancel_btn = tk.Button(
            buttons_frame,
            text="← Cancel",
            command=self.show_method_selection,
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['dark'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2'
        )
        cancel_btn.pack()
        
        # Start authentication process
        self.root.after(1000, self.attempt_fingerprint_login)
    
    def attempt_password_login(self):
        """Attempt domain/password authentication."""
        username_input = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not username_input or not password:
            self.show_custom_dialog("Error", "Please enter both username and password", "error")
            return
        
        # Validate domain\username format
        if '\\' not in username_input:
            username_input = f"{Config.LDAP_DOMAIN}\\{username_input}"

        # Extract domain and username
        try:
            domain, username = username_input.split('\\', 1)
            if not domain or not username:
                raise ValueError("Invalid format")
        except ValueError:
            self.show_custom_dialog("Error", "Invalid username format. Use domain\\username", "error")
            return
        
        self.show_auth_loading("Authenticating with domain server...")
        
        # Simulate authentication delay
        def auth_thread():
            try:
                ldap_auth = LDAPAuthenticator(Config())
                success, result = ldap_auth.authenticate({
                    'username': username_input,
                    'password': password,
                    'domain': domain
                })
                
                if success:
                    # Extract role from LDAP result
                    role = result.get('role', 'user') if isinstance(result, dict) else 'user'
                    # Use just the username part for display
                    display_username = username
                    self.root.after(0, lambda: self.handle_auth_result(True, display_username, "domain_auth", role))
                else:
                    error_msg = result if isinstance(result, str) else "Authentication failed"
                    self.root.after(0, lambda: self.handle_auth_result(False, None, "domain_auth", error_msg))
            except Exception as e:
                error_msg = f"Domain authentication error: {str(e)}"
                self.root.after(0, lambda: self.handle_auth_result(False, None, "domain_auth", error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def attempt_fingerprint_login(self):
        """Attempt fingerprint authentication."""
        if self.current_screen != "fingerprint":
            return
            
        self.fingerprint_status.config(text="Please place finger on sensor...")
        
        def auth_thread():
            try:
                result = self.biometric_auth.authenticate_fingerprint()
                if result:
                    self.root.after(0, lambda: self.handle_auth_result(True, result, "fingerprint", "user"))
                else:
                    self.root.after(0, lambda: self.handle_auth_result(False, None, "fingerprint", "Fingerprint not recognized"))
            except Exception as e:
                error_msg = f"Fingerprint authentication error: {str(e)}"
                self.root.after(0, lambda: self.handle_auth_result(False, None, "fingerprint", error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def show_deepface_auth(self):
        """Show DeepFace authentication screen."""
        self.clear_screen()
        self.current_screen = "deepface"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header with warning color for AI processing
        header_frame = tk.Frame(main_frame, bg=self.colors['warning'], height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🧠 ADVANCED FACE RECOGNITION",
            fg='white',
            bg=self.colors['warning'],
            font=("Segoe UI", 20, "bold")
        )
        title_label.pack(expand=True)
        
        # Center container - compact design
        center_container = tk.Frame(main_frame, bg=self.colors['background'])
        center_container.pack(expand=True, fill='both')
        
        # Authentication card - centered with pack
        auth_frame = tk.Frame(center_container, bg=self.colors['background'])
        auth_frame.pack(expand=True)
        
        auth_card = self.create_modern_card(auth_frame, "AI Face Recognition")
        auth_card.pack(pady=50, padx=100)
        
        auth_content = tk.Frame(auth_card, bg=self.colors['card'])
        auth_content.pack(padx=50, pady=30)
        
        # DeepFace icon
        self.deepface_icon = tk.Label(
            auth_content,
            text="🧠",
            fg=self.colors['warning'],
            bg=self.colors['card'],
            font=("Segoe UI", 80, "bold")
        )
        self.deepface_icon.pack(pady=(20, 30))
        
        # Instructions
        instructions_label = tk.Label(
            auth_content,
            text="Look directly at the camera\nAdvanced AI processing - please be patient\nEnsure good lighting and clear face visibility",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 16, "normal"),
            justify='center'
        )
        instructions_label.pack(pady=(0, 20))
        
        # Status label
        self.deepface_status = tk.Label(
            auth_content,
            text="Initializing AI models...",
            fg=self.colors['warning'],
            bg=self.colors['card'],
            font=("Segoe UI", 14, "bold")
        )
        self.deepface_status.pack(pady=10)
        
        # Buttons frame
        buttons_frame = tk.Frame(auth_content, bg=self.colors['card'])
        buttons_frame.pack(pady=(30, 0))
        
        # Cancel button
        cancel_btn = tk.Button(
            buttons_frame,
            text="← Cancel",
            command=self.show_method_selection,
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['dark'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2'
        )
        cancel_btn.pack()
        
        # Start authentication process
        self.root.after(0, self.attempt_deepface_login)
    
    def attempt_deepface_login(self):
        """Attempt DeepFace authentication."""
        if self.current_screen != "deepface":
            return
            
        self.deepface_status.config(text="Scanning with AI models...")
        
        def auth_thread():
            try:
                result = self.deepface_auth.authenticate_face(timeout=30)
                if result:
                    username = result['username']
                    role = result.get('role', 'user')
                    
                    # Check if password is required for LDAP authentication
                    if result.get('requires_password') or (result.get('password_hash') and result.get('salt')):
                        # Face recognized, now need password for LDAP
                        self.root.after(0, lambda: self.prompt_password_for_ldap(username, result))
                    else:
                        # Face authentication only (no stored password)
                        self.root.after(0, lambda: self.handle_auth_result(True, username, "deepface", role))
                else:
                    self.root.after(0, lambda: self.handle_auth_result(False, None, "deepface", "Face not recognized by AI"))
            except Exception as e:
                error_msg = f"DeepFace authentication error: {str(e)}"
                self.root.after(0, lambda: self.handle_auth_result(False, None, "deepface", error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def prompt_password_for_ldap(self, username, face_result):
        """Prompt for password after successful face recognition for LDAP authentication."""
        self.clear_screen()
        self.current_screen = "password_prompt"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header with success color (face recognized)
        header_frame = tk.Frame(main_frame, bg=self.colors['success'], height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text=f"✅ Face Recognized: {username}",
            fg='white',
            bg=self.colors['success'],
            font=("Segoe UI", 20, "bold")
        )
        title_label.pack(expand=True)
        
        # Center container
        center_container = tk.Frame(main_frame, bg=self.colors['background'])
        center_container.pack(expand=True, fill='both', padx=150, pady=50)
        
        # Password prompt card
        password_card = self.create_modern_card(center_container, "Domain Authentication Required")
        password_card.pack(fill='both', expand=True)
        
        password_content = tk.Frame(password_card, bg=self.colors['card'])
        password_content.pack(expand=True, fill='both', padx=40, pady=30)
        
        # Instructions
        subtitle_label = tk.Label(
            password_content,
            text="Your face has been recognized successfully.\nPlease enter your domain password to complete authentication.",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 14, "normal"),
            justify='center'
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Password field
        password_label = tk.Label(
            password_content,
            text="Password:",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 12, "bold")
        )
        password_label.pack(anchor='w', pady=(0, 5))
        
        password_entry = self.create_modern_entry(password_content, show="*", width=30)
        password_entry.pack(fill='x', pady=(0, 20))
        password_entry.focus_set()
        
        # Status label
        status_label = tk.Label(
            password_content,
            text="",
            fg=self.colors['danger'],
            bg=self.colors['card'],
            font=("Segoe UI", 12, "normal")
        )
        status_label.pack(pady=10)
        
        # Buttons frame
        buttons_frame = tk.Frame(password_content, bg=self.colors['card'])
        buttons_frame.pack(pady=(20, 0))
        
        def authenticate_with_password():
            password = password_entry.get().strip()
            if not password:
                status_label.config(text="Password cannot be empty", fg=self.colors['danger'])
                return
            
            status_label.config(text="Authenticating with domain...", fg=self.colors['primary'])
            
            def ldap_auth_thread():
                try:
                    result = self.deepface_auth.authenticate_user_with_stored_password(username, password)
                    if result:
                        role = result.get('role', 'user')
                        self.root.after(0, lambda: self.handle_auth_result(True, username, "face_and_ldap", role))
                    else:
                        self.root.after(0, lambda: status_label.config(text="Invalid password or domain authentication failed", fg=self.colors['danger']))
                except Exception as e:
                    error_msg = f"Authentication error: {str(e)}"
                    self.root.after(0, lambda: status_label.config(text=error_msg, fg=self.colors['danger']))
            
            threading.Thread(target=ldap_auth_thread, daemon=True).start()
        
        def cancel_auth():
            self.show_method_selection()
        
        # Authenticate button
        auth_btn = tk.Button(
            buttons_frame,
            text="✓ Authenticate",
            command=authenticate_with_password,
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2'
        )
        auth_btn.pack(side='left', padx=(0, 15))
        
        # Cancel button
        cancel_btn = tk.Button(
            buttons_frame,
            text="← Cancel",
            command=cancel_auth,
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['dark'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2'
        )
        cancel_btn.pack(side='left')
        
        # Bind Enter key to authenticate
        password_entry.bind('<Return>', lambda e: authenticate_with_password())
    
    def show_auth_loading(self, message):
        """Show authentication loading screen."""
        self.clear_screen()
        self.current_screen = "loading"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        header_title = tk.Label(
            header_frame,
            text="🔄 AUTHENTICATING",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 20, "bold")
        )
        header_title.pack(expand=True)
        
        # Center container
        center_container = tk.Frame(main_frame, bg=self.colors['background'])
        center_container.pack(expand=True, fill='both', padx=150, pady=100)
        
        # Loading card
        loading_card = self.create_modern_card(center_container, "Please Wait")
        loading_card.pack(fill='both', expand=True)
        
        loading_content = tk.Frame(loading_card, bg=self.colors['card'])
        loading_content.pack(expand=True, fill='both', padx=40, pady=30)
        
        # Loading spinner
        spinner_label = tk.Label(
            loading_content,
            text="⟳",
            fg=self.colors['primary'],
            bg=self.colors['card'],
            font=("Segoe UI", 60, "bold")
        )
        spinner_label.pack(pady=(20, 30))
        
        # Loading message
        message_label = tk.Label(
            loading_content,
            text=message,
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 16, "normal"),
            justify='center'
        )
        message_label.pack(pady=(0, 20))
    
    def handle_auth_result(self, success, username, method, role_or_error):
        """Handle authentication result."""
        if success:
            self.show_auth_success(username, role_or_error)
        else:
            self.show_auth_failure(role_or_error)
    
    def show_auth_success(self, username, role):
        """Show modern authentication success screen."""
        self.is_authenticated = True
        self.current_user = username
        self.current_role = role
        
        SecurityUtils.log_security_event("GUI_AUTH_SUCCESS", f"GUI authentication successful for user: {username}")
        
        # Show modern success screen
        self.clear_screen()
        self.current_screen = "success"
        
        # Center frame with gradient background
        center_frame = tk.Frame(self.root, bg=self.colors['success'])
        center_frame.pack(expand=True, fill='both')
        
        # Success content container
        content_frame = tk.Frame(center_frame, bg=self.colors['success'])
        content_frame.pack(expand=True)
        
        # Modern success icon with animation effect
        success_icon = tk.Label(
            content_frame,
            text="✅",
            fg='white',
            bg=self.colors['success'],
            font=("Segoe UI", 80, "bold")
        )
        success_icon.pack(pady=(100, 20))
        
        # Success message with modern typography
        success_label = tk.Label(
            content_frame,
            text="AUTHENTICATION SUCCESSFUL",
            fg='white',
            bg=self.colors['success'],
            font=("Segoe UI", 26, "bold")
        )
        success_label.pack(pady=(0, 15))
        
        # User info card
        info_card = tk.Frame(content_frame, bg='white', relief='flat', bd=0)
        info_card.pack(pady=20, padx=100, fill='x')
        
        user_info = tk.Label(
            info_card,
            text=f"Welcome, {username}",
            fg=self.colors['on_surface'],
            bg='white',
            font=("Segoe UI", 16, "bold")
        )
        user_info.pack(pady=20)
        
        if role:
            role_info = tk.Label(
                info_card,
                text=f"Role: {role.upper()}",
                fg=self.colors['primary'],
                bg='white',
                font=("Segoe UI", 12, "normal")
            )
            role_info.pack(pady=(0, 20))
        
        # Loading message
        loading_label = tk.Label(
            content_frame,
            text="Loading Dashboard...",
            fg='white',
            bg=self.colors['success'],
            font=("Segoe UI", 12, "normal")
        )
        loading_label.pack(pady=20)
        
        # Auto-proceed to dashboard after 2 seconds
        self.root.after(2000, self.show_dashboard)
    
    def show_dashboard(self):
        """Show the modern main dashboard after successful authentication."""
        self.clear_screen()
        self.current_screen = "dashboard"
        
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Modern header with gradient effect
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Header content
        header_content = tk.Frame(header_frame, bg=self.colors['primary'])
        header_content.pack(fill='both', expand=True, padx=30, pady=15)
        
        # Title section
        title_section = tk.Frame(header_content, bg=self.colors['primary'])
        title_section.pack(side='left', fill='y')
        
        title_label = tk.Label(
            title_section,
            text="🔒 PHYSICAL SECURITY SYSTEM",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 20, "bold")
        )
        title_label.pack(anchor='w')
        
        subtitle_label = tk.Label(
            title_section,
            text="Security Dashboard",
            fg=self.colors['accent'],
            bg=self.colors['primary'],
            font=("Segoe UI", 12, "normal")
        )
        subtitle_label.pack(anchor='w')
        
        # User info section
        user_section = tk.Frame(header_content, bg=self.colors['primary'])
        user_section.pack(side='right', fill='y')
        
        user_info = f"User: {self.current_user}"
        if self.current_role:
            user_info += f" | Role: {self.current_role.upper()}"
        user_info += " | Status: AUTHENTICATED"
        
        user_label = tk.Label(
            user_section,
            text=user_info,
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 11, "bold")
        )
        user_label.pack(anchor='e', pady=5)
        
        # Status indicator
        status_label = tk.Label(
            user_section,
            text="● ONLINE",
            fg=self.colors['success'],
            bg=self.colors['primary'],
            font=("Segoe UI", 10, "bold")
        )
        status_label.pack(anchor='e')
        
        # Content area with modern cards
        content_frame = tk.Frame(main_frame, bg=self.colors['background'])
        content_frame.pack(expand=True, fill='both', padx=30, pady=20)
        
        # Welcome section
        self.create_welcome_section(content_frame)
        
        # Control sections
        self.create_control_sections(content_frame)
        
        # Bottom navigation
        self.create_bottom_navigation(main_frame)
        
    def create_welcome_section(self, parent):
        """Create modern welcome section."""
        welcome_card = self.create_modern_card(parent, "System Status")
        welcome_card.pack(fill='x', pady=(0, 20))
        
        welcome_content = tk.Frame(welcome_card, bg=self.colors['card'])
        welcome_content.pack(fill='x', padx=30, pady=20)
        
        welcome_label = tk.Label(
            welcome_content,
            text=f"Welcome back, {self.current_user}!",
            fg=self.colors['primary'],
            bg=self.colors['card'],
            font=("Segoe UI", 22, "bold")
        )
        welcome_label.pack(anchor='w')
        
        # Status indicators
        status_frame = tk.Frame(welcome_content, bg=self.colors['card'])
        status_frame.pack(fill='x', pady=(10, 0))
        
        # Detection status
        detection_status = "🔍 Detection: Inactive (GUI active)" if not self.detection_running else "🔍 Detection: Active"
        detection_label = tk.Label(
            status_frame,
            text=detection_status,
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 11, "normal")
        )
        detection_label.pack(anchor='w', pady=2)
        
        # Camera status
        camera_status = "📹 Camera: Available for Registration" if not self.detection_running else "📹 Camera: In use by Detection"
        camera_label = tk.Label(
            status_frame,
            text=camera_status,
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 11, "normal")
        )
        camera_label.pack(anchor='w', pady=2)
        
        # Instructions
        instructions = "💡 Minimize window to start detection | ⌨️ Press Ctrl+Shift+R to restore from tray"
        instructions_label = tk.Label(
            status_frame,
            text=instructions,
            fg=self.colors['accent'],
            bg=self.colors['card'],
            font=("Segoe UI", 10, "italic")
        )
        instructions_label.pack(anchor='w', pady=(10, 0))
    
    def create_control_sections(self, parent):
        """Create modern control sections."""
        # Controls container
        controls_container = tk.Frame(parent, bg=self.colors['background'])
        controls_container.pack(fill='both', expand=True)
        
        # Admin controls (only show for admin users)
        if self.current_role and self.current_role.lower() in ['admin', 'administrator']:
            admin_card = self.create_modern_card(controls_container, "Administrator Controls")
            admin_card.pack(fill='x', pady=(0, 15))
            
            admin_content = tk.Frame(admin_card, bg=self.colors['card'])
            admin_content.pack(fill='x', padx=30, pady=20)
            
            admin_buttons = tk.Frame(admin_content, bg=self.colors['card'])
            admin_buttons.pack()
            
            # User Management button
            user_mgmt_btn = tk.Button(
                admin_buttons,
                text="👥 User Management",
                command=self.show_user_management,
                font=("Segoe UI", 12, "bold"),
                bg=self.colors['warning'],
                fg='white',
                relief='flat',
                bd=0,
                padx=25,
                pady=12,
                cursor='hand2'
            )
            user_mgmt_btn.pack(side='left', padx=(0, 15))
            
            # View Logs button
            logs_btn = tk.Button(
                admin_buttons,
                text="📋 Security Logs",
                command=self.show_security_logs,
                font=("Segoe UI", 12, "bold"),
                bg=self.colors['primary'],
                fg='white',
                relief='flat',
                bd=0,
                padx=25,
                pady=12,
                cursor='hand2'
            )
            logs_btn.pack(side='left')
        
        # Common controls
        # common_card = self.create_modern_card(controls_container, "System Controls")
        # common_card.pack(fill='x', pady=(0, 15))
        
        # Add system control buttons here as needed
        
    def create_bottom_navigation(self, parent):
        """Create modern bottom navigation."""
        bottom_frame = tk.Frame(parent, bg=self.colors['dark'], height=80)
        bottom_frame.pack(fill='x', side='bottom')
        bottom_frame.pack_propagate(False)
        
        nav_content = tk.Frame(bottom_frame, bg=self.colors['dark'])
        nav_content.pack(fill='both', expand=True, padx=30, pady=15)
        
        # System info (left side)
        info_label = tk.Label(
            nav_content,
            text="Physical Security System v2.0 | Status: Active",
            fg='white',
            bg=self.colors['dark'],
            font=("Segoe UI", 10, "normal")
        )
        info_label.pack(side='left', anchor='w')
        
        # Action buttons (right side)
        buttons_frame = tk.Frame(nav_content, bg=self.colors['dark'])
        buttons_frame.pack(side='right')
        
        # Minimize button
        minimize_btn = tk.Button(
            buttons_frame,
            text="⬇ Minimize & Start Detection",
            command=self.minimize_to_system_tray,
            font=("Segoe UI", 10, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=8,
            cursor='hand2'
        )
        minimize_btn.pack(side='right', padx=(15, 0))
        
        # Logout button
        logout_btn = tk.Button(
            buttons_frame,
            text="🚪 Logout",
            command=self.logout,
            font=("Segoe UI", 10, "bold"),
            bg=self.colors['danger'],
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=8,
            cursor='hand2'
        )
        logout_btn.pack(side='right')
    
    def show_user_management(self):
        """Show the modern comprehensive user management interface within the GUI."""
        self.clear_screen()
        self.current_screen = "user_management"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Modern header
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=90)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        header_content = tk.Frame(header_frame, bg=self.colors['primary'])
        header_content.pack(fill='both', expand=True, padx=30, pady=15)
        
        # Title section
        title_label = tk.Label(
            header_content,
            text="👥 USER MANAGEMENT",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 20, "bold")
        )
        title_label.pack(side='left', anchor='w')
        
        # Back button
        back_btn = tk.Button(
            header_content,
            text="← Back to Dashboard",
            command=self.show_dashboard,
            font=("Segoe UI", 12, "bold"),
            bg='white',
            fg=self.colors['primary'],
            relief='flat',
            bd=0,
            padx=20,
            pady=8,
            cursor='hand2'
        )
        back_btn.pack(side='right', anchor='e')
        
        # Main content container
        content_container = tk.Frame(main_frame, bg=self.colors['background'])
        content_container.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Left panel container with scrollbar
        left_container = tk.Frame(content_container, bg=self.colors['background'], width=470)
        left_container.pack(side='left', fill='y', expand=False, padx=(0, 15))
        left_container.pack_propagate(False)
        
        # Create scrollable left panel
        left_canvas = tk.Canvas(left_container, bg=self.colors['background'], 
                               highlightthickness=0, width=450)
        left_scrollbar = ttk.Scrollbar(left_container, orient="vertical", command=left_canvas.yview)
        left_panel = tk.Frame(left_canvas, bg=self.colors['background'], width=430)
        
        def configure_scroll_region(event=None):
            left_canvas.configure(scrollregion=left_canvas.bbox("all"))
            # Make sure the inner frame fills the canvas width
            canvas_width = left_canvas.winfo_width()
            if canvas_width > 1:  # Only if canvas is actually visible
                left_canvas.itemconfig(canvas_window, width=canvas_width-20)
        
        left_panel.bind("<Configure>", configure_scroll_region)
        left_canvas.bind("<Configure>", configure_scroll_region)
        
        canvas_window = left_canvas.create_window((0, 0), window=left_panel, anchor="nw")
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        left_canvas.pack(side="left", fill="both", expand=True, padx=(0, 5))
        left_scrollbar.pack(side="right", fill="y")
        
        # Enhanced mousewheel binding for better scrolling
        def _on_mousewheel(event):
            if left_canvas.winfo_exists():
                left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def bind_mousewheel(widget):
            widget.bind("<MouseWheel>", _on_mousewheel)
            for child in widget.winfo_children():
                bind_mousewheel(child)
        
        # Bind mousewheel to canvas and all its children
        bind_mousewheel(left_canvas)
        
        # Also bind to the left panel and its children after they're created
        def bind_left_panel_mousewheel():
            bind_mousewheel(left_panel)
        
        # Schedule binding after the panel is populated
        left_container.after(100, bind_left_panel_mousewheel)
        
        # Right panel for output and user list
        right_panel = tk.Frame(content_container, bg=self.colors['background'])
        right_panel.pack(side='right', fill='both', expand=True)
        
        self.setup_modern_user_mgmt_left_panel(left_panel)
        self.setup_modern_user_mgmt_right_panel(right_panel)
    
    def setup_modern_user_mgmt_left_panel(self, parent):
        """Setup the modern left panel with user input and action buttons."""
        
        # Add padding container to ensure content doesn't touch edges
        padding_frame = tk.Frame(parent, bg=self.colors['background'])
        padding_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # User Information Card
        info_card = self.create_modern_card(padding_frame, "User Information")
        info_card.pack(fill='x', pady=(0, 15))
        
        info_content = tk.Frame(info_card, bg=self.colors['card'])
        info_content.pack(fill='x', padx=25, pady=20)
        
        # Modern form fields with better styling
        # Username
        tk.Label(info_content, text="Username:", 
                fg=self.colors['on_surface'], bg=self.colors['card'], 
                font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky='w', pady=(0, 5))
        username_entry = self.create_modern_entry(info_content, textvariable=self.username_var)
        username_entry.grid(row=1, column=0, sticky='ew', pady=(0, 15))
        
        # First Name
        tk.Label(info_content, text="First Name:", 
                fg=self.colors['on_surface'], bg=self.colors['card'], 
                font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky='w', pady=(0, 5))
        self.create_modern_entry(info_content, textvariable=self.first_name_var).grid(row=3, column=0, sticky='ew', pady=(0, 15))
        
        # Last Name
        tk.Label(info_content, text="Last Name:", 
                fg=self.colors['on_surface'], bg=self.colors['card'], 
                font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky='w', pady=(0, 5))
        self.create_modern_entry(info_content, textvariable=self.last_name_var).grid(row=5, column=0, sticky='ew', pady=(0, 15))
        
        # Email
        tk.Label(info_content, text="Email:", 
                fg=self.colors['on_surface'], bg=self.colors['card'], 
                font=("Segoe UI", 10, "bold")).grid(row=6, column=0, sticky='w', pady=(0, 5))
        self.create_modern_entry(info_content, textvariable=self.email_var).grid(row=7, column=0, sticky='ew', pady=(0, 15))
        
        # Role selection with modern radio buttons
        tk.Label(info_content, text="Role:", 
                fg=self.colors['on_surface'], bg=self.colors['card'], 
                font=("Segoe UI", 10, "bold")).grid(row=8, column=0, sticky='w', pady=(0, 5))
        
        role_frame = tk.Frame(info_content, bg=self.colors['card'])
        role_frame.grid(row=9, column=0, sticky='ew', pady=(0, 10))
        
        roles = [("User", "user"), ("Operator", "operator"), ("Admin", "admin")]
        for i, (text, value) in enumerate(roles):
            tk.Radiobutton(role_frame, text=text, variable=self.role_var, value=value,
                          fg=self.colors['on_surface'], bg=self.colors['card'], 
                          selectcolor=self.colors['accent'], 
                          font=("Segoe UI", 9)).pack(side='left', padx=10)
        
        # OU Information
        ou_info = tk.Label(info_content, 
                          text="📁 Users will be created in SecuritySystem OU", 
                          fg=self.colors['accent'], bg=self.colors['card'], 
                          font=("Segoe UI", 8, "italic"))
        ou_info.grid(row=10, column=0, sticky='w', pady=(0, 15))
        
        # Configure grid weights
        info_content.grid_columnconfigure(0, weight=1)
        
        # Clear button
        clear_btn = tk.Button(info_content, text="Clear Form", command=self.clear_user_form,
                             bg=self.colors['dark'], fg='white', 
                             font=("Segoe UI", 9, "bold"), relief='flat', bd=0, padx=15, pady=5)
        clear_btn.grid(row=11, column=0, sticky='e', pady=(0, 0))
        
        # Image Selection Card
        image_card = self.create_modern_card(padding_frame, "Face Image (Optional)")
        image_card.pack(fill='x', pady=(0, 15))
        
        image_content = tk.Frame(image_card, bg=self.colors['card'])
        image_content.pack(fill='x', padx=25, pady=15)
        
        self.image_label = tk.Label(image_content, text="No image selected", 
                                   fg=self.colors['on_surface'], bg=self.colors['card'], 
                                   font=("Segoe UI", 9, "italic"))
        self.image_label.pack(pady=(0, 10))
        
        select_img_btn = tk.Button(image_content, text="📁 Select Image File", 
                                  command=self.select_image_file,
                                  bg=self.colors['primary'], fg='white', 
                                  font=("Segoe UI", 10, "bold"), relief='flat', bd=0, 
                                  padx=15, pady=8)
        select_img_btn.pack()
        
        # Registration Actions Card
        reg_card = self.create_modern_card(padding_frame, "User Registration")
        reg_card.pack(fill='x', pady=(0, 15))
        
        reg_content = tk.Frame(reg_card, bg=self.colors['card'])
        reg_content.pack(fill='x', padx=25, pady=15)
        
        # Modern action buttons
        tk.Button(reg_content, text="📷 Register User + Face (Camera)", 
                 command=self.register_user_camera_unified,
                 bg=self.colors['success'], fg='white', 
                 font=("Segoe UI", 10, "bold"), relief='flat', bd=0, 
                 padx=15, pady=8).pack(fill='x', pady=3)
        
        tk.Button(reg_content, text="🖼️ Register User + Face (Image)", 
                 command=self.register_user_image_unified,
                 bg=self.colors['primary'], fg='white', 
                 font=("Segoe UI", 10, "bold"), relief='flat', bd=0, 
                 padx=15, pady=8).pack(fill='x', pady=3)
        
        tk.Button(reg_content, text="👤 Create LDAP User Only", 
                 command=self.create_ldap_user_only_unified,
                 bg=self.colors['warning'], fg='white', 
                 font=("Segoe UI", 10, "bold"), relief='flat', bd=0, 
                 padx=15, pady=8).pack(fill='x', pady=3)
        
        # Authentication Testing Card
        test_card = self.create_modern_card(padding_frame, "Authentication Testing")
        test_card.pack(fill='x', pady=(0, 15))
        
        test_content = tk.Frame(test_card, bg=self.colors['card'])
        test_content.pack(fill='x', padx=25, pady=15)
        
        # Test buttons
        test_buttons_frame = tk.Frame(test_content, bg=self.colors['card'])
        test_buttons_frame.pack(fill='x', pady=(0, 10))
        
        tk.Button(test_buttons_frame, text="🧠 Test DeepFace", 
                 command=self.test_deepface_auth_unified,
                 bg=self.colors['warning'], fg='white', 
                 font=("Segoe UI", 9, "bold"), relief='flat', bd=0, 
                 padx=10, pady=6).pack(side='left', padx=(0, 5))
        
        tk.Button(test_buttons_frame, text="👆 Test Fingerprint", 
                 command=self.test_fingerprint_auth_unified,
                 bg=self.colors['danger'], fg='white', 
                 font=("Segoe UI", 9, "bold"), relief='flat', bd=0, 
                 padx=10, pady=6).pack(side='left')
        
        # LDAP test section
        ldap_frame = tk.Frame(test_content, bg=self.colors['card'])
        ldap_frame.pack(fill='x', pady=(10, 0))
        
        # LDAP section title
        ldap_title = tk.Label(ldap_frame, text="LDAP Authentication Test:", 
                             fg=self.colors['on_surface'], bg=self.colors['card'], 
                             font=("Segoe UI", 9, "bold"))
        ldap_title.pack(anchor='w', pady=(0, 5))
        
        # LDAP credentials in grid layout for better organization
        cred_container = tk.Frame(ldap_frame, bg=self.colors['card'])
        cred_container.pack(fill='x')
        
        # Username row
        username_row = tk.Frame(cred_container, bg=self.colors['card'])
        username_row.pack(fill='x', pady=(0, 5))
        
        tk.Label(username_row, text="Username:", fg=self.colors['on_surface'], 
                bg=self.colors['card'], font=("Segoe UI", 8)).pack(side='left')
        username_entry = self.create_modern_entry(username_row, textvariable=self.ldap_user_var, width=20)
        username_entry.pack(side='left', padx=(5, 0), fill='x', expand=True)
        
        # Password row
        password_row = tk.Frame(cred_container, bg=self.colors['card'])
        password_row.pack(fill='x', pady=(0, 8))
        
        tk.Label(password_row, text="Password:", fg=self.colors['on_surface'], 
                bg=self.colors['card'], font=("Segoe UI", 8)).pack(side='left')
        password_entry = self.create_modern_entry(password_row, textvariable=self.ldap_pass_var, 
                                                 show='*', width=20)
        password_entry.pack(side='left', padx=(5, 0), fill='x', expand=True)
        
        # Test button row
        button_row = tk.Frame(cred_container, bg=self.colors['card'])
        button_row.pack(fill='x')
        
        tk.Button(button_row, text="Login", 
                 command=self.test_ldap_auth_unified,
                 bg=self.colors['primary'], fg='white', 
                 font=("Segoe UI", 9, "bold"), relief='flat', bd=0, 
                 padx=15, pady=6).pack(anchor='w')
        
        # User Management Actions Card
        mgmt_card = self.create_modern_card(padding_frame, "User Management")
        mgmt_card.pack(fill='x', pady=(0, 20))  # Add bottom padding
        
        mgmt_content = tk.Frame(mgmt_card, bg=self.colors['card'])
        mgmt_content.pack(fill='x', padx=25, pady=15)
        
        mgmt_buttons_frame = tk.Frame(mgmt_content, bg=self.colors['card'])
        mgmt_buttons_frame.pack()
        
        tk.Button(mgmt_buttons_frame, text="Refresh List", 
                 command=self.refresh_user_list_unified,
                 bg=self.colors['success'], fg='white', 
                 font=("Segoe UI", 9, "bold"), relief='flat', bd=0, 
                 padx=12, pady=6).pack(side='left', padx=(0, 10))
        
        tk.Button(mgmt_buttons_frame, text="Delete Selected", 
                 command=self.delete_selected_user_unified,
                 bg=self.colors['danger'], fg='white', 
                 font=("Segoe UI", 9, "bold"), relief='flat', bd=0, 
                 padx=12, pady=6).pack(side='left')
    
    def setup_modern_user_mgmt_right_panel(self, parent):
        """Setup the modern right panel with output and user list."""
        
        # User List Card
        users_card = self.create_modern_card(parent, "Registered Users")
        users_card.pack(fill='both', expand=True, pady=(0, 15))
        
        list_content = tk.Frame(users_card, bg=self.colors['card'])
        list_content.pack(fill='both', expand=True, padx=20, pady=15)
        
        # Modern Treeview for user list
        columns = ('System', 'Username', 'Name', 'Role', 'Email', 'Created')
        self.user_tree = ttk.Treeview(list_content, columns=columns, show='headings', 
                                     height=12, style='Modern.Treeview')
        
        # Configure columns with modern styling
        self.user_tree.heading('System', text='System')
        self.user_tree.heading('Username', text='Username')
        self.user_tree.heading('Name', text='Full Name')
        self.user_tree.heading('Role', text='Role')
        self.user_tree.heading('Email', text='Email')
        self.user_tree.heading('Created', text='Created')
        
        self.user_tree.column('System', width=80)
        self.user_tree.column('Username', width=100)
        self.user_tree.column('Name', width=150)
        self.user_tree.column('Role', width=80)
        self.user_tree.column('Email', width=150)
        self.user_tree.column('Created', width=120)
        
        # Modern scrollbars
        v_scrollbar = ttk.Scrollbar(list_content, orient='vertical', command=self.user_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_content, orient='horizontal', command=self.user_tree.xview)
        self.user_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout for better scrollbar placement
        self.user_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        list_content.grid_rowconfigure(0, weight=1)
        list_content.grid_columnconfigure(0, weight=1)
        
        # System Output Card
        output_card = self.create_modern_card(parent, "System Output")
        output_card.pack(fill='both', expand=True)
        
        output_content = tk.Frame(output_card, bg=self.colors['card'])
        output_content.pack(fill='both', expand=True, padx=20, pady=15)
        
        # Modern output text area
        self.user_mgmt_output = tk.Text(output_content, height=12, 
                                       font=("Consolas", 9), 
                                       bg='#1e1e1e', fg='#ffffff',
                                       insertbackground='white',
                                       relief='flat', bd=0)
        output_scrollbar = ttk.Scrollbar(output_content, command=self.user_mgmt_output.yview)
        self.user_mgmt_output.configure(yscrollcommand=output_scrollbar.set)
        
        self.user_mgmt_output.pack(side='left', fill='both', expand=True)
        output_scrollbar.pack(side='right', fill='y')
        
        # Load initial data
        self.refresh_user_list_unified()
        self.log_user_mgmt_message("🚀 Modern User Management System initialized", "success")
    
    def setup_user_mgmt_left_panel(self, parent):
        """Setup the left panel with user input and action buttons."""
        
        # User Information Section
        info_frame = tk.LabelFrame(parent, text="User Information", 
                                  font=("Helvetica", 12, "bold"), fg="gold", bg="darkblue")
        info_frame.pack(fill='x', pady=5)
        
        # Username
        tk.Label(info_frame, text="Username:", fg="white", bg="darkblue", font=("Helvetica", 10)).grid(row=0, column=0, sticky='w', padx=5, pady=3)
        username_entry = tk.Entry(info_frame, textvariable=self.username_var, width=25, font=("Helvetica", 10))
        username_entry.grid(row=0, column=1, padx=5, pady=3)
        
        # First Name
        tk.Label(info_frame, text="First Name:", fg="white", bg="darkblue", font=("Helvetica", 10)).grid(row=1, column=0, sticky='w', padx=5, pady=3)
        tk.Entry(info_frame, textvariable=self.first_name_var, width=25, font=("Helvetica", 10)).grid(row=1, column=1, padx=5, pady=3)
        
        # Last Name
        tk.Label(info_frame, text="Last Name:", fg="white", bg="darkblue", font=("Helvetica", 10)).grid(row=2, column=0, sticky='w', padx=5, pady=3)
        tk.Entry(info_frame, textvariable=self.last_name_var, width=25, font=("Helvetica", 10)).grid(row=2, column=1, padx=5, pady=3)
        
        # Email
        tk.Label(info_frame, text="Email:", fg="white", bg="darkblue", font=("Helvetica", 10)).grid(row=3, column=0, sticky='w', padx=5, pady=3)
        tk.Entry(info_frame, textvariable=self.email_var, width=25, font=("Helvetica", 10)).grid(row=3, column=1, padx=5, pady=3)
        
        # Role
        tk.Label(info_frame, text="Role:", fg="white", bg="darkblue", font=("Helvetica", 10)).grid(row=4, column=0, sticky='w', padx=5, pady=3)
        role_frame = tk.Frame(info_frame, bg="darkblue")
        role_frame.grid(row=4, column=1, sticky='w', padx=5, pady=3)
        
        roles = [("User", "user"), ("Operator", "operator"), ("Admin", "admin")]
        for i, (text, value) in enumerate(roles):
            tk.Radiobutton(role_frame, text=text, variable=self.role_var, value=value,
                          fg="white", bg="darkblue", selectcolor="navy", font=("Helvetica", 9)).pack(side='left', padx=5)
        
        # Add informational text about OU placement
        ou_info_frame = tk.Frame(info_frame, bg="darkblue")
        ou_info_frame.grid(row=4, column=2, sticky='w', padx=5, pady=3)
        
        # Clear button
        tk.Button(info_frame, text="Clear Form", command=self.clear_user_form,
                 bg='gray', fg='white', font=("Helvetica", 9)).grid(row=5, column=1, sticky='e', padx=5, pady=5)
        
        # Image Selection Section
        image_frame = tk.LabelFrame(parent, text="Image Selection (Optional)", 
                                   font=("Helvetica", 12, "bold"), fg="cyan", bg="darkblue")
        image_frame.pack(fill='x', pady=5)
        
        self.image_label = tk.Label(image_frame, text="No image selected", 
                                   fg="gray", bg="darkblue", font=("Helvetica", 9))
        self.image_label.pack(pady=5)
        
        tk.Button(image_frame, text="Select Image File", command=self.select_image_file,
                 bg='steelblue', fg='white', font=("Helvetica", 10)).pack(pady=5)
        
        # User Registration Actions
        reg_frame = tk.LabelFrame(parent, text="User Registration Actions", 
                                 font=("Helvetica", 12, "bold"), fg="lightgreen", bg="darkblue")
        reg_frame.pack(fill='x', pady=5)
        
        tk.Button(reg_frame, text="Register User + Face (Camera)", 
                 command=self.register_user_camera_unified,
                 bg='darkgreen', fg='white', font=("Helvetica", 10), width=30).pack(pady=3)
        
        tk.Button(reg_frame, text="Register User + Face (Image)", 
                 command=self.register_user_image_unified,
                 bg='darkblue', fg='white', font=("Helvetica", 10), width=30).pack(pady=3)
        
        tk.Button(reg_frame, text="Register LDAP User Only", 
                 command=self.create_ldap_user_only_unified,
                 bg='purple', fg='white', font=("Helvetica", 10), width=30).pack(pady=3)
        
        # Authentication Testing
        test_frame = tk.LabelFrame(parent, text="Authentication Testing", 
                                  font=("Helvetica", 12, "bold"), fg="yellow", bg="darkblue")
        test_frame.pack(fill='x', pady=5)
        
        test_buttons_frame = tk.Frame(test_frame, bg="darkblue")
        test_buttons_frame.pack(pady=5)
        
        tk.Button(test_buttons_frame, text="Test DeepFace", 
                 command=self.test_deepface_auth_unified,
                 bg='darkviolet', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        tk.Button(test_buttons_frame, text="Test Fingerprint", 
                 command=self.test_fingerprint_auth_unified,
                 bg='red', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        # LDAP Authentication Testing (requires username/password)
        ldap_test_frame = tk.Frame(test_frame, bg="darkblue")
        ldap_test_frame.pack(pady=3)
        
        tk.Label(ldap_test_frame, text="Username:", fg="white", bg="darkblue", font=("Helvetica", 9)).pack(side='left')
        tk.Entry(ldap_test_frame, textvariable=self.ldap_user_var, width=15, font=("Helvetica", 9)).pack(side='left', padx=3)
        
        tk.Label(ldap_test_frame, text="Password:", fg="white", bg="darkblue", font=("Helvetica", 9)).pack(side='left', padx=(10,0))
        tk.Entry(ldap_test_frame, textvariable=self.ldap_pass_var, width=15, show='*', font=("Helvetica", 9)).pack(side='left', padx=3)
        
        tk.Button(ldap_test_frame, text="Login", 
                 command=self.test_ldap_auth_unified,
                 bg='orange', fg='white', font=("Helvetica", 9)).pack(side='left', padx=5)
        
        # User Management Actions
        mgmt_frame = tk.LabelFrame(parent, text="User Management", 
                                  font=("Helvetica", 12, "bold"), fg="lightblue", bg="darkblue")
        mgmt_frame.pack(fill='x', pady=5)
        
        mgmt_buttons_frame = tk.Frame(mgmt_frame, bg="darkblue")
        mgmt_buttons_frame.pack(pady=5)
        
        tk.Button(mgmt_buttons_frame, text="Refresh User List", 
                 command=self.refresh_user_list_unified,
                 bg='darkgreen', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        tk.Button(mgmt_buttons_frame, text="Delete Selected User", 
                 command=self.delete_selected_user_unified,
                 bg='darkred', fg='white', font=("Helvetica", 9), width=20).pack(side='left', padx=2)
        
        # System Information
        sys_frame = tk.LabelFrame(parent, text="System Information", 
                                 font=("Helvetica", 12, "bold"), fg="orange", bg="darkblue")
        sys_frame.pack(fill='x', pady=5)
        
        sys_buttons_frame = tk.Frame(sys_frame, bg="darkblue")
        sys_buttons_frame.pack(pady=5)
        
        tk.Button(sys_buttons_frame, text="System Status", 
                 command=self.show_system_status_unified,
                 bg='brown', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        tk.Button(sys_buttons_frame, text="View Security Logs", 
                 command=self.view_security_logs_unified,
                 bg='navy', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
    
    def setup_user_mgmt_right_panel(self, parent):
        """Setup the right panel with output and user list."""
        
        # User List Section
        users_frame = tk.LabelFrame(parent, text="Registered Users", 
                                   font=("Helvetica", 12, "bold"), fg="lightgreen", bg="darkblue")
        users_frame.pack(fill='both', expand=True, pady=(0,5))
        
        # User list with scrollbar
        list_frame = tk.Frame(users_frame, bg="darkblue")
        list_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create Treeview for user list
        columns = ('System', 'Username', 'Name', 'Role', 'Email', 'Created')
        self.user_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        self.user_tree.heading('System', text='System')
        self.user_tree.heading('Username', text='Username')
        self.user_tree.heading('Name', text='Full Name')
        self.user_tree.heading('Role', text='Role')
        self.user_tree.heading('Email', text='Email')
        self.user_tree.heading('Created', text='Created')
        
        self.user_tree.column('System', width=80)
        self.user_tree.column('Username', width=100)
        self.user_tree.column('Name', width=150)
        self.user_tree.column('Role', width=80)
        self.user_tree.column('Email', width=150)
        self.user_tree.column('Created', width=120)
        
        # Scrollbars for user list
        v_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.user_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient='horizontal', command=self.user_tree.xview)
        self.user_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Use grid for better scrollbar placement
        self.user_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        # Configure grid weights
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Output Section
        output_frame = tk.LabelFrame(parent, text="System Output", 
                                    font=("Helvetica", 12, "bold"), fg="white", bg="darkblue")
        output_frame.pack(fill='both', expand=True, pady=(5,0))
        
        # Output text with scrollbar
        output_container = tk.Frame(output_frame, bg="darkblue")
        output_container.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.user_mgmt_output = tk.Text(output_container, height=12, font=("Courier", 9), bg='black', fg='white')
        output_scrollbar = ttk.Scrollbar(output_container, command=self.user_mgmt_output.yview)
        self.user_mgmt_output.configure(yscrollcommand=output_scrollbar.set)
        
        self.user_mgmt_output.pack(side='left', fill='both', expand=True)
        output_scrollbar.pack(side='right', fill='y')
        
        # Load initial data
        self.refresh_user_list_unified()
        self.log_user_mgmt_message("User Management System initialized")
    
    # User Management Helper Methods
    def validate_user_info(self):
        """Validate that required user information is provided."""
        username = self.username_var.get().strip()
        if not username:
            self.log_user_mgmt_message("ERROR: Username is required", "error")
            return False
        return True
    
    def get_user_info(self):
        """Get user information from form fields."""
        return {
            'username': self.username_var.get().strip(),
            'first_name': self.first_name_var.get().strip(),
            'last_name': self.last_name_var.get().strip(),
            'email': self.email_var.get().strip(),
            'role': self.role_var.get()
        }
    
    def create_modern_card(self, parent, title=None):
        """Create a modern card-style container with title."""
        card = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        
        # Title bar (only if title provided)
        if title:
            title_frame = tk.Frame(card, bg=self.colors['primary'], height=35)
            title_frame.pack(fill='x')
            title_frame.pack_propagate(False)
            
            title_label = tk.Label(title_frame, text=title, 
                                  bg=self.colors['primary'], fg='white',
                                  font=("Segoe UI", 11, "bold"))
            title_label.pack(pady=8)
        
        return card
    
    def log_user_mgmt_message(self, message, type="info"):
        """Log a message to the user management output with modern styling."""
        if not hasattr(self, 'user_mgmt_output'):
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding for different message types
        colors = {
            "info": "#61DAFB",      # Light blue
            "success": "#4CAF50",   # Green
            "warning": "#FF9800",   # Orange
            "error": "#F44336",     # Red
            "system": "#9C27B0"     # Purple
        }
        
        color = colors.get(type, colors["info"])
        
        # Insert colored message
        self.user_mgmt_output.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.user_mgmt_output.insert(tk.END, f"{message}\n", type)
        
        # Configure tags for coloring
        self.user_mgmt_output.tag_config("timestamp", foreground="#888888")
        self.user_mgmt_output.tag_config(type, foreground=color)
        
        # Auto-scroll to bottom
        self.user_mgmt_output.see(tk.END)
        self.user_mgmt_output.update()

    def clear_user_form(self):
        """Clear all form fields."""
        self.username_var.set("")
        self.first_name_var.set("")
        self.last_name_var.set("")
        self.email_var.set("")
        self.role_var.set("user")
        self.selected_image_path = ""
        if hasattr(self, 'image_label'):
            self.image_label.config(text="No image selected", fg='gray')
        self.log_user_mgmt_message("Form cleared")
    
    def select_image_file(self):
        """Select an image file for face registration."""
        file_path = filedialog.askopenfilename(
            title="Select Face Image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.selected_image_path = file_path
            filename = os.path.basename(file_path)
            if hasattr(self, 'image_label'):
                self.image_label.config(text=f"Selected: {filename}", fg='lightgreen')
            self.log_user_mgmt_message(f"Image selected: {filename}")
    
    def log_user_mgmt_message(self, message, level="info"):
        """Log message to the user management output with timestamp and color coding."""
        if not hasattr(self, 'user_mgmt_output'):
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Insert message with timestamp
        self.user_mgmt_output.insert(tk.END, f"[{timestamp}] {message}\n")
        
        # Color coding based on level
        if level == "error":
            # Make the last line red
            start_line = self.user_mgmt_output.index(tk.END).split('.')[0]
            line_num = int(start_line) - 1
            self.user_mgmt_output.tag_add("error", f"{line_num}.0", f"{line_num}.end")
            self.user_mgmt_output.tag_config("error", foreground="red")
        elif level == "success":
            # Make the last line green
            start_line = self.user_mgmt_output.index(tk.END).split('.')[0]
            line_num = int(start_line) - 1
            self.user_mgmt_output.tag_add("success", f"{line_num}.0", f"{line_num}.end")
            self.user_mgmt_output.tag_config("success", foreground="lightgreen")
        elif level == "warning":
            # Make the last line orange
            start_line = self.user_mgmt_output.index(tk.END).split('.')[0]
            line_num = int(start_line) - 1  
            self.user_mgmt_output.tag_add("warning", f"{line_num}.0", f"{line_num}.end")
            self.user_mgmt_output.tag_config("warning", foreground="orange")
        
        # Auto-scroll to bottom
        self.user_mgmt_output.see(tk.END)
        self.root.update()
    
    # User Registration Methods
    def register_user_camera_unified(self):
        """Register a user and their face using camera."""
        if not self.validate_user_info():
            return
            
        user_info = self.get_user_info()
        self.log_user_mgmt_message(f"Starting user registration for: {user_info['username']}")
        
        try:
            # Use the unified registration method from DeepFace with camera
            success, message = self.deepface_auth.create_ldap_user_with_face(
                username=user_info['username'],
                first_name=user_info['first_name'],
                last_name=user_info['last_name'],
                email=user_info['email'],
                role=user_info['role']
            )
            
            if success:
                self.log_user_mgmt_message(f"SUCCESS: {message}", "success")
                self.refresh_user_list_unified()
                self.clear_user_form()
            else:
                self.log_user_mgmt_message(f"ERROR: {message}", "error")
                
        except Exception as e:
            self.log_user_mgmt_message(f"Registration error: {str(e)}", "error")
    
    def register_user_image_unified(self):
        """Register a user and their face using selected image."""
        if not self.validate_user_info():
            return
            
        if not self.selected_image_path:
            self.log_user_mgmt_message("ERROR: Please select an image file first", "error")
            return
        
        user_info = self.get_user_info()
        self.log_user_mgmt_message(f"Starting user registration for: {user_info['username']} with image")
        
        try:
            # Use the unified registration method from DeepFace with image
            success, message = self.deepface_auth.create_ldap_user_with_face(
                username=user_info['username'],
                first_name=user_info['first_name'],
                last_name=user_info['last_name'],
                email=user_info['email'],
                role=user_info['role'],
                image_path=self.selected_image_path
            )
            
            if success:
                self.log_user_mgmt_message(f"SUCCESS: {message}", "success")
                self.refresh_user_list_unified()
                self.clear_user_form()
            else:
                self.log_user_mgmt_message(f"ERROR: {message}", "error")
                
        except Exception as e:
            self.log_user_mgmt_message(f"Registration error: {str(e)}", "error")
    
    def create_ldap_user_only_unified(self):
        """Create LDAP user without face registration."""
        if not self.validate_user_info():
            return
            
        user_info = self.get_user_info()
        self.log_user_mgmt_message(f"Creating LDAP user: {user_info['username']}")
        
        try:
            # Generate a secure password that meets typical domain requirements
            password_length = 14  # Increased length
            # Include all required character types for domain policy
            uppercase = string.ascii_uppercase
            lowercase = string.ascii_lowercase
            digits = string.digits
            special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            # Ensure password contains at least one of each type
            temp_password = (
                secrets.choice(uppercase) +
                secrets.choice(lowercase) + 
                secrets.choice(digits) +
                secrets.choice(special) +
                ''.join(secrets.choice(uppercase + lowercase + digits + special) 
                       for _ in range(password_length - 4))
            )
            
            # Shuffle the password to randomize character positions
            password_list = list(temp_password)
            secrets.SystemRandom().shuffle(password_list)
            temp_password = ''.join(password_list)

            success, message = self.ldap_auth.create_user(
                username=user_info['username'],
                password=temp_password,
                first_name=user_info['first_name'],
                last_name=user_info['last_name'],
                email=user_info['email'],
                role=user_info['role']
            )
            
            if success:
                self.log_user_mgmt_message(f"SUCCESS: LDAP user created. Temporary password: {temp_password}", "success")
                self.log_user_mgmt_message(f"Message: {message}")
                self.refresh_user_list_unified()
                self.clear_user_form()
            else:
                self.log_user_mgmt_message(f"ERROR: {message}", "error")
                print(f"LDAP user creation failed: {message}")

        except Exception as e:
            self.log_user_mgmt_message(f"LDAP user creation error: {str(e)}", "error")
    
    # Authentication Testing Methods
    def test_ldap_auth_unified(self):
        """Test LDAP authentication using form fields."""
        username = self.ldap_user_var.get().strip()
        password = self.ldap_pass_var.get().strip()
        
        if not username or not password:
            self.log_user_mgmt_message("ERROR: Please enter both username and password for LDAP test", "error")
            return
        
        self.log_user_mgmt_message(f"Testing LDAP authentication for: {username}")
        
        try:
            result = self.ldap_auth.authenticate({
                'username': username,
                'password': password
            })
            if result[0]:  # result is a tuple (success, data)
                role_data = result[1] if isinstance(result[1], dict) else {}
                role = role_data.get('role', 'Unknown') if role_data else 'User'
                self.log_user_mgmt_message(f"SUCCESS: LDAP authentication successful! User: {username}, Role: {role}", "success")
            else:
                error_msg = result[1] if result[1] else "Authentication failed"
                self.log_user_mgmt_message(f"ERROR: LDAP authentication failed for user: {username} - {error_msg}", "error")
        except Exception as e:
            self.log_user_mgmt_message(f"LDAP authentication error: {str(e)}", "error")
    
    def test_deepface_auth_unified(self):
        """Test DeepFace authentication using camera."""
        self.log_user_mgmt_message("Starting DeepFace camera authentication test...")
        
        try:
            result = self.deepface_auth.authenticate_face(timeout=10)
            if result:
                username = result.get('username', 'Unknown')
                self.log_user_mgmt_message(f"SUCCESS: DeepFace authentication successful! User: {username}", "success")
            else:
                self.log_user_mgmt_message("ERROR: DeepFace authentication failed - no match found", "error")
        except Exception as e:
            self.log_user_mgmt_message(f"DeepFace authentication error: {str(e)}", "error")
    
    def test_fingerprint_auth_unified(self):
        """Test fingerprint authentication."""
        self.log_user_mgmt_message("Starting fingerprint authentication test...")
        
        try:
            result = self.biometric_auth.authenticate_fingerprint()
            if result:
                self.log_user_mgmt_message(f"SUCCESS: Fingerprint authentication successful! User: {result}", "success")
            else:
                self.log_user_mgmt_message("ERROR: Fingerprint authentication failed", "error")
        except Exception as e:
            self.log_user_mgmt_message(f"Fingerprint authentication error: {str(e)}", "error")
    
    # User Management Methods
    def refresh_user_list_unified(self):
        """Refresh the user list from both LDAP and DeepFace systems."""
        if not hasattr(self, 'user_tree'):
            return
            
        # Clear existing items
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        try:
            # Get LDAP users
            ldap_users = []
            try:
                # LDAP doesn't have a list_users method, skip for now
                # ldap_users = self.ldap_auth.list_users()
                ldap_users = []
            except Exception as e:
                self.log_user_mgmt_message(f"Warning: Could not retrieve LDAP users: {str(e)}", "warning")
            
            # Get DeepFace users
            deepface_users = []
            try:
                deepface_users = self.deepface_auth.list_registered_faces()
                if not deepface_users:
                    deepface_users = []
            except Exception as e:
                self.log_user_mgmt_message(f"Warning: Could not retrieve DeepFace users: {str(e)}", "warning")
            
            # Combine and display users
            all_usernames = set()
            
            # Add LDAP users
            for user in ldap_users:
                username = user.get('username', 'Unknown')
                all_usernames.add(username)
                
                self.user_tree.insert('', 'end', values=(
                    'LDAP',
                    username,
                    f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                    user.get('role', 'Unknown'),
                    user.get('email', ''),
                    user.get('created_date', '')
                ))
            
            # Add DeepFace users (only if not already in LDAP)
            for user in deepface_users:
                username = user.get('username', 'Unknown')
                if username not in all_usernames:
                    self.user_tree.insert('', 'end', values=(
                        'DeepFace',
                        username,
                        f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                        user.get('role', 'Unknown'),
                        user.get('email', ''),
                        user.get('registration_date', '')
                    ))
            
            self.log_user_mgmt_message(f"User list refreshed - LDAP: {len(ldap_users)}, DeepFace: {len(deepface_users)}")
            
        except Exception as e:
            self.log_user_mgmt_message(f"Error refreshing user list: {str(e)}", "error")
    
    def delete_selected_user_unified(self):
        """Delete the selected user from the tree view."""
        if not hasattr(self, 'user_tree'):
            return
            
        selection = self.user_tree.selection()
        if not selection:
            self.log_user_mgmt_message("ERROR: Please select a user to delete", "error")
            return
        
        # Get selected user info
        item = selection[0]
        values = self.user_tree.item(item, 'values')
        system = values[0]
        username = values[1]
        
        self.log_user_mgmt_message(f"Deleting user: {username} from {system} system")
        
        try:
            success = False
            
            if system == 'LDAP':
                success = self.ldap_auth.delete_user(username)
                if success:
                    self.log_user_mgmt_message(f"SUCCESS: User {username} deleted from LDAP", "success")
                else:
                    self.log_user_mgmt_message(f"ERROR: Failed to delete user {username} from LDAP", "error")
            
            elif system == 'DeepFace':
                success = self.deepface_auth.delete_user(username)
                if success:
                    self.log_user_mgmt_message(f"SUCCESS: User {username} deleted from DeepFace", "success")
                else:
                    self.log_user_mgmt_message(f"ERROR: Failed to delete user {username} from DeepFace", "error")
            
            if success:
                self.refresh_user_list_unified()
                
        except Exception as e:
            self.log_user_mgmt_message(f"Error deleting user {username}: {str(e)}", "error")
    
    # System Information Methods
    def show_system_status_unified(self):
        """Show system status information."""
        self.log_user_mgmt_message("=== SYSTEM STATUS ===")
        
        try:
            # LDAP Status
            try:
                # LDAP doesn't have a list_users method, just check availability
                if self.ldap_auth.is_available():
                    self.log_user_mgmt_message("LDAP Server: Connected (users count not available)")
                else:
                    self.log_user_mgmt_message("LDAP Server: Not available", "warning")
            except Exception as e:
                self.log_user_mgmt_message(f"LDAP Server: Error - {str(e)}", "error")
            
            # DeepFace Status
            try:
                deepface_users = self.deepface_auth.list_registered_faces()
                self.log_user_mgmt_message(f"DeepFace System: Active ({len(deepface_users)} users)")
            except Exception as e:
                self.log_user_mgmt_message(f"DeepFace System: Error - {str(e)}", "error")
            
            # Biometric Status
            try:
                self.log_user_mgmt_message("Biometric System: Available")
            except Exception as e:
                self.log_user_mgmt_message(f"Biometric System: Error - {str(e)}", "error")
            
            # Database Status
            try:
                db_path = "face_data/deepface_auth.db"
                if os.path.exists(db_path):
                    size = os.path.getsize(db_path)
                    self.log_user_mgmt_message(f"Database: Connected ({size} bytes)")
                else:
                    self.log_user_mgmt_message("Database: Not found", "warning")
            except Exception as e:
                self.log_user_mgmt_message(f"Database: Error - {str(e)}", "error")
                
        except Exception as e:
            self.log_user_mgmt_message(f"Error checking system status: {str(e)}", "error")
    
    def view_security_logs_unified(self):
        """View recent security logs."""
        self.log_user_mgmt_message("=== RECENT SECURITY LOGS ===")
        
        try:
            logs_dir = "logs"
            if not os.path.exists(logs_dir):
                self.log_user_mgmt_message("Logs directory not found", "warning")
                return
            
            # Get the most recent log file
            log_files = [f for f in os.listdir(logs_dir) if f.startswith("security_log_")]
            if not log_files:
                self.log_user_mgmt_message("No security log files found", "warning")
                return
            
            # Sort by date and get the most recent
            log_files.sort(reverse=True)
            recent_log = os.path.join(logs_dir, log_files[0])
            
            self.log_user_mgmt_message(f"Showing recent entries from: {log_files[0]}")
            
            # Read and display last 10 lines
            with open(recent_log, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-10:] if len(lines) > 10 else lines
                
                for line in recent_lines:
                    self.log_user_mgmt_message(line.strip())
            
        except Exception as e:
            self.log_user_mgmt_message(f"Error reading security logs: {str(e)}", "error")
        
        # Show camera/detection status
        if self.detection_running:
            self.log_user_mgmt_output("⚠️  WARNING: Detection system is currently running")
            self.log_user_mgmt_output("📹 Camera is being used by detection system")
            self.log_user_mgmt_output("💡 Face registration from camera may fail")
            self.log_user_mgmt_output("🔧 Consider using 'Register Face (Image)' instead")
        else:
            self.log_user_mgmt_output("✅ Camera available for face registration")
            self.log_user_mgmt_output("📹 Detection system inactive - GUI mode active")
    
    def show_security_logs(self):
        """Show the modern security logs interface within the GUI."""
        self.clear_screen()
        self.current_screen = "security_logs"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Modern header
        header_frame = tk.Frame(main_frame, bg=self.colors['primary'], height=90)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        header_content = tk.Frame(header_frame, bg=self.colors['primary'])
        header_content.pack(fill='both', expand=True, padx=30, pady=15)
        
        # Title section
        title_label = tk.Label(
            header_content,
            text="📋 SECURITY LOGS",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 20, "bold")
        )
        title_label.pack(side='left', anchor='w')
        
        # Back button
        back_btn = tk.Button(
            header_content,
            text="← Back to Dashboard",
            command=self.show_dashboard,
            font=("Segoe UI", 12, "bold"),
            bg='white',
            fg=self.colors['primary'],
            relief='flat',
            bd=0,
            padx=20,
            pady=8,
            cursor='hand2'
        )
        back_btn.pack(side='right', anchor='e')
        
        # Content container
        content_container = tk.Frame(main_frame, bg=self.colors['background'])
        content_container.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Controls Card
        controls_card = self.create_modern_card(content_container, "Log Controls")
        controls_card.pack(fill='x', pady=(0, 20))
        
        controls_content = tk.Frame(controls_card, bg=self.colors['card'])
        controls_content.pack(fill='x', padx=25, pady=15)
        
        controls_frame = tk.Frame(controls_content, bg=self.colors['card'])
        controls_frame.pack()
        
        # Modern control buttons
        tk.Button(
            controls_frame,
            text="Refresh Logs",
            command=self.refresh_security_logs,
            font=("Segoe UI", 11, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='left', padx=(0, 15))
        
        tk.Button(
            controls_frame,
            text="Today's Logs",
            command=lambda: self.filter_logs_by_date("today"),
            font=("Segoe UI", 11, "bold"),
            bg=self.colors['primary'],
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='left', padx=(0, 15))
        
        tk.Button(
            controls_frame,
            text="All Logs",
            command=lambda: self.filter_logs_by_date("all"),
            font=("Segoe UI", 11, "bold"),
            bg=self.colors['warning'],
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(side='left')
        
        # Log Display Card
        log_card = self.create_modern_card(content_container, "Security Log Entries")
        log_card.pack(fill='both', expand=True)
        
        log_content = tk.Frame(log_card, bg=self.colors['card'])
        log_content.pack(fill='both', expand=True, padx=20, pady=15)
        
        # Modern log text area
        self.logs_output = tk.Text(
            log_content,
            font=("Consolas", 9),
            bg='#1e1e1e',
            fg='#ffffff',
            insertbackground='white',
            relief='flat',
            bd=0,
            wrap=tk.WORD
        )
        
        log_scrollbar = ttk.Scrollbar(log_content, command=self.logs_output.yview)
        self.logs_output.configure(yscrollcommand=log_scrollbar.set)
        
        self.logs_output.pack(side='left', fill='both', expand=True)
        log_scrollbar.pack(side='right', fill='y')
        
        # Load initial logs
        self.refresh_security_logs()
    
    def view_security_logs(self):
        """Deprecated - replaced by show_security_logs."""
        self.show_security_logs()
    
    def log_user_mgmt_output(self, message: str):
        """Log message to user management output area."""
        self.log_user_mgmt_message(message, "info")
    
    def register_face_camera(self):
        """Register face from camera."""
        def on_username_input(username):
            if not username:
                return
            
            def on_password_input(password):
                if not password:
                    return
                
                self.log_user_mgmt_output(f"Starting face registration for user: {username}")
                self.log_user_mgmt_output("⚠️  Important: If detection system is running, camera access may conflict")
                self.log_user_mgmt_output("📷 Attempting to access camera for face capture...")
                
                def registration_thread():
                    try:
                        # Show warning about potential camera conflicts
                        self.root.after(0, lambda: self.log_user_mgmt_output("🔄 Checking camera availability..."))
                        
                        success = self.deepface_auth.register_face(username, first_name="", last_name="", 
                                                                 email="", role="user", image_path=None, password=password)
                        if success:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ Face registered successfully for {username}"))
                            self.root.after(0, lambda: self.show_custom_dialog("Success", 
                                f"Face registered successfully for {username}!\n\nThe user can now authenticate using face recognition.", "info"))
                        else:
                            error_msg = f"Face registration failed for {username}"
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("💡 Troubleshooting tips:"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   - Ensure camera is not being used by detection system"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   - Check camera permissions"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   - Try using image registration instead"))
                            
                            detailed_error = """Face registration failed. 
                            Ensure good lighting and clear face visibility"""
                            
                            self.root.after(0, lambda: self.show_custom_dialog("Registration Failed", detailed_error, "error"))
                    except Exception as e:
                        error_msg = f"Error during face registration: {str(e)}"
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                        
                        # Provide specific guidance based on the error
                        if "cannot access camera" in str(e).lower() or "msmf" in str(e).lower():
                            self.root.after(0, lambda: self.log_user_mgmt_output("🔧 Camera access error detected"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   This usually means another process is using the camera"))
                            troubleshoot_msg = """Camera Access Error

The camera is likely being used by:
• Object detection system
• Another application
• System monitoring
"""
                        else:
                            troubleshoot_msg = f"Face Registration Error\n\nError: {str(e)}\n\nPlease try again or use image registration instead."
                        
                        self.root.after(0, lambda: self.show_custom_dialog("Error", troubleshoot_msg, "error"))
                
                threading.Thread(target=registration_thread, daemon=True).start()
            
            self.show_custom_dialog("Password", f"Enter password for {username}:", "info", input_field=True, password=True, callback=on_password_input)

        # Show initial warning about camera usage
        def proceed_with_registration():
            self.show_custom_dialog("Username", "Enter username for face registration:", "info", input_field=True, callback=on_username_input)
        
        warning_msg = """⚠️ Important Notes
• Press SPACE to capture your face
• Press ESC to cancel
• Ensure good lighting for best results
"""
        
        self.show_custom_dialog("Camera Registration", warning_msg, "yesno", callback=lambda confirmed: proceed_with_registration() if confirmed else None)

    def register_face_image(self):
        """Register face from image file."""
        def on_username_input(username):
            if not username:
                return
            
            def on_password_input(password):
                if not password:
                    return
                
                # Show file selection dialog within the GUI
                self.show_file_selection_dialog("Select face image", [("Image files", "*.jpg *.jpeg *.png *.bmp")], 
                                               lambda image_path: self._process_image_registration(username, password, image_path))
            
            self.show_custom_dialog("Password", "Enter password for LDAP authentication:", "info", input_field=True, callback=on_password_input, password=True)
        
        self.show_custom_dialog("Username", "Enter username for face registration:", "info", input_field=True, callback=on_username_input)
    
    def show_file_selection_dialog(self, title, filetypes, callback):
        """Show file selection dialog within GUI."""
        # For now, we'll use a simple text input for the file path
        # In a full implementation, you could create a file browser within the GUI
        def on_path_input(file_path):
            if file_path and callback:
                callback(file_path)
        
        self.show_custom_dialog("File Path", f"{title}\nEnter full path to image file:", "info", input_field=True, callback=on_path_input)
    
    def _process_image_registration(self, username, password, image_path):
        """Process image registration with given username, password and path."""
        if not image_path:
            return
        
        self.log_user_mgmt_output(f"Registering face from image for user: {username}")
        self.log_user_mgmt_output(f"Image path: {image_path}")
        
        def registration_thread():
            try:
                success = self.deepface_auth.register_face(username, image_path, password=password)
                if success:
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ Face registered successfully for {username}"))
                    self.root.after(0, lambda: self.show_custom_dialog("Success", f"Face registered successfully for {username}", "info"))
                else:
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Face registration failed for {username}"))
                    self.root.after(0, lambda: self.show_custom_dialog("Error", f"Face registration failed for {username}", "error"))
            except Exception as e:
                self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Error during face registration: {e}"))
                self.root.after(0, lambda: self.show_custom_dialog("Error", f"Face registration error: {e}", "error"))
        
        threading.Thread(target=registration_thread, daemon=True).start()
    
    def list_registered_users(self):
        """List all registered users."""
        self.log_user_mgmt_output("Retrieving list of registered users...")
        
        def list_thread():
            try:
                users = self.deepface_auth.list_registered_faces()
                if users:
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ Found {len(users)} registered users:"))
                    for user in users:
                        if isinstance(user, dict):
                            user_info = f"  - {user.get('first_name', '')} {user.get('last_name', '')} ({user.get('username', 'N/A')})"
                            if user.get('email'):
                                user_info += f" - {user['email']}"
                            if user.get('role'):
                                user_info += f" [{user['role']}]"
                            # Fix closure issue by capturing user_info in a new scope
                            self.root.after(0, self._log_user_info, user_info)
                        else:
                            user_info = f"  - {user}"
                            self.root.after(0, self._log_user_info, user_info)
                else:
                    self.root.after(0, lambda: self.log_user_mgmt_output("No registered users found."))
            except Exception as e:
                self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Error retrieving users: {e}"))
        
        threading.Thread(target=list_thread, daemon=True).start()
    
    def _log_user_info(self, user_info):
        """Helper method to log user info (fixes closure issues)."""
        self.log_user_mgmt_output(user_info)
    
    def delete_user_face(self):
        """Delete a user's face registration."""
        def on_username_input(username):
            if not username:
                return
            
            def on_confirmation(confirmed):
                if not confirmed:
                    return
                
                self.log_user_mgmt_output(f"Deleting user registration for: {username}")
                
                def delete_thread():
                    try:
                        success = self.deepface_auth.delete_face(username)
                        if success:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ User {username} deleted successfully"))
                            self.root.after(0, lambda: self.show_custom_dialog("Success", f"User {username} deleted successfully", "info"))
                        else:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Failed to delete user {username}"))
                            self.root.after(0, lambda: self.show_custom_dialog("Error", f"Failed to delete user {username}", "error"))
                    except Exception as e:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Error deleting user: {e}"))
                        self.root.after(0, lambda: self.show_custom_dialog("Error", f"Error deleting user: {e}", "error"))
                
                threading.Thread(target=delete_thread, daemon=True).start()
            
            self.show_custom_dialog("Confirm Deletion", f"Are you sure you want to delete user '{username}'?", "yesno", callback=on_confirmation)
        
        self.show_custom_dialog("Delete User", "Enter username to delete:", "info", input_field=True, callback=on_username_input)
    
    def test_deepface_auth(self):
        """Test DeepFace recognition authentication."""
        self.log_user_mgmt_output("Starting DeepFace recognition test...")
        
        def test_thread():
            try:
                result = self.deepface_auth.authenticate_face(timeout=30)
                if result:
                    user_info = f"{result.get('first_name', '')} {result.get('last_name', '')} ({result.get('username', 'N/A')})"
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ DeepFace authentication successful for user: {user_info}"))
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Role: {result.get('role', 'N/A')}"))
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Email: {result.get('email', 'N/A')}"))
                    if 'euclidean_distance' in result:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Euclidean Distance: {result['euclidean_distance']:.4f}"))
                    if 'cosine_similarity' in result:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Cosine Similarity: {result['cosine_similarity']:.4f}"))
                    success_msg = f"DeepFace authentication successful!\nUser: {user_info}\nRole: {result.get('role', 'N/A')}"
                    self.root.after(0, lambda: self.show_custom_dialog("Success", success_msg, "info"))
                else:
                    self.root.after(0, lambda: self.log_user_mgmt_output("❌ DeepFace authentication failed or timed out"))
                    self.root.after(0, lambda: self.show_custom_dialog("Failed", "DeepFace authentication failed or timed out", "error"))
            except Exception as e:
                self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ DeepFace authentication error: {e}"))
                self.root.after(0, lambda: self.show_custom_dialog("Error", f"DeepFace authentication error: {e}", "error"))
        
        threading.Thread(target=test_thread, daemon=True).start()
    
    def test_ldap_auth(self):
        """Test LDAP authentication."""
        def on_username_input(username):
            if not username:
                return
            
            def on_password_input(password):
                if not password:
                    return
                
                self.log_user_mgmt_output(f"Testing LDAP authentication for user: {username}")
                
                def test_thread():
                    try:
                        ldap_auth = LDAPAuthenticator(Config())
                        success, result = ldap_auth.authenticate({
                            'username': username,
                            'password': password
                        })
                        
                        if success:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ LDAP authentication successful for {username}"))
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"User info: {result}"))
                            role = result.get('role', 'Unknown') if isinstance(result, dict) else 'User'
                            success_msg = f"LDAP authentication successful!\nUser: {username}\nRole: {role}"
                            self.root.after(0, lambda: self.show_custom_dialog("Success", success_msg, "info"))
                        else:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ LDAP authentication failed: {result}"))
                            self.root.after(0, lambda: self.show_custom_dialog("Error", f"LDAP authentication failed: {result}", "error"))
                    except Exception as e:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ LDAP authentication error: {e}"))
                        self.root.after(0, lambda: self.show_custom_dialog("Error", f"LDAP authentication error: {e}", "error"))
                
                threading.Thread(target=test_thread, daemon=True).start()
            
            self.show_custom_dialog("LDAP Test", "Enter password:", "info", input_field=True, password=True, callback=on_password_input)
        
        self.show_custom_dialog("LDAP Test", "Enter username:", "info", input_field=True, callback=on_username_input)
    
    def create_ldap_user_camera(self):
        """Create LDAP user and register face from camera."""
        def on_username_input(username):
            if not username:
                return
            
            def on_first_name_input(first_name):
                def on_last_name_input(last_name):
                    def on_email_input(email):
                        def on_role_selection(role):
                            if not role:
                                role = "user"
                            
                            self.log_user_mgmt_output(f"Creating LDAP user with face registration: {username}")
                            self.log_user_mgmt_output(f"Name: {first_name} {last_name}, Role: {role}, Email: {email}")
                            
                            def creation_thread():
                                try:
                                    success, message = self.deepface_auth.create_ldap_user_with_face(
                                        username=username,
                                        first_name=first_name or "",
                                        last_name=last_name or "",
                                        email=email or "",
                                        role=role,
                                        image_path=None  # Camera capture
                                    )
                                    
                                    if success:
                                        self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ {message}"))
                                        self.root.after(0, lambda: self.show_custom_dialog("Success", message, "info"))
                                    else:
                                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {message}"))
                                        self.root.after(0, lambda: self.show_custom_dialog("Error", message, "error"))
                                except Exception as e:
                                    error_msg = f"Error creating LDAP user with face: {e}"
                                    self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                                    self.root.after(0, lambda: self.show_custom_dialog("Error", error_msg, "error"))
                            
                            threading.Thread(target=creation_thread, daemon=True).start()
                        
                        # Role selection dialog
                        role_options = ["user", "operator", "admin"]
                        self.show_selection_dialog("Select Role", "Choose user role:", role_options, on_role_selection)
                    
                    self.show_custom_dialog("Email", "Enter email address (optional):", "info", input_field=True, callback=on_email_input)
                
                self.show_custom_dialog("Last Name", "Enter last name (optional):", "info", input_field=True, callback=on_last_name_input)
            
            self.show_custom_dialog("First Name", "Enter first name (optional):", "info", input_field=True, callback=on_first_name_input)
        
        self.show_custom_dialog("Create LDAP User", "Enter username:", "info", input_field=True, callback=on_username_input)
    
    def create_ldap_user_image(self):
        """Create LDAP user and register face from image file."""
        def on_username_input(username):
            if not username:
                return
            
            def on_first_name_input(first_name):
                def on_last_name_input(last_name):
                    def on_email_input(email):
                        def on_role_selection(role):
                            if not role:
                                role = "user"
                            
                            def on_image_path_input(image_path):
                                if not image_path:
                                    return
                                
                                self.log_user_mgmt_output(f"Creating LDAP user with face registration: {username}")
                                self.log_user_mgmt_output(f"Name: {first_name} {last_name}, Role: {role}, Email: {email}")
                                self.log_user_mgmt_output(f"Image path: {image_path}")
                                
                                def creation_thread():
                                    try:
                                        success, message = self.deepface_auth.create_ldap_user_with_face(
                                            username=username,
                                            first_name=first_name or "",
                                            last_name=last_name or "",
                                            email=email or "",
                                            role=role,
                                            image_path=image_path
                                        )
                                        
                                        if success:
                                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ {message}"))
                                            self.root.after(0, lambda: self.show_custom_dialog("Success", message, "info"))
                                        else:
                                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {message}"))
                                            self.root.after(0, lambda: self.show_custom_dialog("Error", message, "error"))
                                    except Exception as e:
                                        error_msg = f"Error creating LDAP user with face: {e}"
                                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                                        self.root.after(0, lambda: self.show_custom_dialog("Error", error_msg, "error"))
                                
                                threading.Thread(target=creation_thread, daemon=True).start()
                            
                            self.show_custom_dialog("Image Path", "Enter full path to image file:", "info", input_field=True, callback=on_image_path_input)
                        
                        # Role selection dialog
                        role_options = ["user", "operator", "admin"]
                        self.show_selection_dialog("Select Role", "Choose user role:", role_options, on_role_selection)
                    
                    self.show_custom_dialog("Email", "Enter email address (optional):", "info", input_field=True, callback=on_email_input)
                
                self.show_custom_dialog("Last Name", "Enter last name (optional):", "info", input_field=True, callback=on_last_name_input)
            
            self.show_custom_dialog("First Name", "Enter first name (optional):", "info", input_field=True, callback=on_first_name_input)
        
        self.show_custom_dialog("Create LDAP User", "Enter username:", "info", input_field=True, callback=on_username_input)
    
    def show_selection_dialog(self, title, message, options, callback):
        """Show a modern selection dialog with multiple options."""
        # Create overlay instead of toplevel for consistency
        self.dialog_overlay = tk.Frame(self.root, bg='#404040')
        self.dialog_overlay.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Modern dialog frame
        dialog_frame = tk.Frame(self.dialog_overlay, bg=self.colors['card'], 
                               relief='flat', bd=0)
        dialog_frame.place(relx=0.5, rely=0.5, anchor='center', width=380, height=400)
        
        # Add subtle shadow
        shadow_frame = tk.Frame(self.dialog_overlay, bg='#808080', relief='flat', bd=0)
        shadow_frame.place(relx=0.5, rely=0.5, anchor='center', width=385, height=405)
        dialog_frame.lift()
        
        # Modern header
        header_frame = tk.Frame(dialog_frame, bg=self.colors['primary'], height=50)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        header_label = tk.Label(header_frame, text=f"📋 {title}",
                              bg=self.colors['primary'], fg='white',
                              font=("Segoe UI", 12, "bold"))
        header_label.pack(pady=12)
        
        # Content area
        content_frame = tk.Frame(dialog_frame, bg=self.colors['card'])
        content_frame.pack(fill='both', expand=True, padx=25, pady=20)
        
        # Message
        msg_label = tk.Label(content_frame, text=message,
                           fg=self.colors['on_surface'], bg=self.colors['card'],
                           font=("Segoe UI", 11), wraplength=320)
        msg_label.pack(pady=(0, 20))
        
        # Selection variable
        selection = tk.StringVar(value=options[0] if options else "")
        
        # Modern radio buttons in a frame
        options_frame = tk.Frame(content_frame, bg=self.colors['surface'], 
                               relief='flat', bd=1)
        options_frame.pack(fill='x', pady=(0, 20))
        
        for i, option in enumerate(options):
            option_frame = tk.Frame(options_frame, bg=self.colors['surface'])
            option_frame.pack(fill='x', padx=15, pady=8)
            
            rb = tk.Radiobutton(option_frame, text=option.title(), variable=selection, value=option,
                              fg=self.colors['on_surface'], bg=self.colors['surface'], 
                              selectcolor=self.colors['accent'], 
                              activebackground=self.colors['surface'],
                              activeforeground=self.colors['on_surface'],
                              font=("Segoe UI", 10))
            rb.pack(anchor='w')
        
        # Modern buttons
        btn_frame = tk.Frame(content_frame, bg=self.colors['card'])
        btn_frame.pack(side='bottom')
        
        def on_confirm():
            selected = selection.get()
            self.dialog_overlay.destroy()
            self.dialog_overlay = None
            if callback:
                callback(selected)
        
        def on_cancel():
            self.dialog_overlay.destroy()
            self.dialog_overlay = None
            if callback:
                callback(None)
        
        confirm_btn = tk.Button(btn_frame, text="✓ Confirm", command=on_confirm,
                              font=("Segoe UI", 10, "bold"), bg=self.colors['primary'], 
                              fg='white', relief='flat', bd=0, padx=20, pady=8)
        confirm_btn.pack(side='left', padx=(0, 10))
        
        cancel_btn = tk.Button(btn_frame, text="✗ Cancel", command=on_cancel,
                             font=("Segoe UI", 10, "bold"), bg=self.colors['dark'], 
                             fg='white', relief='flat', bd=0, padx=20, pady=8)
        cancel_btn.pack(side='left')
        
        # Add hover effects
        def add_hover_effect(button, hover_color, normal_color):
            button.bind('<Enter>', lambda e: button.config(bg=hover_color))
            button.bind('<Leave>', lambda e: button.config(bg=normal_color))
        
        add_hover_effect(confirm_btn, self.colors['primary_light'], self.colors['primary'])
        add_hover_effect(cancel_btn, '#374151', self.colors['dark'])

    def refresh_security_logs(self):
        """Refresh and display security logs."""
        self.logs_output.delete(1.0, tk.END)
        self.logs_output.insert(tk.END, "Loading security logs...\n")
        self.logs_output.update_idletasks()
        
        def load_logs_thread():
            try:
                logs_dir = Path("logs")
                if not logs_dir.exists():
                    self.root.after(0, lambda: self.display_log_message("❌ Logs directory not found."))
                    return
                
                log_files = sorted(logs_dir.glob("security_log_*.txt"), reverse=True)
                if not log_files:
                    self.root.after(0, lambda: self.display_log_message("❌ No security log files found."))
                    return
                
                all_logs = []
                for log_file in log_files:
                    try:
                        with open(log_file, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            for line in lines:
                                all_logs.append(line.strip())
                    except Exception as e:
                        all_logs.append(f"❌ Error reading {log_file.name}: {e}")
                
                # Sort logs by timestamp (most recent first)
                all_logs.reverse()
                
                self.root.after(0, lambda: self.display_logs(all_logs))
                
            except Exception as e:
                self.root.after(0, lambda: self.display_log_message(f"❌ Error loading logs: {e}"))
        
        threading.Thread(target=load_logs_thread, daemon=True).start()
    
    def filter_logs_by_date(self, filter_type):
        """Filter logs by date."""
        if filter_type == "today":
            today = datetime.now().strftime("%Y-%m-%d")
            self.logs_output.delete(1.0, tk.END)
            self.logs_output.insert(tk.END, f"Loading logs for {today}...\n")
        else:
            self.refresh_security_logs()
            return
        
        def filter_logs_thread():
            try:
                logs_dir = Path("logs")
                today_file = logs_dir / f"security_log_{today}.txt"
                
                if not today_file.exists():
                    self.root.after(0, lambda: self.display_log_message(f"❌ No logs found for {today}."))
                    return
                
                with open(today_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    logs = [line.strip() for line in lines if line.strip()]
                
                logs.reverse()  # Most recent first
                self.root.after(0, lambda: self.display_logs(logs))
                
            except Exception as e:
                self.root.after(0, lambda: self.display_log_message(f"❌ Error filtering logs: {e}"))
        
        threading.Thread(target=filter_logs_thread, daemon=True).start()
    
    def display_logs(self, logs):
        """Display logs in the text widget."""
        self.logs_output.delete(1.0, tk.END)
        
        if not logs:
            self.logs_output.insert(tk.END, "No log entries found.\n")
            return
        
        self.logs_output.insert(tk.END, f"📋 Security Log Entries ({len(logs)} entries)\n")
        self.logs_output.insert(tk.END, "=" * 80 + "\n\n")
        
        for log_entry in logs:
            if log_entry:
                # Color code different types of events
                if "AUTH_SUCCESS" in log_entry:
                    self.logs_output.insert(tk.END, f"✅ {log_entry}\n", "success")
                elif "AUTH_FAILED" in log_entry or "FAILED" in log_entry:
                    self.logs_output.insert(tk.END, f"❌ {log_entry}\n", "error")
                elif "SYSTEM_START" in log_entry:
                    self.logs_output.insert(tk.END, f"🚀 {log_entry}\n", "system")
                elif "LOGOUT" in log_entry:
                    self.logs_output.insert(tk.END, f"🚪 {log_entry}\n", "logout")
                else:
                    self.logs_output.insert(tk.END, f"ℹ️ {log_entry}\n")
                self.logs_output.insert(tk.END, "\n")
        
        # Configure tags for colored text
        self.logs_output.tag_config("success", foreground="lightgreen")
        self.logs_output.tag_config("error", foreground="lightcoral")
        self.logs_output.tag_config("system", foreground="lightblue")
        self.logs_output.tag_config("logout", foreground="yellow")
        
        self.logs_output.see(tk.END)
    
    def display_log_message(self, message):
        """Display a simple message in the logs output."""
        self.logs_output.delete(1.0, tk.END)
        self.logs_output.insert(tk.END, message + "\n")
    
    def minimize_to_system_tray(self):
        """Minimize GUI to system tray and start detection system."""
        self.is_minimized = True
        self.root.iconify()
        
        # Start detection system when GUI is minimized
        if self.detector_service and not self.detection_running:
            self.start_detection_system()
        
        SecurityUtils.log_security_event("GUI_MINIMIZED", f"User {self.current_user} minimized GUI to system tray - detection started")
        print("🔽 GUI minimized to system tray. Detection system started.")
    
    def restore_from_tray(self):
        """Restore GUI from system tray and stop detection system."""
        self.is_minimized = False
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        
        # Stop detection system when GUI is restored
        if self.detector_service and self.detection_running:
            self.stop_detection_system()
        
        SecurityUtils.log_security_event("GUI_RESTORED", f"User {self.current_user} restored GUI from system tray - detection stopped")
        print("🔼 GUI restored from system tray. Detection system stopped.")
    
    def start_detection_system(self):
        """Start the detection system in a separate thread."""
        if self.detection_running:
            print("⚠️ Detection system already running")
            return
        
        def detection_thread():
            try:
                self.detection_running = True
                print("🎥 Starting detection system...")
                SecurityUtils.log_security_event("DETECTION_STARTED", "Detection system started from GUI")
                
                # Start detection with camera source
                self.detector_service.inference(source=0, view_img=False, save_img=False)
                
            except Exception as e:
                print(f"❌ Detection system error: {e}")
                SecurityUtils.log_security_event("DETECTION_ERROR", f"Detection system error: {e}")
            finally:
                self.detection_running = False
        
        # Start detection in daemon thread
        detection_thread_obj = threading.Thread(target=detection_thread, daemon=True)
        detection_thread_obj.start()
    
    def stop_detection_system(self):
        """Stop the detection system."""
        if not self.detection_running:
            print("⚠️ Detection system not running")
            return
        
        try:
            print("🛑 Stopping detection system...")
            SecurityUtils.log_security_event("DETECTION_STOPPED", "Detection system stopped from GUI")
            
            # Signal detection to stop
            if hasattr(self.detector_service, 'stop_detection'):
                self.detector_service.stop_detection()
            else:
                # Fallback: set running flag to False
                self.detection_running = False
                
        except Exception as e:
            print(f"❌ Error stopping detection: {e}")
            SecurityUtils.log_security_event("DETECTION_STOP_ERROR", f"Error stopping detection: {e}")
    
    def setup_window_events(self):
        """Setup window event handlers for minimize/restore detection."""
        # Bind window state events
        self.root.bind('<Unmap>', self.on_window_minimize)
        self.root.bind('<Map>', self.on_window_restore)
        
        # Add global hotkey for restoring window (Ctrl+Shift+R)
        self.root.bind_all('<Control-Shift-R>', lambda e: self.restore_from_tray())
        
        # Override the minimize button behavior
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)  # Keep security requirement
    
    def on_window_minimize(self, event):
        """Handle window minimize event."""
        if event.widget == self.root:
            if not self.is_minimized:  # Avoid duplicate calls
                self.minimize_to_system_tray()
    
    def on_window_restore(self, event):
        """Handle window restore event."""
        if event.widget == self.root:
            if self.is_minimized:  # Only if actually minimized
                self.restore_from_tray()
    
    def logout(self):
        """Logout and return to authentication screen."""
        def on_confirmation(confirmed):
            if confirmed:
                self.is_authenticated = False
                current_user_temp = self.current_user  # Store for logging
                self.current_user = None
                self.current_role = None
                
                if self.auth_manager:
                    self.auth_manager.logout()
                
                SecurityUtils.log_security_event("GUI_LOGOUT", f"User {current_user_temp} logged out")
                
                # Return to login screen
                self.show_login_screen()
        
        self.show_custom_dialog("Logout", "Are you sure you want to logout?", "yesno", callback=on_confirmation)
    
    def show_auth_failure(self, error_message):
        """Show authentication failure screen."""
        SecurityUtils.log_security_event("GUI_AUTH_FAILED", f"GUI authentication failed: {error_message}")
        
        self.clear_screen()
        self.current_screen = "failure"
        
        # Main container with modern background
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.pack(expand=True, fill='both')
        
        # Header with danger color
        header_frame = tk.Frame(main_frame, bg=self.colors['danger'], height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        header_title = tk.Label(
            header_frame,
            text="❌ AUTHENTICATION FAILED",
            fg='white',
            bg=self.colors['danger'],
            font=("Segoe UI", 20, "bold")
        )
        header_title.pack(expand=True)
        
        # Center container
        center_container = tk.Frame(main_frame, bg=self.colors['background'])
        center_container.pack(expand=True, fill='both', padx=150, pady=50)
        
        # Failure card
        failure_card = self.create_modern_card(center_container, "Access Denied")
        failure_card.pack(fill='both', expand=True)
        
        failure_content = tk.Frame(failure_card, bg=self.colors['card'])
        failure_content.pack(expand=True, fill='both', padx=40, pady=30)
        
        # Failure icon
        failure_icon = tk.Label(
            failure_content,
            text="❌",
            fg=self.colors['danger'],
            bg=self.colors['card'],
            font=("Segoe UI", 80, "bold")
        )
        failure_icon.pack(pady=(20, 30))
        
        # Failure message
        failure_label = tk.Label(
            failure_content,
            text="AUTHENTICATION FAILED",
            fg=self.colors['danger'],
            bg=self.colors['card'],
            font=("Segoe UI", 24, "bold")
        )
        failure_label.pack(pady=(0, 20))
        
        # Error details
        error_label = tk.Label(
            failure_content,
            text=error_message,
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 14, "normal"),
            wraplength=500,
            justify='center'
        )
        error_label.pack(pady=(0, 30))
        
        # Retry button
        retry_btn = tk.Button(
            failure_content,
            text="🔄 Try Again",
            command=self.show_method_selection,
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['primary'],
            fg='white',
            relief='flat',
            bd=0,
            padx=30,
            pady=12,
            cursor='hand2'
        )
        retry_btn.pack(pady=(0, 20))
    
    def show_security_error(self, title, message):
        """Show security error dialog."""
        self.show_custom_dialog(title, message, "error")


if __name__ == "__main__":
    # Test the GUI
    gui = SecurityGUI()
    gui.run()
