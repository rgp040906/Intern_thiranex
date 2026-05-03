import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from analyzer import analyze_password, hash_password
from generator import generate_password
from database import init_db, is_hash_used, store_hash

class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("500x650")
        self.root.configure(bg="#2b2b2b")
        self.root.resizable(False, False)
        
        init_db()

        # Styles
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#2b2b2b", foreground="#ffffff", font=("Helvetica", 11))
        style.configure("Title.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=6)
        style.configure("TCheckbutton", background="#2b2b2b", foreground="#ffffff")
        
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = ttk.Label(self.root, text="Password Strength Analyzer", style="Title.TLabel")
        title_label.pack(pady=20)

        # Password Input Frame
        input_frame = tk.Frame(self.root, bg="#2b2b2b")
        input_frame.pack(pady=10, padx=30, fill=tk.X)

        ttk.Label(input_frame, text="Enter Password:").pack(anchor=tk.W)
        
        self.password_var = tk.StringVar()
        # Bind the trace to trigger analysis dynamically
        self.password_var.trace_add("write", self.on_password_change)
        
        self.password_entry = ttk.Entry(input_frame, textvariable=self.password_var, show="*", font=("Helvetica", 12))
        self.password_entry.pack(fill=tk.X, pady=5, ipady=4)

        # Show password toggle
        self.show_pass_var = tk.BooleanVar()
        self.show_pass_cb = ttk.Checkbutton(input_frame, text="Show Password", variable=self.show_pass_var, command=self.toggle_password_vis)
        self.show_pass_cb.pack(anchor=tk.W)

        # Analysis Result Frame
        result_frame = tk.Frame(self.root, bg="#3b3b3b", bd=2, relief=tk.GROOVE)
        result_frame.pack(pady=20, padx=30, fill=tk.BOTH, expand=True)

        self.strength_label = ttk.Label(result_frame, text="Strength: N/A", font=("Helvetica", 12, "bold"), background="#3b3b3b")
        self.strength_label.pack(pady=10)

        # Progress bar
        style = ttk.Style()
        style.configure("TProgressbar", thickness=15)
        self.progress = ttk.Progressbar(result_frame, orient="horizontal", length=300, mode="determinate", style="TProgressbar")
        self.progress.pack(pady=10)

        # Suggestions
        ttk.Label(result_frame, text="Suggestions:", font=("Helvetica", 11, "bold"), background="#3b3b3b").pack(anchor=tk.W, padx=20)
        self.suggestions_text = tk.Text(result_frame, height=5, width=40, font=("Helvetica", 10), bg="#4b4b4b", fg="white", state=tk.DISABLED, wrap=tk.WORD)
        self.suggestions_text.pack(pady=5, padx=20, fill=tk.X)
        
        # Hash Display
        ttk.Label(result_frame, text="SHA-256 Hash:", font=("Helvetica", 10), background="#3b3b3b").pack(anchor=tk.W, padx=20)
        self.hash_var = tk.StringVar()
        self.hash_entry = ttk.Entry(result_frame, textvariable=self.hash_var, state='readonly', font=("Courier", 8))
        self.hash_entry.pack(fill=tk.X, padx=20, pady=2)

        # Warning Label for password reuse
        self.warning_label = tk.Label(result_frame, text="", fg="red", bg="#3b3b3b", font=("Helvetica", 10, "bold"))
        self.warning_label.pack(pady=5)

        # Buttons Frame
        btn_frame = tk.Frame(self.root, bg="#2b2b2b")
        btn_frame.pack(pady=10, fill=tk.X, padx=30)

        analyze_btn = ttk.Button(btn_frame, text="Save Password", command=self.save_password)
        analyze_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        gen_btn = ttk.Button(btn_frame, text="Generate Secure", command=self.generate_and_fill)
        gen_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=5)

    def toggle_password_vis(self):
        if self.show_pass_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def on_password_change(self, *args):
        password = self.password_var.get()
        if not password:
            self.strength_label.config(text="Strength: N/A", foreground="white")
            self.progress['value'] = 0
            self.update_suggestions([])
            self.hash_var.set("")
            self.warning_label.config(text="")
            return

        score, strength, suggestions, pwned_count = analyze_password(password)
        
        # Update progress and color
        max_score = 7
        percentage = (min(score, max_score) / max_score) * 100
        self.progress['value'] = percentage

        if strength == "Weak" or strength == "Very Weak":
            color = "#ff4d4d" # Red
        elif strength == "Medium":
            color = "#ffa64d" # Orange
        elif strength == "Strong":
            color = "#85e085" # Light Green
        else:
            color = "#33cc33" # Dark Green
            
        self.strength_label.config(text=f"Strength: {strength}", foreground=color)
        
        self.update_suggestions(suggestions)
        
        # Calculate Hash
        pwd_hash = hash_password(password)
        self.hash_var.set(pwd_hash)
        
        # Check Database
        if is_hash_used(pwd_hash):
            self.warning_label.config(text="⚠️ Password already used before!")
        else:
            self.warning_label.config(text="")

    def update_suggestions(self, suggestions):
        self.suggestions_text.config(state=tk.NORMAL)
        self.suggestions_text.delete(1.0, tk.END)
        for sug in suggestions:
            self.suggestions_text.insert(tk.END, f"• {sug}\n")
        self.suggestions_text.config(state=tk.DISABLED)

    def save_password(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
            
        score, strength, _, _ = analyze_password(password)
        if score < 5: # Require at least 'Strong'
            if not messagebox.askyesno("Weak Password", f"Your password is only '{strength}'. Are you sure you want to save it?"):
                return
                
        pwd_hash = hash_password(password)
        if store_hash(pwd_hash):
            messagebox.showinfo("Success", "Password securely hashed and stored!")
            self.warning_label.config(text="⚠️ Password already used before!")
        else:
            messagebox.showerror("Error", "This password was previously used. Please choose another one.")

    def generate_and_fill(self):
        new_pwd = generate_password()
        self.password_var.set(new_pwd)
        if not self.show_pass_var.get():
            self.show_pass_var.set(True)
            self.toggle_password_vis()
