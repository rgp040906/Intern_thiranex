import tkinter as tk
from gui import PasswordAnalyzerApp

def main():
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
