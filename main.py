# developer: @pyroalww, @c4gwn
# 03.04.2024
# HashCheck
# https://github.com/pyroalww/HashCheck
# M.I.T License

# pip install pyperclip
# pip install hashlib
# pip install tk
# pip install ttkthemes




import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from ttkthemes import ThemedTk
import hashlib
import os
import pyperclip
import threading # Coming Soon
import time

class HashCheckApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HashCheck")

        self.file_path = None
        self.selected_algorithms = ['MD5', 'SHA-1', 'SHA-256']
        self.hash_value = tk.StringVar()
        self.result_text = tk.StringVar()
        self.result_text.set("Result will be displayed here.")
        self.file_info = tk.StringVar()
        self.file_info.set("No file selected.")
        self.computed_hashes = {}

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")

        file_frame = ttk.Frame(main_frame, padding="10")
        file_frame.grid(row=0, column=0, columnspan=2, sticky="ew")

        file_label = ttk.Label(file_frame, text="Selected File:")
        file_label.grid(row=0, column=0, sticky="w")

        select_button = ttk.Button(file_frame, text="Browse", command=self.select_file)
        select_button.grid(row=0, column=1, padx=10)

        info_label = ttk.Label(file_frame, textvariable=self.file_info)
        info_label.grid(row=1, column=0, columnspan=2, pady=(5, 10), sticky="w")

        hash_label = ttk.Label(main_frame, text="Enter Hash Value:")
        hash_label.grid(row=1, column=0, sticky="w")
        hash_label_tooltip = Tooltip(hash_label, "Enter the hash value to check against the file's hash")

        hash_entry = ttk.Entry(main_frame, textvariable=self.hash_value)
        hash_entry.grid(row=1, column=1, pady=5, sticky="ew")

        algo_label = ttk.Label(main_frame, text="Select Hash Algorithms:")
        algo_label.grid(row=2, column=0, sticky="w")
        algo_label_tooltip = Tooltip(algo_label, "Select the hash algorithms to compute the file's hash")

        algo_frame = ttk.Frame(main_frame)
        algo_frame.grid(row=2, column=1, pady=5, sticky="w")

        for i, algo in enumerate(self.selected_algorithms):
            check_button = ttk.Checkbutton(algo_frame, text=algo, variable=tk.BooleanVar(), onvalue=True, offvalue=False, command=self.update_result)
            check_button.grid(row=0, column=i, padx=5, sticky="w")
            check_button.invoke() 

        check_button = ttk.Button(main_frame, text="Check", command=self.check_hash)
        check_button.grid(row=3, column=0, columnspan=2, pady=10, sticky="ew")

        show_hash_button = ttk.Button(main_frame, text="Show Hash", command=self.show_hash)
        show_hash_button.grid(row=4, column=0, columnspan=2, pady=(0, 10), sticky="ew")

        result_label = ttk.Label(main_frame, text="Result:")
        result_label.grid(row=5, column=0, sticky="w")

        result_text = tk.Text(main_frame, height=6, width=50, wrap="word", state="disabled")
        result_text.grid(row=6, column=0, columnspan=2, pady=5, sticky="w")

        self.result_text_widget = result_text

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_info.set("File: " + os.path.basename(self.file_path))
            self.compute_hashes()

    def compute_hashes(self):
        if self.file_path:
            try:
                with open(self.file_path, 'rb') as file:
                    data = file.read()
                    for algo in self.selected_algorithms:
                        computed_hash = self.calculate_hash(data, algo.lower())
                        self.computed_hashes[algo] = computed_hash
            except Exception as e:
                messagebox.showerror("Error", f"Error reading file: {e}")

    def calculate_hash(self, data, algorithm='sha256'):
        """Calculate the hash of the data using the specified algorithm."""
        try:
            hash_function = hashlib.new(algorithm)
            hash_function.update(data)
            return hash_function.hexdigest()
        except Exception as e:
            messagebox.showerror("Error", f"Error calculating hash: {e}")
            return None

    def check_hash(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file.")
            return

        if not any(self.selected_algorithms):
            messagebox.showerror("Error", "Please select at least one hash algorithm.")
            return

        hash_value = self.hash_value.get().strip()
        if not hash_value:
            messagebox.showerror("Error", "Please enter the hash value.")
            return

        results = []

        for algo in self.selected_algorithms:
            if algo:
                computed_hash = self.computed_hashes.get(algo)
                if computed_hash == hash_value:
                    results.append(f"{algo}: Hashes match! File integrity is intact.")
                else:
                    results.append(f"{algo}: Hashes don't match! File may have been tampered with.")

        if not results:
            messagebox.showerror("Error", "No hash algorithms selected.")
            return

        self.animate_result(results)

    def update_result(self):
        self.compute_hashes()

    def show_hash(self):
        if not self.computed_hashes:
            messagebox.showwarning("Warning", "No file selected or hash algorithms computed.")
            return

        hash_text = "\n".join([f"{algo}: {hash}" for algo, hash in self.computed_hashes.items()])
        pyperclip.copy(hash_text)
        messagebox.showinfo("Computed Hashes", "Hashes copied to clipboard.\n\n" + hash_text)

    def animate_result(self, results):
        self.result_text_widget.config(state="normal")
        self.result_text_widget.delete(1.0, tk.END)

        for result in results:
            self.result_text_widget.insert(tk.END, result + "\n")
            self.root.update()
            time.sleep(0.5) 

        self.result_text_widget.config(state="disabled")

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1, font=("Arial", "10", "normal"))
        label.pack(ipadx=5, ipady=3)

    def leave(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

def main():
    root = ThemedTk(theme="breeze")  
    app = HashCheckApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
