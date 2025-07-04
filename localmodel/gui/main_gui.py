import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.enrich_local import enrich_from_local_db
from core.scoring import score_indicator
from core.schema import validate_entry
from core.ioc_parser import parse_file

class IndicatorInspectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Indicator Inspector - Local Model")
        self.root.geometry("700x500")

        self.label = tk.Label(root, text="Enter IOC (IP, domain, or hash):")
        self.label.pack(pady=5)

        self.entry = tk.Entry(root, width=50)
        self.entry.pack(pady=5)

        self.enrich_button = tk.Button(root, text="Enrich Indicator", command=self.enrich_ioc)
        self.enrich_button.pack(pady=5)

        self.file_button = tk.Button(root, text="Parse File for IOCs", command=self.parse_file_dialog)
        self.file_button.pack(pady=5)

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.output.pack(padx=10, pady=10)

    def enrich_ioc(self):
        ioc = self.entry.get().strip()
        if not ioc:
            messagebox.showwarning("Input Error", "Please enter an indicator.")
            return

        matches = enrich_from_local_db(ioc)
        valid_entries = [entry for entry in matches if not validate_entry(entry)]

        self.output.delete(1.0, tk.END)

        if not matches:
            self.output.insert(tk.END, f"[!] No data found for {ioc}\n")
            return
        if not valid_entries:
            self.output.insert(tk.END, f"[!] No valid entries for {ioc}\n")
            return

        score, tags = score_indicator(valid_entries)
        self.output.insert(tk.END, f"\n=== Indicator Report ===\n")
        self.output.insert(tk.END, f"Indicator: {ioc}\n")
        self.output.insert(tk.END, f"Score: {score}/100\n")
        self.output.insert(tk.END, f"Tags: {', '.join(tags) if tags else 'None'}\n")

    def parse_file_dialog(self):
        filepath = filedialog.askopenfilename(
            title="Select File to Parse",
            filetypes=[("All Supported", "*.txt *.json *.csv *.yaml *.yml")]
        )
        if not filepath:
            return

        output_path = os.path.join("data", "parsed_gui_output.json")
        parsed = parse_file(filepath, output_path)

        self.output.delete(1.0, tk.END)
        if parsed:
            self.output.insert(tk.END, f"[+] Parsed {len(parsed)} indicators from file.\n")
            self.output.insert(tk.END, f"Saved to: {output_path}\n")
        else:
            self.output.insert(tk.END, f"[!] No IOCs found or valid in file: {filepath}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = IndicatorInspectorApp(root)
    root.mainloop()
