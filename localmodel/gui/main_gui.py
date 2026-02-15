import pyperclip
import tkinter as tk
import os
import sys
from localmodel.core.reports import report
from localmodel.core.scoring import score_indicator
from localmodel.core.schema import validate_entry
from tkinter import filedialog, messagebox, scrolledtext

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Updated import path for local enrichment logic
from localmodel.core.enrichment import enrich_local
from localmodel.core.scoring import score_indicator
from localmodel.core.schema import validate_entry
from localmodel.core.ioc_parser import parse_file
from localmodel.core.reports import report

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

        self.report_button = tk.Button(root, text="Export Report", command=self.export_report_gui)
        self.report_button.pack(pady=5)

    def enrich_ioc(self):
        ioc = self.entry.get().strip()
        if not ioc:
            messagebox.showwarning("Input Error", "Please enter an indicator.")
            return

        matches = enrich_local(ioc)
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

    def export_report_gui(self):
        if not self.valid_entries:
            messagebox.showwarning("Export Error", "No valid IOC data available. Run enrichment first.")
            return

        json_path, md_path, sbom_path, hash_entries = report(self.valid_entries)
        hash_text = "\n".join(hash_entries)

        popup = tk.Toplevel(self.root)
        popup.title("Report Exported")
        popup.geometry("600x300")

        label = tk.Label(popup, text="Report files created. SHA256 hashes:")
        label.pack(pady=5)

        text_box = scrolledtext.ScrolledText(popup, wrap=tk.WORD, width=70, height=10)
        text_box.pack(padx=10, pady=5)
        text_box.insert(tk.END, hash_text)
        text_box.config(state=tk.DISABLED)

        def copy_to_clipboard():
            pyperclip.copy(hash_text)
            messagebox.showinfo("Copied", "SHA256 hashes copied to clipboard.")

        copy_btn = tk.Button(popup, text="Copy to Clipboard", command=copy_to_clipboard)
        copy_btn.pack(pady=5)

    def parse_file_dialog(self):
        filepath = filedialog.askopenfilename(
            title="Select File to Parse",
            filetypes=[("All Supported", "*.txt *.json *.csv *.yaml *.yml")]
        )
        if not filepath:
            return

        base_data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
        output_path = os.path.join(base_data_dir, "parsed_gui_output.json")
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
