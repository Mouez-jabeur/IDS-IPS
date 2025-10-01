import tkinter as tk
from tkinter import ttk
import json
import subprocess
import threading
import time

# === Configuration ===
LOG_FILE = "/var/log/suricata/eve.json"
TAIL_LINES = 50
REFRESH_INTERVAL = 5
MAX_ROWS = 500

SEVERITY_LEVELS = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low"
}

# Color palette (readable)
COLOR_SCHEME = {
    "dark_bg": "#1e1e1e",
    "text_fg": "#ffffff",
    "header_bg": "#333333",
    "critical_bg": "#ff4d4d",
    "high_bg": "#ffb347",
    "medium_bg": "#add8e6",  # light blue
    "low_bg": "#d3d3d3",     # light gray
    "row_text": "#000000"
}

class SuricataDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Suricata Alerts Dashboard")
        self.paused = False

        # --- Top bar ---
        top_frame = tk.Frame(root, bg=COLOR_SCHEME["dark_bg"])
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(top_frame, text="Search:", fg=COLOR_SCHEME["text_fg"], bg=COLOR_SCHEME["dark_bg"]).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.apply_filter)
        search_entry = tk.Entry(top_frame, textvariable=self.search_var, bg="#2e2e2e", fg="#ffffff")
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.severity_filter = ttk.Combobox(top_frame, values=["All", "Critical", "High", "Medium", "Low"], state="readonly")
        self.severity_filter.set("All")
        self.severity_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        self.severity_filter.pack(side=tk.LEFT, padx=5)

        self.toggle_btn = tk.Button(top_frame, text="Pause", command=self.toggle_updates)
        self.toggle_btn.pack(side=tk.RIGHT)

        self.status_label = tk.Label(top_frame, text="Updating...", fg="green", bg=COLOR_SCHEME["dark_bg"])
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # --- TreeView (Table) ---
        self.tree = ttk.Treeview(root, columns=("Time", "Src", "Dst", "Protocol", "Alert", "Severity", "Dangerous"), show='headings')
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER, width=120 if col != "Alert" else 300)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.setup_styles()

        self.all_rows = []
        self.seen_events = set()
        self.stop_thread = False

        threading.Thread(target=self.update_logs, daemon=True).start()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=COLOR_SCHEME["dark_bg"], foreground=COLOR_SCHEME["text_fg"],
                        fieldbackground=COLOR_SCHEME["dark_bg"], font=("Consolas", 10))
        style.configure("Treeview.Heading", background=COLOR_SCHEME["header_bg"], foreground="#ffffff",
                        font=("Arial", 10, "bold"))

        self.tree.tag_configure("critical", background=COLOR_SCHEME["critical_bg"], foreground=COLOR_SCHEME["row_text"])
        self.tree.tag_configure("high", background=COLOR_SCHEME["high_bg"], foreground=COLOR_SCHEME["row_text"])
        self.tree.tag_configure("medium", background=COLOR_SCHEME["medium_bg"], foreground=COLOR_SCHEME["row_text"])
        self.tree.tag_configure("low", background=COLOR_SCHEME["low_bg"], foreground=COLOR_SCHEME["row_text"])

    def toggle_updates(self):
        self.paused = not self.paused
        self.toggle_btn.config(text="Resume" if self.paused else "Pause")
        self.status_label.config(text="Paused" if self.paused else "Updating...",
                                 fg="red" if self.paused else "green")

    def apply_filter(self, *_):
        search_term = self.search_var.get().lower()
        selected_severity = self.severity_filter.get()
        self.tree.delete(*self.tree.get_children())

        for entry in self.all_rows:
            if selected_severity != "All" and SEVERITY_LEVELS.get(entry["severity"], "") != selected_severity:
                continue
            if any(search_term in str(field).lower() for field in entry["values"]):
                self.tree.insert("", "end", values=entry["values"], tags=(entry["tag"],))

    def update_logs(self):
        while not self.stop_thread:
            if not self.paused:
                try:
                    output = subprocess.check_output(["tail", f"-n{TAIL_LINES}", LOG_FILE], text=True)
                    lines = output.strip().split("\n")
                    for line in lines:
                        self.process_line(line)
                except Exception as e:
                    print("Error reading logs:", e)
            time.sleep(REFRESH_INTERVAL)

    def process_line(self, line):
        try:
            data = json.loads(line)
            if "alert" in data:
                event_id = str(data.get("flow_id", "")) + data.get("timestamp", "")
                if event_id in self.seen_events:
                    return
                self.seen_events.add(event_id)

                timestamp = data.get("timestamp", "N/A")
                src_ip = data.get("src_ip", "N/A")
                dst_ip = data.get("dest_ip", "N/A")
                proto = data.get("proto", "N/A")
                alert_msg = data["alert"].get("signature", "N/A")
                severity = data["alert"].get("severity", 3)

                alert_msg_lower = alert_msg.lower()
                danger_keywords = ["nmap", "scan", "portscan", "recon", "brute", "malware", "exploit"]
                is_dangerous = severity <= 2 or any(word in alert_msg_lower for word in danger_keywords)
                dangerous = "Yes" if is_dangerous else "No"

                tag = self.get_severity_tag(severity)
                self.insert_row(timestamp, src_ip, dst_ip, proto, alert_msg,
                                SEVERITY_LEVELS.get(severity, severity), dangerous, tag, severity)
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print("Error processing line:", e)

    def insert_row(self, time_, src, dst, proto, msg, severity, dangerous, tag, severity_val):
        if len(self.tree.get_children()) >= MAX_ROWS:
            self.tree.delete(self.tree.get_children()[0])

        values = (time_, src, dst, proto, msg, severity, dangerous)
        self.tree.insert("", "end", values=values, tags=(tag,))
        self.all_rows.append({"values": values, "tag": tag, "severity": severity_val})

        if self.search_var.get():
            self.apply_filter()
        else:
            self.tree.see(self.tree.get_children()[-1])

    def get_severity_tag(self, severity):
        if severity == 1:
            return "critical"
        elif severity == 2:
            return "high"
        elif severity == 3:
            return "medium"
        else:
            return "low"

def main():
    root = tk.Tk()
    root.geometry("1200x700")
    root.configure(bg=COLOR_SCHEME["dark_bg"])
    app = SuricataDashboard(root)
    root.mainloop()

if __name__ == "__main__":
    main()
