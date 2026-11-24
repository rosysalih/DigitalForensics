import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from collections import Counter
import hashlib
import re
import csv

# Create the application window
root = tk.Tk()
root.title('Digital Forensics Investigation Simulator')
root.geometry('900x600')
root.configure(bg='#e8eef5')
style = ttk.Style()
style.theme_use('clam')
style.configure('Treeview', rowheight=25)

source = tk.StringVar(value=str(Path(__file__).with_name('evidence.log')))
status = tk.StringVar(value='Select evidence and click Analyze Evidence.')
rows = []
report = ''

# Select an evidence file
def browse():
    path = filedialog.askopenfilename(filetypes=[('Log files', '*.log'), ('All files', '*.*')])
    if path:
        source.set(path)

# Analyze the original evidence without changing it
def analyze():
    global rows, report
    try:
        path = Path(source.get())
        data = path.read_bytes()
        original = hashlib.sha256(data).hexdigest()
        logs = data.decode('utf-8', errors='replace').splitlines()
        events, ips, users = Counter(), Counter(), Counter()
        new_rows = []
        for number, line in enumerate(logs, 1):
            event = None
            if 'Failed password' in line:
                event = 'Failed login'
                match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line)
                if match:
                    users[match.group(1)] += 1
                    ips[match.group(2)] += 1
            elif 'Accepted password' in line or 'Accepted publickey' in line:
                event = 'Successful login'
            elif 'Invalid user' in line:
                event = 'Invalid username'
            elif 'POSSIBLE BREAK-IN ATTEMPT' in line:
                event = 'Possible break-in warning'
            if event:
                events[event] += 1
                new_rows.append((number, line[:15].strip(), event, line))
        final = hashlib.sha256(path.read_bytes()).hexdigest()
        integrity = 'Verified: evidence unchanged' if original == final else 'WARNING: evidence changed'
    except OSError as error:
        messagebox.showerror('Evidence error', str(error))
        return
    rows = new_rows
    for label, value in zip(metrics, [len(logs), events['Failed login'], events['Successful login'], events['Possible break-in warning']]):
        label.config(text=str(value))
    report = f'Evidence: {path.name}\nTotal log entries: {len(logs)}\n'
    for event, count in events.items():
        report += f'{event}: {count}\n'
    report += f'\nTimeline records: {len(rows)}\n\nFLAGGED IP ADDRESSES (5+ failed records)\n'
    for ip, count in ips.most_common():
        if count >= 5:
            report += f'{ip}: {count}\n'
    report += '\nTOP TARGETED USERNAMES\n'
    for user, count in users.most_common(5):
        report += f'{user}: {count}\n'
    report += f'\nOriginal SHA-256: {original}\nFinal SHA-256: {final}\n{integrity}\n'
    report += '\nRepeated-message summaries count as one record. Flags suggest possible brute force, not confirmed compromise.\n'
    summary.config(state='normal')
    summary.delete('1.0', 'end')
    summary.insert('end', report)
    summary.config(state='disabled')
    show_timeline()
    status.set(integrity)

# Filter and display timeline records
def show_timeline(*args):
    tree.delete(*tree.get_children())
    for row in rows:
        if filter_event.get() == 'All events' or row[2] == filter_event.get():
            tree.insert('', 'end', values=row)

# Export the investigation results
def export():
    if not report:
        messagebox.showinfo('Export', 'Analyze evidence first.')
        return
    folder = filedialog.askdirectory()
    if not folder:
        return
    try:
        folder = Path(folder)
        targets = [folder / 'dashboard_summary.txt', folder / 'dashboard_timeline.csv']
        if any(p.resolve() == Path(source.get()).resolve() for p in targets):
            raise OSError('Cannot overwrite the evidence file.')
        targets[0].write_text(report, encoding='utf-8')
        with targets[1].open('w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Line Number', 'Timestamp', 'Event', 'Evidence'])
            writer.writerows(rows)
        messagebox.showinfo('Export', 'Summary and timeline exported.')
    except OSError as error:
        messagebox.showerror('Export error', str(error))

# Build the dashboard layout
tk.Label(root, text='Digital Forensics Investigation Simulator', font=('Segoe UI', 18, 'bold'), bg='#183451', fg='white', pady=14).pack(fill='x')
controls = ttk.Frame(root, padding=10)
controls.pack(fill='x')
ttk.Entry(controls, textvariable=source).pack(side='left', fill='x', expand=True)
ttk.Button(controls, text='Browse', command=browse).pack(side='left', padx=4)
ttk.Button(controls, text='Analyze Evidence', command=analyze).pack(side='left', padx=4)
ttk.Button(controls, text='Export Results', command=export).pack(side='left')
cards = tk.Frame(root, bg='#e8eef5')
cards.pack(fill='x', padx=10)
metrics = []
for name in ['Total logs', 'Failed login records', 'Successful logins', 'Break-in warnings']:
    card = tk.Frame(cards, bg='white', padx=10, pady=8)
    card.pack(side='left', expand=True, fill='both', padx=4)
    tk.Label(card, text=name, bg='white').pack()
    value = tk.Label(card, text='-', font=('Segoe UI', 20, 'bold'), bg='white', fg='#183451')
    value.pack()
    metrics.append(value)

tabs = ttk.Notebook(root)
tabs.pack(fill='both', expand=True, padx=12, pady=10)
summary_tab = ttk.Frame(tabs)
timeline_tab = ttk.Frame(tabs)
tabs.add(summary_tab, text='Investigation Summary')
tabs.add(timeline_tab, text='Event Timeline')
summary = tk.Text(summary_tab, wrap='word', font=('Consolas', 10), state='disabled')
scroll = ttk.Scrollbar(summary_tab, command=summary.yview)
summary.configure(yscrollcommand=scroll.set)
scroll.pack(side='right', fill='y')
summary.pack(fill='both', expand=True)
filter_event = tk.StringVar(value='All events')
filter_box = ttk.Combobox(timeline_tab, textvariable=filter_event, state='readonly', values=['All events', 'Failed login', 'Successful login', 'Invalid username', 'Possible break-in warning'])
filter_box.pack(anchor='w', padx=5, pady=5)
filter_box.bind('<<ComboboxSelected>>', show_timeline)
frame = ttk.Frame(timeline_tab)
frame.pack(fill='both', expand=True)
tree = ttk.Treeview(frame, columns=('line', 'time', 'event', 'evidence'), show='headings')
for col, title, width in [('line', 'Line', 65), ('time', 'Timestamp', 135), ('event', 'Event', 175), ('evidence', 'Original evidence', 650)]:
    tree.heading(col, text=title)
    tree.column(col, width=width, stretch=False)
y = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
x = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
y.pack(side='right', fill='y')
x.pack(side='bottom', fill='x')
tree.pack(fill='both', expand=True)
ttk.Label(root, textvariable=status, padding=8).pack(fill='x')
root.mainloop()
