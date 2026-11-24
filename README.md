Digital Forensics Investigation Simulator
Description
This simulator uses Python to analyze SSH logs, identify suspicious activities, and detect possible brute-force attacks.

Features
• Detects failed and successful logins.
• Identifies suspicious IP addresses and targeted usernames.
• Creates an event timeline.
• Verifies evidence using SHA-256.
• Provides a graphical interface using Tkinter.
• Filters events and exports results.

Tools Used
Python, Tkinter, and Visual Studio Code.

How to Run
Terminal version:

python investigator.py

Graphical version:

python dashboard.py

Click Analyze Evidence to view the results.

Results
• 2,000 log entries analyzed.
• 520 failed login records.
• 1 successful login.
• 10 flagged IP addresses.
• 719 timeline records.
• Evidence integrity verified.

Dataset
https://github.com/logpai/loghub/tree/master/OpenSSH
