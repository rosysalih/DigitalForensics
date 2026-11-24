import hashlib
import re
import csv
from collections import Counter
from pathlib import Path

# Read the evidence and calculate its hash
evidence = Path('evidence.log')
original_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
logs = evidence.read_text(encoding='utf-8', errors='replace').splitlines()

failed_ips = Counter()
usernames = Counter()
events = Counter()
timeline = []

# Find suspicious activity and successful logins
for number, line in enumerate(logs, start=1):
    timestamp = line[:15].strip()
    event = None

    if 'Failed password' in line:
        event = 'Failed login'
        match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line)
        if match:
            usernames[match.group(1)] += 1
            failed_ips[match.group(2)] += 1
    elif 'Accepted password' in line or 'Accepted publickey' in line:
        event = 'Successful login'
    elif 'Invalid user' in line:
        event = 'Invalid username'
    elif 'POSSIBLE BREAK-IN ATTEMPT' in line:
        event = 'Possible break-in warning'

    if event:
        events[event] += 1
        timeline.append([number, timestamp, event, line])

# Display the investigation results
print('DIGITAL FORENSICS INVESTIGATION')
print('Evidence file:', evidence.name)
print('Total log entries:', len(logs))
for event in ['Failed login', 'Successful login', 'Invalid username', 'Possible break-in warning']:
    print(event + ':', events[event])

print('\nTOP IP ADDRESSES BY FAILED LOGINS')
for ip, count in failed_ips.most_common(5):
    print(ip, '-', count, 'failed attempts')

print('\nTOP TARGETED USERNAMES')
for username, count in usernames.most_common(5):
    print(username, '-', count, 'failed attempts')

# Flag IP addresses with at least five failed logins
print('\nPOTENTIAL BRUTE-FORCE ACTIVITY')
for ip, count in failed_ips.most_common():
    if count >= 5:
        print(ip, '-', count, 'failed attempts')

# Save the timeline in original log order
with open('timeline.csv', 'w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerow(['Line Number', 'Timestamp', 'Event', 'Evidence'])
    writer.writerows(timeline)

# Verify that the evidence has not changed
final_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
print('\nEVIDENCE INTEGRITY')
print('Original SHA-256:', original_hash)
print('Final SHA-256:   ', final_hash)
if original_hash == final_hash:
    print('Integrity verified: Evidence unchanged.')
else:
    print('WARNING: Evidence has been modified.')

print('\nTimeline saved to timeline.csv')
print('Investigation completed.')
