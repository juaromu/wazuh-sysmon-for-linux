################################
### Script to Extract Sysmon for Linux Events
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# Tails /var/log/syslog
# Extracts the XML section of the sysmon log
# Applies XMLtoDICT to parse the event
# Converts to JSON and appends to the active responses log file
##########
#!/bin/bash
if pgrep -u root,ossec -f sysmon_for_linux.py
then
    exit 1;
else
    /usr/bin/python3 /var/ossec/active-response/bin/sysmon_for_linux.py
fi
