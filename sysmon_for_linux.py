################################
### Script to Extract Ssysmon for Linux Events
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
import os
import time
import re
import xmltodict
import json
#Define the Regex Expression to match the log header:
#Dec 28 22:46:26 ubunutu2004vm sysmon:
regex = re.compile('^\w+\s[0-3][0-9]\s(?:[01]\d|2[0123]):(?:[012345]\d):(?:[012345]\d)\s\S+\ssysmon:\s')
#Function to tail sysmon log file
def follow(thefile):
    '''generator function that yields new lines in a file
    '''
    # seek the end of the file
    thefile.seek(0, os.SEEK_END)

    # start infinite loop
    while True:
        # read last line of file
        line = thefile.readline()
        # sleep if file hasn't been updated
        if not line:
            time.sleep(0.1)
            continue
        yield line
#Function to append new lines to Active Responses Log
def append_new_line(json_msg):
    """Append given text as a new line at the end of file"""
    # Open the file in append & read mode ('a+')
    with open('/var/ossec/logs/active-responses.log', "a+") as active_responses:
        # Move read cursor to the start of file.
        active_responses.seek(0)
        # If file is not empty then append '\n'
        data = active_responses.read(100)
        if len(data) > 0:
            active_responses.write("\n")
        # Append text at the end of file
        active_responses.write(json.dumps(json_msg))
#Main
if __name__ == '__main__':
    logfile = open("/var/log/syslog","r")
    loglines = follow(logfile)
    # iterate over the generator
    for line in loglines:
        #initialise json object
        line_json = {}
# Evaluate IndexRerror in Split by Regex. If Error, ignore and continue
        try:
            line_xml = regex.split(line)[1]
        except IndexError:
            continue
        else:
            line_xml = regex.split(line)[1]
            line_xml = xmltodict.parse(line_xml,disable_entities=True,process_namespaces=False)
            line_json["Event"] = {}
            line_json["Event"]["System"] = {}
            line_json["Event"]["EventData"] = {}
            line_json["Event"]["EventData"]["Data"] = {}
            line_json["Event"]["System"]["ProviderName"] = line_xml['Event']['System']['Provider']['@Name']
            line_json["Event"]["System"]["Guid"] = line_xml['Event']['System']['Provider']['@Guid']
            line_json["Event"]["System"]["EventID"] = line_xml['Event']['System']['EventID']
            line_json["Event"]["System"]["Version"] = line_xml['Event']['System']['Version']
            line_json["Event"]["System"]["Level"] = line_xml['Event']['System']['Level']
            line_json["Event"]["System"]["Task"] = line_xml['Event']['System']['Task']
            line_json["Event"]["System"]["Opcode"] = line_xml['Event']['System']['Opcode']
            line_json["Event"]["System"]["Keywords"] = line_xml['Event']['System']['Keywords']
            line_json["Event"]["System"]["Version"] = line_xml['Event']['System']['Version']
            line_json["Event"]["System"]["TimeCreated"] = line_xml['Event']['System']['TimeCreated']['@SystemTime']
            line_json["Event"]["System"]["EventRecordID"] = line_xml['Event']['System']['EventRecordID']
            line_json["Event"]["System"]["Correlation"] = line_xml['Event']['System']['Correlation']
            line_json["Event"]["System"]["ProcessID"] = line_xml['Event']['System']['Execution']['@ProcessID']
            line_json["Event"]["System"]["ThreadID"] = line_xml['Event']['System']['Execution']['@ThreadID']
            line_json["Event"]["System"]["Channel"] = line_xml['Event']['System']['Channel']
            line_json["Event"]["System"]["Computer"] = line_xml['Event']['System']['Computer']
            line_json["Event"]["System"]["UserId"] = line_xml['Event']['System']['Security']['@UserId']
            line_json["Event"]["EventData"]["Data"]["RuleName"] = line_xml['Event']['EventData']['Data'][0]['#text']
            line_json["Event"]["EventData"]["Data"]["UtcTime"] = line_xml['Event']['EventData']['Data'][1]['#text']
            line_json["Event"]["EventData"]["Data"]["ProcessGuid"] = line_xml['Event']['EventData']['Data'][2]['#text']
            if line_json["Event"]["System"]["EventID"] == '1':
                line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
                line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
                line_json["Event"]["EventData"]["Data"]["FileVersion"] = line_xml['Event']['EventData']['Data'][5]['#text']
                line_json["Event"]["EventData"]["Data"]["Description"] = line_xml['Event']['EventData']['Data'][6]['#text']
                line_json["Event"]["EventData"]["Data"]["Product"] = line_xml['Event']['EventData']['Data'][7]['#text']
                line_json["Event"]["EventData"]["Data"]["Company"] = line_xml['Event']['EventData']['Data'][8]['#text']
                line_json["Event"]["EventData"]["Data"]["OriginalFileName"] = line_xml['Event']['EventData']['Data'][9]['#text']
                line_json["Event"]["EventData"]["Data"]["CommandLine"] = line_xml['Event']['EventData']['Data'][10]['#text']
                line_json["Event"]["EventData"]["Data"]["CurrentDirectory"] = line_xml['Event']['EventData']['Data'][11]['#text']
                line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][12]['#text']
                line_json["Event"]["EventData"]["Data"]["LogonGuid"] = line_xml['Event']['EventData']['Data'][13]['#text']
                line_json["Event"]["EventData"]["Data"]["LogonId"] = line_xml['Event']['EventData']['Data'][14]['#text']
                line_json["Event"]["EventData"]["Data"]["TerminalSessionId"] = line_xml['Event']['EventData']['Data'][15]['#text']
                line_json["Event"]["EventData"]["Data"]["IntegrityLevel"] = line_xml['Event']['EventData']['Data'][16]['#text']
                line_json["Event"]["EventData"]["Data"]["Hashes"] = line_xml['Event']['EventData']['Data'][17]['#text']
                line_json["Event"]["EventData"]["Data"]["ParentProcessGuid"] = line_xml['Event']['EventData']['Data'][18]['#text']
                line_json["Event"]["EventData"]["Data"]["ParentProcessId"] = line_xml['Event']['EventData']['Data'][19]['#text']
                line_json["Event"]["EventData"]["Data"]["ParentImage"] = line_xml['Event']['EventData']['Data'][20]['#text']
                line_json["Event"]["EventData"]["Data"]["ParentCommandLine"] = line_xml['Event']['EventData']['Data'][21]['#text']
                line_json["Event"]["EventData"]["Data"]["ParentUser"] = line_xml['Event']['EventData']['Data'][22]['#text']
            elif line_json["Event"]["System"]["EventID"] == '3':
                line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
                line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
                line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][5]['#text']
                line_json["Event"]["EventData"]["Data"]["Protocol"] = line_xml['Event']['EventData']['Data'][6]['#text']
                line_json["Event"]["EventData"]["Data"]["Initiated"] = line_xml['Event']['EventData']['Data'][7]['#text']
                line_json["Event"]["EventData"]["Data"]["SourceIsIpv6"] = line_xml['Event']['EventData']['Data'][8]['#text']
                line_json["Event"]["EventData"]["Data"]["SourceIp"] = line_xml['Event']['EventData']['Data'][9]['#text']
                line_json["Event"]["EventData"]["Data"]["SourceHostname"] = line_xml['Event']['EventData']['Data'][10]['#text']
                line_json["Event"]["EventData"]["Data"]["SourcePort"] = line_xml['Event']['EventData']['Data'][11]['#text']
                line_json["Event"]["EventData"]["Data"]["SourcePortName"] = line_xml['Event']['EventData']['Data'][12]['#text']
                line_json["Event"]["EventData"]["Data"]["DestinationIsIpv6"] = line_xml['Event']['EventData']['Data'][13]['#text']
                line_json["Event"]["EventData"]["Data"]["DestinationIp"] = line_xml['Event']['EventData']['Data'][14]['#text']
                line_json["Event"]["EventData"]["Data"]["DestinationHostname"] = line_xml['Event']['EventData']['Data'][15]['#text']
                line_json["Event"]["EventData"]["Data"]["DestinationPort"] = line_xml['Event']['EventData']['Data'][16]['#text']
                line_json["Event"]["EventData"]["Data"]["DestinationPortName"] = line_xml['Event']['EventData']['Data'][17]['#text']
            elif line_json["Event"]["System"]["EventID"] == '5':
                line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
                line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
                line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][5]['#text']
            elif line_json["Event"]["System"]["EventID"] == '9':
                line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
                line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
                line_json["Event"]["EventData"]["Data"]["Device"] = line_xml['Event']['EventData']['Data'][5]['#text']
            elif line_json["Event"]["System"]["EventID"] == '11':
                line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
                line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
                line_json["Event"]["EventData"]["Data"]["TargetFilename"] = line_xml['Event']['EventData']['Data'][5]['#text']
                line_json["Event"]["EventData"]["Data"]["CreationUtcTime"] = line_xml['Event']['EventData']['Data'][6]['#text']
                line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][7]['#text']
            elif line_json["Event"]["System"]["EventID"] == '16':
                line_json["Event"]["EventData"]["Data"]["Configuration"] = line_xml['Event']['EventData']['Data'][3]['#text']
                line_json["Event"]["EventData"]["Data"]["ConfigurationFileHash"] = line_xml['Event']['EventData']['Data'][4]['#text']
            elif line_json["Event"]["System"]["EventID"] == '23':
                line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
                line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][4]['#text']
                line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][5]['#text']
                line_json["Event"]["EventData"]["Data"]["TargetFilename"] = line_xml['Event']['EventData']['Data'][6]['#text']
                line_json["Event"]["EventData"]["Data"]["Hashes"] = line_xml['Event']['EventData']['Data'][7]['#text']
                line_json["Event"]["EventData"]["Data"]["IsExecutable"] = line_xml['Event']['EventData']['Data'][8]['#text']
                line_json["Event"]["EventData"]["Data"]["Archived"] = line_xml['Event']['EventData']['Data'][9]['#text']
            append_new_line(line_json)
