**SYSMON FOR LINUX AND WAZUH AGENT**

## Intro

Using Sysmon for Linux integrated with the Wazuh agent.


## Sysmon for Linux


### Dependencies

eBPF: Available [here](https://github.com/Sysinternals/SysinternalsEBPF). Needs to be compiled from sources. 

Extended Berkeley Packet Filter (eBPF) is a kernel technology (starting in Linux 4.x) that allows programs to run without having to change the kernel source code or adding additional modules. 

Using eBPF eliminates the need to change kernel source code and streamlines the ability of software to leverage existing layers. As a result, it’s a powerful technology with the potential to fundamentally alter how services like networking, observability, and security are delivered.

eBPF programs are event-driven and attached to a code path. The code path contains specific triggers—called hooks—which execute any attached eBPF programs when they’re passed. Some examples of hooks include network events, system calls, function entries, and kernel tracepoints.

eBPF is typically used to trace user-space processes, and its advantages shine here. It’s a safe and useful method to ensure:



* Speed and performance. eBPF can move packet processing from the kernel-space and into the user-space. Likewise, eBPF is a just-in-time (JIT) compiler. After the bytecode is compiled, eBPF is invoked rather than a new interpretation of the bytecode for every method.
* Low intrusiveness. When leveraged as a debugger, eBPF doesn’t need to stop a program to observe its state.
* Security. Programs are effectively sandboxed, meaning kernel source code remains protected and unchanged. The verification step ensures that resources don’t get choked up with programs that run infinite loops.
* Convenience. It’s less work to create code that hooks kernel functions than it is to build and maintain kernel modules.
* Unified tracing. eBPF gives you a single, powerful, and accessible framework for tracing processes. This increases visibility and security.
* Programmability. Using eBPF helps increase the feature-richness of an environment without adding additional layers. Likewise, since code is run directly in the kernel, it’s possible to store data between eBPF events instead of dumping it like other tracers do.
* Expressiveness. eBPF is expressive, capable of performing functions usually only found in high-level languages.

### Installing Sysmon For Linux

After eBPF is installed you can move on to compiling and installing Sysmon, it has been well documented in the repository, just walk through the steps. Instructions [here](https://github.com/Sysinternals/SysmonForLinux).

While enabling sysmon in the Linux system a config file can be passed on:


```
# sysmon -accepteula -i /path/to/config_file.xml 
```



## Sysmon events included in Sysmon for Linux.

<span style="text-decoration:underline;">Event ID | Description</span>

1 | Process Creation

3 | Network Connect

5 | Process Terminate

9 | RAW access read

11 | File Create / Overwrite 

16 | Sysmon config change

23 | File Delete

As a starting point, the following config file can be used (record all supported events)


```
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Event ID 1 == ProcessCreate. Log all newly created processes -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 3 == NetworkConnect Detected. Log all network connections -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 5 == ProcessTerminate. Log all processes terminated -->
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 9 == RawAccessRead. Log all raw access read -->
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess. Log all open process operations -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 11 == FileCreate. Log every file creation -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
    <!--Event ID 23 == FileDelete. Log all files being deleted -->
    <RuleGroup name="" groupRelation="or">
      <FileDelete onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



## How events are logged.

Sysmon for Linux records events in “/var/log/syslog” (Debian/Ubuntu based distros) or in “/var/log/messages” (Redhat/Fedora based distros).

The format of the logged events is as follows (Debian/Ubuntu):


```
Dec 28 22:21:45 ubunutu2004vm sysmon: <full_event_in_XML>
```


Where “ubunutu2004vm” is the hostname of the machine where sysmon is running.

For Redhat/Fedora:


```
Dec 28 22:21:45 fedora sysmon[sysmon_pid]: <full_event_in_XML>
```


The PID of the sysmon process is added in this case in squared brackets.

## SYSMON EVENT ID 1:


```
<?xml version="1.0" encoding="UTF-8"?>
<Event>
   <System>
      <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}" />
      <EventID>1</EventID>
      <Version>5</Version>
      <Level>4</Level>
      <Task>1</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2021-12-28T22:21:50.643000000Z" />
      <EventRecordID>78947</EventRecordID>
      <Correlation />
      <Execution ProcessID="21298" ThreadID="21298" />
      <Channel>Linux-Sysmon/Operational</Channel>
      <Computer>ubunutu2004vm</Computer>
      <Security UserId="0" />
   </System>
   <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2021-12-28 22:21:50.650</Data>
      <Data Name="ProcessGuid">{277d2fec-8dfe-61cb-f1fe-8a16c6550000}</Data>
      <Data Name="ProcessId">37869</Data>
      <Data Name="Image">/usr/bin/tail</Data>
      <Data Name="FileVersion">-</Data>
      <Data Name="Description">-</Data>
      <Data Name="Product">-</Data>
      <Data Name="Company">-</Data>
      <Data Name="OriginalFileName">-</Data>
      <Data Name="CommandLine">tail -f /var/log/syslog</Data>
      <Data Name="CurrentDirectory">/home/jromero</Data>
      <Data Name="User">root</Data>
      <Data Name="LogonGuid">{277d2fec-0000-0000-0000-000000000000}</Data>
      <Data Name="LogonId">0</Data>
      <Data Name="TerminalSessionId">79</Data>
      <Data Name="IntegrityLevel">no level</Data>
      <Data Name="Hashes">-</Data>
      <Data Name="ParentProcessGuid">{277d2fec-8df5-61cb-0587-c95ca5550000}</Data>
      <Data Name="ParentProcessId">37862</Data>
      <Data Name="ParentImage">/usr/bin/bash</Data>
      <Data Name="ParentCommandLine">bash</Data>
      <Data Name="ParentUser">root</Data>
   </EventData>
</Event>
```


## SYSMON EVENT ID 3: 


```
<?xml version="1.0" encoding="UTF-8"?>
<Event>
   <System>
      <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}" />
      <EventID>3</EventID>
      <Version>5</Version>
      <Level>4</Level>
      <Task>3</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2021-12-28T22:39:36.263912000Z" />
      <EventRecordID>79230</EventRecordID>
      <Correlation />
      <Execution ProcessID="21298" ThreadID="21298" />
      <Channel>Linux-Sysmon/Operational</Channel>
      <Computer>ubunutu2004vm</Computer>
      <Security UserId="0" />
   </System>
   <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2021-12-28 22:39:36.272</Data>
      <Data Name="ProcessGuid">{277d2fec-19a9-61c8-6589-03ccc6550000}</Data>
      <Data Name="ProcessId">581</Data>
      <Data Name="Image">/usr/lib/systemd/systemd-timesyncd</Data>
      <Data Name="User">systemd-timesync</Data>
      <Data Name="Protocol">udp</Data>
      <Data Name="Initiated">true</Data>
      <Data Name="SourceIsIpv6">false</Data>
      <Data Name="SourceIp">192.168.252.191</Data>
      <Data Name="SourceHostname">-</Data>
      <Data Name="SourcePort">53259</Data>
      <Data Name="SourcePortName">-</Data>
      <Data Name="DestinationIsIpv6">false</Data>
      <Data Name="DestinationIp">91.189.91.157</Data>
      <Data Name="DestinationHostname">-</Data>
      <Data Name="DestinationPort">123</Data>
      <Data Name="DestinationPortName">-</Data>
   </EventData>
</Event>
```


## SYSMON EVENT ID 5:


```
<?xml version="1.0" encoding="UTF-8"?>
<Event>
   <System>
      <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}" />
      <EventID>5</EventID>
      <Version>3</Version>
      <Level>4</Level>
      <Task>5</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2021-12-28T22:21:41.752772000Z" />
      <EventRecordID>78940</EventRecordID>
      <Correlation />
      <Execution ProcessID="21298" ThreadID="21298" />
      <Channel>Linux-Sysmon/Operational</Channel>
      <Computer>ubunutu2004vm</Computer>
      <Security UserId="0" />
   </System>
   <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2021-12-28 22:21:41.761</Data>
      <Data Name="ProcessGuid">{277d2fec-8df5-61cb-31f9-ed3635560000}</Data>
      <Data Name="ProcessId">37868</Data>
      <Data Name="Image">/usr/bin/dircolors</Data>
      <Data Name="User">root</Data>
   </EventData>
</Event>
```


## SYSMON EVENT ID 9:


```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
	<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
	<EventID>9</EventID>
	<Version>2</Version>
	<Level>4</Level>
	<Task>9</Task>
	<Opcode>0</Opcode>
	<Keywords>0x8000000000000000</Keywords>
	<TimeCreated SystemTime="2018-03-22T20:32:22.333778700Z" />
	<EventRecordID>1944686</EventRecordID>
	<Correlation />
	<Execution ProcessID="19572" ThreadID="21888" />
	<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
	<Computer>rfsH.lab.local</Computer>
	<Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="UtcTime">2018-03-22 20:32:22.332</Data>
	<Data Name="ProcessGuid">{A23EAE89-C65F-5AB2-0000-0010EB030000}</Data>
	<Data Name="ProcessId">4</Data>
	<Data Name="Image">System</Data>
	<Data Name="Device">\Device\HarddiskVolume2</Data>
  </EventData>
 </Event>
```


(Event Above taken from Windows Sysmon)

## SYSMON EVENT ID 11:


```
<?xml version="1.0" encoding="UTF-8"?>
<Event>
   <System>
      <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}" />
      <EventID>11</EventID>
      <Version>2</Version>
      <Level>4</Level>
      <Task>11</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2021-12-28T22:21:44.382776000Z" />
      <EventRecordID>78941</EventRecordID>
      <Correlation />
      <Execution ProcessID="21298" ThreadID="21298" />
      <Channel>Linux-Sysmon/Operational</Channel>
      <Computer>ubunutu2004vm</Computer>
      <Security UserId="0" />
   </System>
   <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2021-12-28 22:21:44.391</Data>
      <Data Name="ProcessGuid">{277d2fec-2501-61c8-8cd4-480000000000}</Data>
      <Data Name="ProcessId">6626</Data>
      <Data Name="Image">/var/ossec/bin/wazuh-agentd</Data>
      <Data Name="TargetFilename">/var/ossec/var/run/wazuh-agentd.state.temp</Data>
      <Data Name="CreationUtcTime">2021-12-28 22:21:44.391</Data>
      <Data Name="User">ossec</Data>
   </EventData>
</Event>
```


## SYSMON EVENT ID 16:


```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
        <EventID>16</EventID>
        <Version>3</Version>
        <Level>4</Level>
        <Task>16</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8000000000000000</Keywords>
        <TimeCreated SystemTime="2017-04-28T21:24:31.661858200Z" />
        <EventRecordID>1</EventRecordID>
        <Correlation />
        <Execution ProcessID="32420" ThreadID="24524" />
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>rfsH.lab.local</Computer>
        <Security UserID="S-1-5-21-311908031-1195731464-1505490484-1605" />
    </System>
    <EventData>
        <Data Name="UtcTime">2017-04-28 21:24:31.661</Data>
        <Data Name="Configuration">sysmon64 -i -h sha256 -l -n</Data>
        <Data Name="ConfigurationFileHash">
        </Data>
    </EventData>
</Event>
```


(Event Above taken from Windows Sysmon)

## SYSMON EVENT ID 23:


```
<?xml version="1.0" encoding="UTF-8"?>
<Event>
   <System>
      <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}" />
      <EventID>23</EventID>
      <Version>5</Version>
      <Level>4</Level>
      <Task>23</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2021-12-28T22:21:33.858268000Z" />
      <EventRecordID>78884</EventRecordID>
      <Correlation />
      <Execution ProcessID="21298" ThreadID="21298" />
      <Channel>Linux-Sysmon/Operational</Channel>
      <Computer>ubunutu2004vm</Computer>
      <Security UserId="0" />
   </System>
   <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2021-12-28 22:21:33.867</Data>
      <Data Name="ProcessGuid">{277d2fec-19a8-61c8-a1a1-6e0374550000}</Data>
      <Data Name="ProcessId">396</Data>
      <Data Name="User">root</Data>
      <Data Name="Image">/usr/lib/systemd/systemd-udevd</Data>
      <Data Name="TargetFilename">/run/udev/queue</Data>
      <Data Name="Hashes">-</Data>
      <Data Name="IsExecutable">-</Data>
      <Data Name="Archived">-</Data>
   </EventData>
</Event>
```



## 


## Sysmon for Linux - Integration in Wazuh Agent

The main challenge is formatting the sysmon logs in the agent, converting them from XML to JSON.

To achieve this a python script is used with the following logic:



* The script tails the file where sysmon logs are stored.
    * While tailing the file a grep-alike pipe is applied, splitting the non-XML header from the sysmon event itself.
* A common xmltodict parsing is done first, parsing the XML section common to all sysmon events, regardless of their ID (&lt;Event>&lt;System> section).
* The second xmltodict parsing depends on the sysmon event ID recorded, extracting in each case the metadata in the &lt;EventData> section.
* The parsed event is converted to JSON and appended to the active responses log in the agent.
* Custom rules in the Wazuh manager (json decoder) are added.


### Python Script


```
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
```



### Python Script initialisation

The script is triggered via active response using rule_id=501|502|503 (Agent Started). In the bash script to be executed on the agent a check on python script running is done.

Script “/var/ossec/active-response/bin/sysmon_for_linux.sh”:


```
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
```



### Wazuh Manager config to trigger the sysmon event collection


```
 <command>
    <name>sysmon-for-linux</name>
    <executable>sysmon_for_linux.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
   <disabled>no</disabled>
    <command>sysmon-for-linux</command>
    <location>local</location>
    <rules_id>501,502,503</rules_id>
  </active-response>
```



### Wazuh Rules (Manager)


```
<!--
 - Sysmon For Linux rules
 - Created by SOCFortress.
 - https://www.socfortress.co
 - info@socfortress.co.
-->

<group name="linux,sysmon, ">
    <rule id="200150" level="3">
        <decoded_as>json</decoded_as>
        <field name="Event.System.ProviderName">^Linux-Sysmon$</field>
        <description>Sysmon For Linux</description>
        <options>no_full_log</options>
    </rule>
    <rule id="200151" level="3">
        <if_sid>200150</if_sid>
        <field name="Event.System.EventID">^1$</field>
        <group>sysmon_event1</group>
        <description>Sysmon - Event 1: Process creation $(Event.EventData.Data.Image)</description>
        <mitre>
         <id>T1204</id>
        </mitre>
        <options>no_full_log</options>
    </rule>
    <rule id="200152" level="3">
        <if_sid>200150</if_sid>
        <field name="Event.System.EventID">^3$</field>
        <description>Sysmon - Event 3: Network connection by $(Event.EventData.Data.Image)</description>
        <group>sysmon_event3</group>
        <mitre>
         <id>T1043</id>
        </mitre>
        <options>no_full_log</options>
    </rule>
    <rule id="200153" level="3">
        <if_sid>200150</if_sid>
        <field name="Event.System.EventID">^5$</field>
        <description>Sysmon - Event 5: Process terminated $(Event.EventData.Data.Image)</description>
        <group>sysmon_event5</group>
        <mitre>
         <id>T1204</id>
        </mitre>
        <options>no_full_log</options>
    </rule>
    <rule id="200154" level="3">
        <if_sid>200150</if_sid>
        <field name="Event.System.EventID">^9$</field>
        <description>Sysmon - Event 9: Raw Access Read by $(Event.EventData.Data.Image)</description>
        <group>sysmon_event9</group>
        <mitre>
         <id>T1204</id>
        </mitre>
        <options>no_full_log</options>
    </rule>
    <rule id="200155" level="3">
        <if_sid>200150</if_sid>
        <field name="Event.System.EventID">^11$</field>
        <description>Sysmon - Event 11: FileCreate by $(Event.EventData.Data.Image)</description>
	<group>sysmon_event_11</group>
        <mitre>
         <id>T1044</id>
        </mitre>
        <options>no_full_log</options>
    </rule>
    <rule id="200156" level="3">
        <if_sid>200150</if_sid>
        <field name="Event.System.EventID">^16$</field>
        <description>Sysmon - Event 16: Sysmon config state changed $(Event.EventData.Data.Configuration)</description>
        <group>sysmon_event_16</group>
        <mitre>
         <id>T1562</id>
        </mitre>
        <options>no_full_log</options>
    </rule>
    <rule id="200157" level="3">
        <if_sid>200150</if_sid>
        <field name="Event.System.EventID">^23$</field>
        <description>Sysmon - Event 23: FileDelete (A file delete was detected) by $(Event.EventData.Data.Image)</description>
        <group>sysmon_event_23</group>
        <mitre>
         <id>T1107</id>
         <id>T1485</id>
        </mitre>
        <options>no_full_log</options>
    </rule>
</group>
```


NOTE: The MITRE IDs added are quite generic and more granularity would be required, evaluation process name, etc., for each sysmon event type.

Alert (example):


```
{
   "timestamp":"2021-12-29T05:34:56.382+0000",
   "rule":{
      "level":3,
      "description":"Sysmon - Event 11: FileCreate by /var/ossec/bin/wazuh-agentd",
      "id":"200155",
      "mitre":{
         "id":[
            "T1044"
         ],
         "tactic":[
            "Persistence",
            "Privilege Escalation"
         ],
         "technique":[
            "File System Permissions Weakness"
         ]
      },
      "firedtimes":7983,
      "mail":false,
      "groups":[
         "linux",
         "sysmon",
         "sysmon_event_11"
      ]
   },
   "agent":{
      "id":"017",
      "name":"ubunutu2004vm",
      "ip":"192.168.252.191",
      "labels":{
         "customer":"3c59"
      }
   },
   "manager":{
      "name":"ASHWZH01"
   },
   "id":"1640756096.99481500",
   "decoder":{
      "name":"json"
   },
   "data":{
      "Event":{
         "System":{
            "ProviderName":"Linux-Sysmon",
            "Guid":"{ff032593-a8d3-4f13-b0d6-01fc615a0f97}",
            "EventID":"11",
            "Version":"2",
            "Level":"4",
            "Task":"11",
            "Opcode":"0",
            "Keywords":"0x8000000000000000",
            "TimeCreated":"2021-12-29T05:34:50.738308000Z",
            "EventRecordID":"166705",
            "Correlation":"null",
            "ProcessID":"21298",
            "ThreadID":"21298",
            "Channel":"Linux-Sysmon/Operational",
            "Computer":"ubunutu2004vm",
            "UserId":"0"
         },
         "EventData":{
            "Data":{
               "RuleName":"-",
               "UtcTime":"2021-12-29 05:34:50.746",
               "ProcessGuid":"{277d2fec-2501-61c8-8cd4-480000000000}",
               "ProcessID":"6626",
               "Image":"/var/ossec/bin/wazuh-agentd",
               "TargetFilename":"/var/ossec/var/run/wazuh-agentd.state.temp",
               "CreationUtcTime":"2021-12-29 05:34:50.746",
               "User":"ossec"
            }
         }
      }
   },
   "location":"/var/ossec/logs/active-responses.log"
}
```

