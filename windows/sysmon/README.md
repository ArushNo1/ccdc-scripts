# Sysmon

This installs Sysmon and uses `umd.xml` to log activity on the box. Run it as administrator:

```powershell
.\sysmon.ps1
```

Keep the `tools` folder next to the `sysmon` folder. The script uses `..\tools\Sysmon64.exe`.

To watch all collected activity in the terminal:

```powershell
.\sysmon.ps1 -Monitor
```

Keep that PowerShell window open. Q or Ctrl+C stops the viewer, but Sysmon will keep logging.

If you do not supply `-Monitor`, sysmon will start but you must look in event viewer to check logs.

## What it shows

Every event collected by `umd.xml` appears in an interactive event list. Routine events are gray, suspicious findings are yellow and critical findings are red. Select an event to see its details below.

**PLEASE NOTE THAT JUST BECAUSE AN EVENT IS GRAY DOES NOT MEAN ITS SAFE. THE CLASSIFIER WILL GET THINGS WRONG. CHECK ANYTHING YOU SEE SUSPICIOUS**

Details include full command lines, parent commands and PIDs, user and integrity level, network endpoints, DNS queries/results, registry values, file paths and other fields relevant to that event. Process context appears when its creation event is available.

### Controls

- Up/Down or Page Up/Page Down: browse events.
- Tab: switch between the event list and details. Arrow/page keys then scroll the details.
- Home/End: first/latest event, or top/bottom of the details.
- Click **FOLLOW LATEST**, press F or Ctrl+End: clear filters and follow the newest events from either pane.
- P: pause/resume following new events. Collection continues while paused.
- Mouse: click an event to select it; use the wheel to browse the pane under the pointer. If mouse input is unavailable, keyboard controls still work.
- `/`: search event fields and pause following. Enter applies; Esc cancels.
- I: filter by event ID. Leave blank for all IDs.
- S: cycle all events, suspicious/critical, or critical only.
- C: clear filters.
- Q: quit the viewer.
- Y or click **COPY DETAILS**: copy the selected event's full details and findings to the Windows clipboard, including lines outside the visible area. Following pauses; F resumes it

The viewer keeps the latest 5,000 events in memory. Older events remain in the text log. Use `-NoTui` for the grouped scrolling output. Redirected output and `-Once` also use that mode.

The monitor highlights:

- Executables with missing, invalid or unavailable signatures starting from locations such as Downloads, AppData, Temp or ProgramData.
- Outbound connections from those executables, with repeat alerts suppressed for the same process/destination/port.
- Encoded PowerShell and download commands.
- Critical: IIS, Apache, PHP-CGI, nginx or Tomcat directly starting cmd, PowerShell, WScript, CScript, mshta, bash or sh. Possible webshell activity; check the parent, command line and user. Legitimate web applications can also start these tools. This check works without `-ProfileCheck`.
- Possible process injection and process tampering (Event 25).
- WMI subscriptions. Sysmon service/configuration changes also appear as routine events.
- DNS traffic to unapproved servers, if you supply `-ApprovedDnsServer`.

Full fields for every collected event, plus available process context, save to `C:\ProgramData\CCDC\Sysmon\alerts.log`. View filters do not affect this log. The text log includes routine events too, so it can grow quickly.

The original XML noise filters still apply. Activity excluded by `umd.xml` is not collected and cannot appear here.

**An alert does not automatically mean red team. Check it before killing anything. The script does not block traffic or kill processes, IT IS NOT A SOAR. Please investigate carefully.**

**IF YOU DO NOT WANT TO USE A TUI, YOU CAN ALWAYS LOOK AT SYSMON LOGS IN EVENT VIEWER: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational**

Legitimate unsigned tools can trigger these checks. Signed malware, injected code and executables outside the checked locations can be missed. 

## Experimental profile checks

```powershell
.\sysmon.ps1 -Monitor -ProfileCheck
```

Adds **possible C2 activity** findings for:

- Long Base32-looking DNS labels. Five distinct names from the same process and suffix within 5 minutes become critical.
- TCP/UDP activity involving executables with missing, invalid or unavailable signatures in writable locations, including inbound TCP/P2P and SMB connections.
- Five approximately periodic connections from one process to the same destination within 5 minutes. These become critical only when the executable also matches the writable-location/signature check. Otherwise they are suspicious. Concurrent connections are not counted as periodic activity.
- DNS lookups/connections to Discord, Slack, GitHub API, Gitee, Azure Blob, Teams/Graph and Tailscale endpoints.
- Common MQTT ports, suspicious named pipes and packet capture libraries loaded by executables matching the writable-location/signature check.

Without `-ProfileCheck`, these extra classifications, including the DNS critical escalation, are off. Every collected event still appears and saves to the log. The regular process, network, injection, WMI and tampering checks still apply.

These are experimental heuristics. A connection does not reveal whether it carries HTTP, WebSocket, MQTT or C2 messages. Legitimate API clients, polling programs, unsigned tools and packet capture software can trigger them. Jitter, persistent connections, signed/injected agents, changed endpoints and XML exclusions can hide activity.

## Arguments

- `-Monitor`: applies the config, then continuously monitors.
- `-MonitorOnly`: monitors without installing Sysmon or changing its config.
- `-NoTui`: uses grouped scrolling output instead of the interactive viewer.
- `-ProfileCheck`: enables the experimental C2 activity checks. Off by default.
- `-BufferSize`: maximum events kept in the viewer. Default: 5,000.
- `-ApprovedDnsServer`: approved DNS server IPs, separated by commas.
- `-SysmonPath`: uses a different Sysmon executable.
- `-AlertPath`: changes where all displayed events and findings are saved.
- `-LookBackMinutes`: how much recent history to check when monitoring starts. Default: 5.
- `-MinimumLabelLength`: minimum Base32-looking DNS label length. Default: 24.
- `-DnsThreshold` and `-WindowMinutes`: change the DNS alert threshold. Defaults: 5 names in 5 minutes.
- `-PollSeconds`: time between checks. Default: 3.
- `-Once`: checks one batch of up to 1,000 events, then stops. Use with `-Monitor` or `-MonitorOnly`.
