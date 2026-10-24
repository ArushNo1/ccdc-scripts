Here is the consolidated, sequential checklist of all the hardening, auditing, and cleanup commands:

### 1. Account Hardening & Password Change

* **Change `sa` password and enforce complexity:**
```powershell
sqlcmd -E -S localhost -Q "ALTER LOGIN [sa] WITH PASSWORD = 'YourStrongPassword123!', CHECK_POLICY = ON, CHECK_EXPIRATION = ON;"

```


* **Rename `sa` account:**
```powershell
sqlcmd -E -S localhost -Q "ALTER LOGIN [sa] WITH NAME = [sql_admin_local];"

```


* **Disable the renamed `sa` account (if not strictly needed by an app):**
```powershell
sqlcmd -E -S localhost -Q "ALTER LOGIN [sql_admin_local] DISABLE;"

```



---

### 2. Disable High-Risk Features & Execution Vectors

* **Disable `xp_cmdshell`, OLE automation, CLR, and Database Mail (One-liner):**
```powershell
sqlcmd -E -S localhost -Q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; EXEC sp_configure 'Ole Automation Procedures', 0; EXEC sp_configure 'clr enabled', 0; EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE;"

```



---

### 3. Authentication & Service Configuration

* **Enforce Windows Authentication only (disable Mixed Mode):**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*\MSSQLServer" -Name "LoginMode" -Value 1

```


* **Enable auditing for both successful and failed logins:**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*\MSSQLServer" -Name "AuditLevel" -Value 3

```


* **Disable the SQL Server Browser UDP discovery service:**
```powershell
Stop-Service -Name SQLBrowser -ErrorAction SilentlyContinue; Set-Service -Name SQLBrowser -StartupType Disabled

```


* **Restart SQL Server service to apply registry changes:**
```powershell
Restart-Service -Name MSSQLSERVER -Force

```



---

### 4. Privilege Auditing & Inspection Queries

* **List all server principals with `sysadmin` privileges:**
```powershell
sqlcmd -E -S localhost -Q "SELECT sp.name AS LoginName, sp.type_desc, sp.is_disabled, sp.modify_date FROM sys.server_principals sp JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id JOIN sys.server_principals spr ON srm.role_principal_id = spr.principal_id WHERE spr.name = 'sysadmin';"

```


* **Disable an unauthorized or rogue login:**
```powershell
sqlcmd -E -S localhost -Q "ALTER LOGIN [suspicious_user] DISABLE;"

```


* **Drop an unauthorized login completely:**
```powershell
sqlcmd -E -S localhost -Q "DROP LOGIN [suspicious_user];"

```


* **Inspect the SQL Server error log for failed authentication attempts:**
```powershell
sqlcmd -E -S localhost -Q "EXEC xp_readerrorlog 0, 1, 'Login failed';"

```



---

### 5. Network Exposure & Host Firewall

* **Drop broad inbound SQL rules and restrict TCP 1433 to trusted internal subnets:**
```powershell
Get-NetFirewallRule -DisplayName "*SQL*" | Remove-NetFirewallRule; New-NetFirewallRule -DisplayName "MSSQL - Restrict Access" -Direction Inbound -Protocol TCP -LocalPort 1433 -RemoteAddress 172.25.24.0/24 -Action Allow

```



---

### 6. Command History Cleanup

* **Wipe both PowerShell disk history and active memory buffer (One-liner):**
```powershell
Clear-History; if (Test-Path (Get-PSReadLineOption).HistorySavePath) { Clear-Content (Get-PSReadLineOption).HistorySavePath -Force }

```


* **Clear Command Prompt (`cmd.exe`) buffer:**
Press `Alt + F7` or close the window.
* **Clear Windows Run dialog (`Win + R`) history:**
```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name * -ErrorAction SilentlyContinue

```

---

sqlcmd -E -S localhost -Q "ALTER SERVER ROLE [sysadmin] DROP MEMBER [\Everyone]; ALTER SERVER ROLE [sysadmin] DROP MEMBER [UNDERPRESSURE\Guest]; ALTER SERVER ROLE [sysadmin] DROP MEMBER [UNDERPRESSURE\jerry]; ALTER SERVER ROLE [sysadmin] DROP MEMBER [UNDERPRESSURE\agrapplernamedsam]; DROP LOGIN [\Everyone]; DROP LOGIN [UNDERPRESSURE\Guest]; DROP LOGIN [UNDERPRESSURE\jerry]; DROP LOGIN [UNDERPRESSURE\agrapplernamedsam];"