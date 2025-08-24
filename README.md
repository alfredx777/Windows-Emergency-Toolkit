# Windows Emergency Toolkit (PowerShell)

A menu-driven *panic button for Windows* that helps you recover, protect, and isolate your system during emergencies.

## Features
- ✅ Quick Backup (Desktop, Documents, Pictures, Downloads, Videos)
- ✅ System Restore Point
- ✅ Installed Apps Export (CSV)
- ✅ Driver Export (offline reinstall)
- ✅ Ransomware Protection (Defender Controlled Folder Access)
- ✅ Network Kill Switch (disable/enable adapters)

## When to Use
- Ransomware or malware scare  
- Bad update or unstable driver  
- Hard drive failing  
- Before reinstalling Windows  
- IT support triage  
- Offline/field recovery  

## Usage
Run PowerShell as Administrator, then:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\EmergencyToolkit.ps1
