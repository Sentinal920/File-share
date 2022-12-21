
### Generate new SID on every clone of VM Template

1) Run sysprep with xml (Auto-answer) file with /shutdown argument. 
2) Once it's shutdown, convert it to a VM template. 
3) Now every time you create a new VM from this template, it'll generate new SID for the VM.

Replace unattended.xml with the file depending upon the OS

```
c:\windows\system32\sysprep\sysprep /generalize /oobe /shutdown /unattend:unattended.xml
```
