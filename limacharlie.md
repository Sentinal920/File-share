
**Download Sensors & Install them in VMs**
https://downloads.limacharlie.io/sensor/windows/msi64
https://downloads.limacharlie.io/sensor/linux/deb64

**Sample sensor InstallationKey**
```
AAAABgAAAQsFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEAIBuwAAAQwFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEQIBuwAAAAiBAAAABQAAAAUHAAAAEA55b25hlUPjpTidkVZltvAAAAAJBwAAABBGI9xSHzxNLIKyekStpIZ2AAAABAcAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAcDAAAAAAAAAAYDAAAAAAAAAQ4HAAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANyjhXY1h793TFRgw2b78ydr4K4g5k7NrytkEthyjEVwvb58fMmA7EfoGdg5QYYXLBp9QV6hHiAw7EsMtTMCnUe3aSgamNxsODm+1zLjGI1DRlrgzp0i4TgYYD9P+gBaY5Sb7bN82R4cu+coKEE+zZP6FRQ/h6TVJN2ZJ6cwMF1kU6mrz24at0pr1BH17ZeV+TELmuQ4OwRSoBXLawFUkEzQW4rgMBfv0dO9gKWGRmajxwz350/61DxNhQP97nJM51FuNj5OFVPhHB5Oa6CX/v1l6fO4PNOa44QM+WE3s4U46DqWaPWPT8hmr7F7/PPIfb/HpvJ88psDqtEwPFlDwMcCAwEAAQ==
```

#### Install Sensor in windows with INSTALLATION_KEY using following command
```powershell
installer.msi InstallationKey="AAAABgAAAQsFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEAIBuwAAAQwFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEQIBuwAAAAiBAAAABQAAAAUHAAAAEA55b25hlUPjpTidkVZltvAAAAAJBwAAABBGI9xSHzxNLIKyekStpIZ2AAAABAcAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAcDAAAAAAAAAAYDAAAAAAAAAQ4HAAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANyjhXY1h793TFRgw2b78ydr4K4g5k7NrytkEthyjEVwvb58fMmA7EfoGdg5QYYXLBp9QV6hHiAw7EsMtTMCnUe3aSgamNxsODm+1zLjGI1DRlrgzp0i4TgYYD9P+gBaY5Sb7bN82R4cu+coKEE+zZP6FRQ/h6TVJN2ZJ6cwMF1kU6mrz24at0pr1BH17ZeV+TELmuQ4OwRSoBXLawFUkEzQW4rgMBfv0dO9gKWGRmajxwz350/61DxNhQP97nJM51FuNj5OFVPhHB5Oa6CX/v1l6fO4PNOa44QM+WE3s4U46DqWaPWPT8hmr7F7/PPIfb/HpvJ88psDqtEwPFlDwMcCAwEAAQ=="
```

OR

#### Change limacharlie installation key in windows using [POWERSHELL]
```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\rphcpsvc" `
-Name ImagePath -Value "C:\Windows\System32\rphcp.exe -w -d AAAABgAAAQsFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEAIBuwAAAQwFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEQIBuwAAAAiBAAAABQAAAAUHAAAAEA55b25hlUPjpTidkVZltvAAAAAJBwAAABBGI9xSHzxNLIKyekStpIZ2AAAABAcAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAcDAAAAAAAAAAYDAAAAAAAAAQ4HAAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANyjhXY1h793TFRgw2b78ydr4K4g5k7NrytkEthyjEVwvb58fMmA7EfoGdg5QYYXLBp9QV6hHiAw7EsMtTMCnUe3aSgamNxsODm+1zLjGI1DRlrgzp0i4TgYYD9P+gBaY5Sb7bN82R4cu+coKEE+zZP6FRQ/h6TVJN2ZJ6cwMF1kU6mrz24at0pr1BH17ZeV+TELmuQ4OwRSoBXLawFUkEzQW4rgMBfv0dO9gKWGRmajxwz350/61DxNhQP97nJM51FuNj5OFVPhHB5Oa6CX/v1l6fO4PNOa44QM+WE3s4U46DqWaPWPT8hmr7F7/PPIfb/HpvJ88psDqtEwPFlDwMcCAwEAAQ=="

net stop "rphcpsvc";start-Service rphcpsvc 
```

#### Install Sensor in Linux with INSTALLATION_KEY using .deb file (https://downloads.limacharlie.io/sensor/linux/deb64)
```bash
echo "limacharlie limacharlie/installation_key string AAAABgAAAQsFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEAIBuwAAAQwFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEQIBuwAAAAiBAAAABQAAAAUHAAAAEA55b25hlUPjpTidkVZltvAAAAAJBwAAABBGI9xSHzxNLIKyekStpIZ2AAAABAcAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAcDAAAAAAAAAAYDAAAAAAAAAQ4HAAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANyjhXY1h793TFRgw2b78ydr4K4g5k7NrytkEthyjEVwvb58fMmA7EfoGdg5QYYXLBp9QV6hHiAw7EsMtTMCnUe3aSgamNxsODm+1zLjGI1DRlrgzp0i4TgYYD9P+gBaY5Sb7bN82R4cu+coKEE+zZP6FRQ/h6TVJN2ZJ6cwMF1kU6mrz24at0pr1BH17ZeV+TELmuQ4OwRSoBXLawFUkEzQW4rgMBfv0dO9gKWGRmajxwz350/61DxNhQP97nJM51FuNj5OFVPhHB5Oa6CX/v1l6fO4PNOa44QM+WE3s4U46DqWaPWPT8hmr7F7/PPIfb/HpvJ88psDqtEwPFlDwMcCAwEAAQ==" | sudo debconf-set-selections && sudo dpkg -i limacharlie.deb
```

#### INSTALLATION_KEY is saved in /etc/systemd/system/limacharlie.service 
```
cat /etc/systemd/system/limacharlie.service 
[Unit]
Description=LimaCharlie Agent
[Service]
Type=simple
User=root
Restart=always
RestartSec=10
WorkingDirectory=/etc
ExecStart=/bin/rphcp -d AAAABgAAAQsFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEAIBuwAAAQwFAAAAIzRkODk3MDE1YjA4MTU2MjEubGMubGltYWNoYXJsaWUuaW8AAAABEQIBuwAAAAiBAAAABQAAAAUHAAAAEA55b25hlUPjpTidkVZltvAAAAAJBwAAABBGI9xSHzxNLIKyekStpIZ2AAAABAcAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAcDAAAAAAAAAAYDAAAAAAAAAQ4HAAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANyjhXY1h793TFRgw2b78ydr4K4g5k7NrytkEthyjEVwvb58fMmA7EfoGdg5QYYXLBp9QV6hHiAw7EsMtTMCnUe3aSgamNxsODm+1zLjGI1DRlrgzp0i4TgYYD9P+gBaY5Sb7bN82R4cu+coKEE+zZP6FRQ/h6TVJN2ZJ6cwMF1kU6mrz24at0pr1BH17ZeV+TELmuQ4OwRSoBXLawFUkEzQW4rgMBfv0dO9gKWGRmajxwz350/61DxNhQP97nJM51FuNj5OFVPhHB5Oa6CX/v1l6fO4PNOa44QM+WE3s4U46DqWaPWPT8hmr7F7/PPIfb/HpvJ88psDqtEwPFlDwMcCAwEAAQ==
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target


# After changing installation key restart the service
systemctl restart limacharlie
```

## Configure Routing for INTERNAL adapters to be able to ping lab_controller (-> internet)
#### LINUX (ens160 is DHCP interface and ens192 is INTERNAL interface)
Run following script in DHCP VM & Change Gateways for the VMs having INTERNAL adapters to point out to INTERNAL IP of VM having DHCP+INTERNAL adapter
```bash
apt update -y && apt install iptables-persistent -y
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p
iptables -A FORWARD -i ens192 -o ens160 -j ACCEPT
iptables -A FORWARD -i  ens160 -o ens192 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -o ens160 -j MASQUERADE
iptables -t nat -A POSTROUTING -o ens192 -j MASQUERADE
iptables-save > /etc/iptables/rules.v4
```

#### WINDOWS
```
- Note down the static IP of INTERNAL adapter inside DHCP VM
- 'Network & Sharing Center' -> Edit DHCP adapter Ethernet Properties
- Click on Share & Share the internet connection with network.
- After sharing the static IP of TNTERNAL adapter would be replaced with 192.168.x.x. 
- Replace that again with original static IP of INTERNAL adapter that was previously noted down.

Once done, run following to persist network sharing after reboot

New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\SharedAccess -Name EnableRebootPersistConnection -Value 1 -PropertyType dword
Set-Service SharedAccess –startuptype automatic –passthru
Start-Service SharedAccess
```
