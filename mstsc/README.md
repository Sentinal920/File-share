
Enable RDP Client in server core
```
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/d2d1.dll C:\Windows\System32\d2d1.dll
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/d3d11.dll C:\Windows\System32\d3d11.dll
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/dxgi.dll C:\Windows\System32\dxgi.dll
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/msacm32.dll C:\Windows\System32\msacm32.dll
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/mstsc.exe C:\Windows\System32\mstsc.exe 
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/mstscax.dll C:\Windows\System32\mstscax.dll
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/en-US/mstsc.exe.mui C:\Windows\System32\en-US\mstsc.exe.mui
certutil -urlcache -f https://github.com/Sentinal920/File-share/raw/main/mstsc/en-US/mstscax.dll.mui C:\Windows\System32\en-US\mstscax.dll.mui
certutil -urlcache * delete
```
