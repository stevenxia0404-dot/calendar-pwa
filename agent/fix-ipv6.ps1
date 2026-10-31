Disable-NetAdapterBinding -Name "WLAN" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "本地连接" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name "utun244" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
"done"
