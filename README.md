# CallExtract

Call extract is a quick and dirty utility that will extract calls with a specific phone number or other wireshark compatible search query from a collection of .pcap files.

Wireshark itself is pretty great for troubleshooting VoIP calls, however when it comes to large .pcap files, every action you take causes it to reload the entire file. If the file gets too large, you can't play streams anymore the player falsely shows as empty. Additionally, if your capture is long running spaning multiple pcap files, you may miss parts of call if it spans multiple files.

This tool automates the terminal version of Wireshark known as tshark to extract the sip data for the phone number that you want, it then uses either tcpdump on linux, or WinDump on windows to search the files again for any rtp data that is referenced by the SIP packet's SDP data. This all results in a single .pcap file that contains just the calls you want.

## Prerequisites (Linux)

This has been tested with Debian.

* Install dotnet as per https://docs.microsoft.com/en-us/dotnet/core/install/linux-debian
* apt install tshark tcpdump

## Prerequisites (Windows 10)

* You must install the latest version of Wireshark from https://www.wireshark.org/#download You must make sure that the tshark executable is located at "C:\Program Files\Wireshark\tshark.exe" and the mergecap executable is located at "C:\Program Files\Wireshark\mergecap.exe". You can overwrite this by setting the environment variables EXECUTABLE_PATH_TSHARK and EXECUTABLE_PATH_MERGECAP .
* Install a Windows 10 compatible version of WinDump, I used this one: https://github.com/hsluoyz/WinDump/releases/tag/v0.3 You must make sure that the WinDump.exe file is located at "C:\Program Files\WinDump-for-Npcap-0.3\x64\WinDump.exe". You can overwrite this by setting the environment variable EXECUTABLE_TCPDUMP_PATH .
* Install the dotnet runtime https://dotnet.microsoft.com/download/dotnet/thank-you/runtime-desktop-6.0.0-windows-x64-installer

## Example use case: 

You are having a long term issue with some phone calls having issues. Unfortunately it is happening too intermittently to catch.

1. Hook up a port mirroring switch in the path of the voice traffic. In this example, I set an old 24 port switch to mirror all ports to port number 1. I then connected the ISP modem to port number 6, and the phone system to port number 18.
2. On the laptop that will be watching this connection, I disabled IPv4 and IPv6 on the "Ethernet" interface so that the laptop wouldn't try to pull an IP from the modem over DHCP. 
3. I ran the following command in a terminal window to capture all traffic coming out of the phone system. This will capture a max of 50 files so that it doesn't fill up the laptop's drive.

~~~
"C:\Program Files\Wireshark\dumpcap.exe" -i "Ethernet" -q -b duration:3600 -b files:50 -w "C:\Users\dan\Desktop\capture.pcapng"
~~~

4. Wait until you get a report of the issue. 
5. Once you get a report, make sure to note down the date and time, and the number that was involved. 
6. Run CallExtract:

~~~
.\CallExtract.exe --output=C:\Users\dan\Desktop\extracted.pcap --did=2045551234 [pcap1path] [pcap2path] etc
~~~

7. Assuming the input pcaps provided were properly formatted, you will have a file on your desktop that contains just the specific phone calls you were looking for.


Enjoy!

-- Dan Saul
