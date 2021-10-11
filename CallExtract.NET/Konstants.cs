// (c) 2021 Dan Saul, All Rights Reserved
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation using version 3 of the License.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Runtime.InteropServices;

namespace CallExtract.NET
{
	public static class Konstants
	{
		public const string kTcpdumpEnvVariableName = "EXECUTABLE_PATH_TCPDUMP";
		public const string kWindowsDefaultWinDumpPath = @"C:\Program Files\WinDump-for-Npcap-0.3\x64\WinDump.exe";
		public const string kLinuxDefaultTcpdumpPath = @"/usr/sbin/tcpdump";

		public const string kTsharkEnvVariableName = "EXECUTABLE_PATH_TSHARK";
		public const string kWindowsDefaultTsharkPath = @"C:\Program Files\Wireshark\tshark.exe";
		public const string kLinuxDefaultTsharkPath = @"/usr/bin/tshark";

		public const string kMergecapEnvVariableName = "EXECUTABLE_PATH_MERGECAP";
		public const string kWindowsDefaultMergecapPath = @"C:\Program Files\Wireshark\mergecap.exe";
		public const string kLinuxDefaultMergecapPath = @"/usr/bin/mergecap";

		public static string EXECUTABLE_TCPDUMP_PATH
		{
			get
			{
				string? env = Environment.GetEnvironmentVariable(kTcpdumpEnvVariableName);
				if (!string.IsNullOrWhiteSpace(env))
					return env;

				if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
					return kWindowsDefaultWinDumpPath;
				else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
					return kLinuxDefaultTcpdumpPath;

				throw new InvalidOperationException("Tcpdump: No default path for detected operating system.");
			}
		}

		public static string EXECUTABLE_TSHARK_PATH
		{
			get
			{
				string? env = Environment.GetEnvironmentVariable(kTsharkEnvVariableName);
				if (!string.IsNullOrWhiteSpace(env))
					return env;

				if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
					return kWindowsDefaultTsharkPath;
				else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
					return kLinuxDefaultTsharkPath;

				throw new InvalidOperationException("Tshark: No default path for detected operating system.");
			}
		}

		public static string EXECUTABLE_MERGECAP_PATH
		{
			get
			{
				string? env = Environment.GetEnvironmentVariable(kMergecapEnvVariableName);
				if (!string.IsNullOrWhiteSpace(env))
					return env;

				if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
					return kWindowsDefaultMergecapPath;
				else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
					return kLinuxDefaultMergecapPath;

				throw new InvalidOperationException("Mergecap: No default path for detected operating system.");
			}
		}
	}
}
