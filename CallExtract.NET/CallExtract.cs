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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;

namespace CallExtract.NET
{
	public static class CallExtract
	{
		public record IPAndPort(string IP, string Port);

		public static void Perform(string searchQuery, IEnumerable<string> inputFiles, string outputFile)
		{
			// Verify support programs exist.
			if (string.IsNullOrWhiteSpace(Konstants.EXECUTABLE_TCPDUMP_PATH))
				throw new InvalidOperationException("No path to tcpdump, see --help.");
			if (string.IsNullOrWhiteSpace(Konstants.EXECUTABLE_TSHARK_PATH))
				throw new InvalidOperationException("No path to tshark, see --help.");
			if (string.IsNullOrWhiteSpace(Konstants.EXECUTABLE_MERGECAP_PATH))
				throw new InvalidOperationException("No path to mergecap, see --help.");

			// Verify query exists.
			if (string.IsNullOrWhiteSpace(searchQuery))
				throw new InvalidOperationException("No query provided, see --help.");



			// Merge all input pcaps together.
			string tmpMergedPcapsPath = Path.GetTempFileName();


			Process procMergeInputPCaps = new Process();

			procMergeInputPCaps.StartInfo.FileName = Konstants.EXECUTABLE_MERGECAP_PATH;
			procMergeInputPCaps.StartInfo.RedirectStandardError = true;
			procMergeInputPCaps.StartInfo.UseShellExecute = false;
			procMergeInputPCaps.StartInfo.ArgumentList.Add("-v"); // Verbose
			procMergeInputPCaps.StartInfo.ArgumentList.Add("-w"); // Write to
			procMergeInputPCaps.StartInfo.ArgumentList.Add(tmpMergedPcapsPath); // Write path.
			foreach (string file in inputFiles)
				procMergeInputPCaps.StartInfo.ArgumentList.Add(file); // Supplied pcap file

			procMergeInputPCaps.Start();
			StringBuilder mergecap1StderrBuff = new StringBuilder();
			while (!procMergeInputPCaps.HasExited)
			{
				mergecap1StderrBuff.Append(procMergeInputPCaps.StandardError.ReadToEnd());


			}
			string mergecap1Stderr = mergecap1StderrBuff.ToString();

			// Extract just signaling.

			string tmpSignalingPcapPath = Path.GetTempFileName();

			Process procExtractSignaling = new Process();
			procExtractSignaling.StartInfo.FileName = Konstants.EXECUTABLE_TSHARK_PATH;
			procExtractSignaling.StartInfo.ArgumentList.Add("-r"); // Read file.
			procExtractSignaling.StartInfo.ArgumentList.Add(tmpMergedPcapsPath); // pcap file to read
			procExtractSignaling.StartInfo.ArgumentList.Add("-w"); // File to write out to.
			procExtractSignaling.StartInfo.ArgumentList.Add(tmpSignalingPcapPath); // path to signaling file
			procExtractSignaling.StartInfo.ArgumentList.Add("-2"); // Scan twice to fill in missing info.
			procExtractSignaling.StartInfo.ArgumentList.Add("-R"); // Read filter
			procExtractSignaling.StartInfo.ArgumentList.Add(searchQuery); // wireshark query
			procExtractSignaling.StartInfo.RedirectStandardError = true;
			procExtractSignaling.StartInfo.UseShellExecute = false;

			procExtractSignaling.Start();
			StringBuilder procExtractSignalingStderrBuff = new StringBuilder();
			while (!procExtractSignaling.HasExited)
			{
				procExtractSignalingStderrBuff.Append(procExtractSignaling.StandardError.ReadToEnd());


			}
			string procExtractSignalingStderr = procExtractSignalingStderrBuff.ToString();


			// "C:\Program Files\Wireshark\tshark.exe" -r C:\Users\Dan\Desktop\tmpE171.pcap -T fields -e sdp.connection_info.address -e sdp.media.port


			// tcpdump filter:
			//(host 10.1.1.20 && udp port 4016 )
			// ||
			//(host 10.1.1.20 && udp port 4016 )
			// ||
			//(host 172.105.104.150 && udp port 28452 )
			// ||
			//(host 172.105.104.150 && udp port 26250 )
			// ||
			//(host 172.105.104.150 && udp port 26250 )
			// ||
			//(host 172.105.13.149 && udp port 20000 )
			// ||
			//(host 172.105.13.149 && udp port 20000 )

			// Extract sdp media information from the packets.

			Process procExtractSDPMedia = new Process();
			procExtractSDPMedia.StartInfo.FileName = Konstants.EXECUTABLE_TSHARK_PATH;
			procExtractSDPMedia.StartInfo.ArgumentList.Add("-r"); // Read file.
			procExtractSDPMedia.StartInfo.ArgumentList.Add(tmpSignalingPcapPath); // filtered signaling pcap file
			procExtractSDPMedia.StartInfo.ArgumentList.Add("-T"); // Set the format of the output when viewing decoded packet data
			procExtractSDPMedia.StartInfo.ArgumentList.Add("fields"); // value of fields
			procExtractSDPMedia.StartInfo.ArgumentList.Add("-E"); // Set an option controlling the printing of fields
			procExtractSDPMedia.StartInfo.ArgumentList.Add("separator=,"); // Set the separator character to use for fields.
																		   //procExtractSDPMedia.StartInfo.ArgumentList.Add("-E"); // Set an option controlling the printing of fields
																		   //procExtractSDPMedia.StartInfo.ArgumentList.Add("quote=d"); // Set the quote character to use to surround fields.
			procExtractSDPMedia.StartInfo.ArgumentList.Add("-e"); // Add a field to the list of fields to display
			procExtractSDPMedia.StartInfo.ArgumentList.Add("sdp.connection_info.address"); // Address in RTP packets
			procExtractSDPMedia.StartInfo.ArgumentList.Add("-e"); // Add a field to the list of fields to display
			procExtractSDPMedia.StartInfo.ArgumentList.Add("sdp.media.port"); // Media attribute, port
			procExtractSDPMedia.StartInfo.RedirectStandardOutput = true;
			procExtractSDPMedia.StartInfo.UseShellExecute = false;

			procExtractSDPMedia.Start();
			StringBuilder procExtractSDPMediaStdoutBuff = new StringBuilder();
			while (!procExtractSDPMedia.HasExited)
			{
				procExtractSDPMediaStdoutBuff.Append(procExtractSDPMedia.StandardOutput.ReadToEnd());


			}

			string procExtractSDPMediaStdout = procExtractSDPMediaStdoutBuff.ToString();
			string[] sdpMediaLines = procExtractSDPMediaStdout.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

			//,
			//,
			//"10.1.1.20","4016"
			//,
			//,
			//"10.1.1.20","4016"
			//,
			//"172.105.104.150","28452"
			//,
			//"172.105.104.150","26250"
			//,
			//"172.105.13.149","20000"
			//,
			//,
			//,
			//,
			//,

			List<IPAndPort> rtpAddresses = new List<IPAndPort>();

			foreach (string line in sdpMediaLines)
			{
				if (line == ",") // skip any empty lines, not all sdp packets have media info
					continue;

				if (string.IsNullOrWhiteSpace(line))
					continue;

				string[] columns = line.Split(",");
				if (columns.Length != 2)
				{
					Console.WriteLine($"We got some weird sdp information on this line, skipping: {line}");
				}

				string ip = columns[0];
				string port = columns[1];

				rtpAddresses.Add(new IPAndPort(ip, port));
			}

			StringBuilder rtpFilterStringSB = new StringBuilder();
			for (int i = 0; i < rtpAddresses.Count; i++)
			{
				rtpFilterStringSB.AppendLine($"( host {rtpAddresses[i].IP} && udp port {rtpAddresses[i].Port} )");

				if (i != (rtpAddresses.Count - 1))
					rtpFilterStringSB.AppendLine("||");
			}

			string rtpFilterString = rtpFilterStringSB.ToString();

			// Filter original pcap with tcpdump to get the rtp packets.

			string tmpRTPPath = Path.GetTempFileName();

			Process procTCPDumpExtractRTP = new Process();
			procTCPDumpExtractRTP.StartInfo.FileName = Konstants.EXECUTABLE_TCPDUMP_PATH;
			procTCPDumpExtractRTP.StartInfo.ArgumentList.Add("-s"); // snapshot-length
			procTCPDumpExtractRTP.StartInfo.ArgumentList.Add("1514"); // 
			procTCPDumpExtractRTP.StartInfo.ArgumentList.Add("-r"); // Read packets from file
			procTCPDumpExtractRTP.StartInfo.ArgumentList.Add(tmpMergedPcapsPath); // 
			procTCPDumpExtractRTP.StartInfo.ArgumentList.Add("-w"); // Write the raw packets to file
			procTCPDumpExtractRTP.StartInfo.ArgumentList.Add(tmpRTPPath); // 
			procTCPDumpExtractRTP.StartInfo.ArgumentList.Add(rtpFilterString); // computed filter from above
			procTCPDumpExtractRTP.StartInfo.RedirectStandardOutput = true;
			procTCPDumpExtractRTP.StartInfo.UseShellExecute = false;

			procTCPDumpExtractRTP.Start();
			StringBuilder procTCPDumpExtractRTPStdoutBuff = new StringBuilder();
			while (!procTCPDumpExtractRTP.HasExited)
			{
				procTCPDumpExtractRTPStdoutBuff.Append(procTCPDumpExtractRTP.StandardOutput.ReadToEnd());


			}

			string procTCPDumpExtractRTPStdout = procTCPDumpExtractRTPStdoutBuff.ToString();


			// Merge the signaling file and the rtp file together.

			Process procMergeFinalFile = new Process();

			procMergeFinalFile.StartInfo.FileName = Konstants.EXECUTABLE_MERGECAP_PATH;
			procMergeFinalFile.StartInfo.RedirectStandardError = true;
			procMergeFinalFile.StartInfo.UseShellExecute = false;
			procMergeFinalFile.StartInfo.ArgumentList.Add("-v"); // Verbose
			procMergeFinalFile.StartInfo.ArgumentList.Add("-w"); // Write to
			procMergeFinalFile.StartInfo.ArgumentList.Add(outputFile); // Write path.
			procMergeFinalFile.StartInfo.ArgumentList.Add(tmpSignalingPcapPath); // Signaling file
			procMergeFinalFile.StartInfo.ArgumentList.Add(tmpRTPPath); // RTP file

			procMergeFinalFile.Start();
			StringBuilder procMergeFinalFileStderrBuff = new StringBuilder();
			while (!procMergeFinalFile.HasExited)
			{
				mergecap1StderrBuff.Append(procMergeFinalFile.StandardError.ReadToEnd());


			}
			string procMergeFinalFileStderr = procMergeFinalFileStderrBuff.ToString();



			// Cleanup
			File.Delete(tmpMergedPcapsPath);
			File.Delete(tmpSignalingPcapPath);
			File.Delete(tmpRTPPath);
		}
	}
}
