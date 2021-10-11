using Mono.Options;
using System;
using System.Collections.Generic;
using System.IO;
using CallExtract.NET;


//sip.to.addr contains 2042877433 || sip.from.addr contains 2042877433

//tshark -r test.pcap -w test.signaling.pcap -2 -R "sip.to.addr contains 2042877433 || sip.from.addr contains 2042877433"

namespace CallExtract
{
	class Program
	{
		static List<string> inputFiles = new List<string>();
		static string? outputFile = null;
		static string? searchQuery = null;
		static bool showHelp = false;

		
		

		
		static void Main(string[] args)
		{

			var p = new OptionSet() {
				"Usage: CallExtract [odqh] [inputfiles.pcap]...",
				"(c) 2021 Dan Saul All Rights Reserved",
				"",
				"This program extracts SIP signaling, then extracts RTP that appears to be related to the SDP found in that signaling.",
				"",
				"\"inputfiles.pcap\" are the set of PCAP files that may contain the call you are looking for. They are " +
				"scanned twice; once for finding the signaling, then a second time for extracting the RTP.",
				"",
				"Important! This program has several requirements to function:",
				" - Windows: Install WinDump from https://github.com/dsaul/WinDump",
				$"   Must be located at \"{Konstants.kWindowsDefaultWinDumpPath}\".",
				"",
				"   Linux: Install tcpdump from your package manager,",
				"   this has only been tested on Debian 11+.",
				$"   Must be located at \"{Konstants.kLinuxDefaultTcpdumpPath}\".",
				
				"",
				$"   To specify a custom location, set the environment variable ",
				$"   {Konstants.kTcpdumpEnvVariableName}",
				"",
				" - Windows: Install the latest 64 bit version of Wireshark.",
				"   You can download Wireshark from https://www.wireshark.org/#download",
				$"   Must be located at \"{Konstants.kWindowsDefaultTsharkPath}\".",
				$"   Must be located at \"{Konstants.kWindowsDefaultMergecapPath}\".",
				"",
				"   Linux: Install the latest tshark version from your package manager, ",
				"   this has only been tested on Debian 11+.",
				$"   Must be located at \"{Konstants.kLinuxDefaultTsharkPath}\".",
				$"   Must be located at \"{Konstants.kLinuxDefaultMergecapPath}\".",
				"",
				$"   To specify a custom location, set the environment variables ",
				$"   {Konstants.kTsharkEnvVariableName} and {Konstants.kMergecapEnvVariableName}.",
				"",
				{
					"o|output=",
					"a .pcap file that we will write the extracted calls to",
					(value) => {

						if (string.IsNullOrWhiteSpace(value))
							throw new OptionException ($"No argument provided!", "-o");

						if (File.Exists(value))
							throw new OptionException ($"\"{value}\" already exists!", "-o");

						outputFile = value;
					}
				},
				{
					"d|did=",
					"generates a wireshark compatible filter for you for a specified did, for more advanced usage, use --query",
					(value) =>
					{
						if (string.IsNullOrWhiteSpace(value))
							throw new OptionException ($"No argument provided!", "-q");

						searchQuery = $"sip.to.addr contains {value} || sip.from.addr contains {value}";
					}
				},
				{
					"q|query=",
					"a wireshark compatible search filter to locate the SIP packets, use this or --did they replace each other",
					(value) => {

						if (string.IsNullOrWhiteSpace(value))
							throw new OptionException ($"No argument provided!", "-q");

						searchQuery = value;
					}
				},
				{
					"h|help",
					"shows this help message",
					(value) =>
					{
						showHelp = true;
					}
				}
			};

			try
			{
				List<string> extraArgs = p.Parse(args);

				foreach (string value in extraArgs)
				{
					if (string.IsNullOrWhiteSpace(value))
						continue;

					if (!File.Exists(value))
						throw new OptionException($"pcap file \"{value}\" doesn't exist!", "-i");

					FileAttributes attr = File.GetAttributes(value);
					if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
						throw new OptionException($"\"{value}\" is a directory and not a file!", "-i");

					inputFiles.Add(value);
				}
			}
			catch (OptionException e)
			{
				Console.Write("CallExtract: ");
				Console.WriteLine(e.Message);
				Console.WriteLine("Try `CallExtract --help' for more information.");
				return;
			}

			if (showHelp || args.Length == 0)
			{
				p.WriteOptionDescriptions(Console.Out);
				return;
			}

			CallExtract.NET.CallExtract.Perform(searchQuery, inputFiles, outputFile);
			

		}
	}
}
