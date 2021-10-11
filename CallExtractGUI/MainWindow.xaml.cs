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

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace CallExtractGUI
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		public MainWindow()
		{
			InitializeComponent();
		}

		private void button_Click(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();

			dlg.DefaultExt = ".pcap";
			dlg.Filter = "PCAP Files (*.pcap)|*.pcap|PCAPNG Files (*.pcapng)|*.pcapng";
			dlg.Multiselect = true;
			dlg.Title = "Select the PCAP files.";

			bool? result = dlg.ShowDialog();

			if (result == false)
				return;

			string[] inputPcapFiles = dlg.FileNames;
			if (inputPcapFiles.Length == 0)
				return;

			SaveFileDialog filteredFile = new SaveFileDialog();

			filteredFile.Filter = "PCAP Files (*.pcap)|*.pcap";
			filteredFile.FilterIndex = 1;
			filteredFile.Title = "Where should we save the filtered packets?";

			bool? saveResult = filteredFile.ShowDialog();

			if (null == saveResult || saveResult.Value == false)
				return;

			string outputFile = filteredFile.FileName;

			string did = didTextBox.Text;

			CallExtract.NET.CallExtract.Perform($"sip.to.addr contains {did} || sip.from.addr contains {did}", inputPcapFiles, outputFile);

			MessageBox.Show("Done");
		}

		private void textBox_TextChanged(object sender, TextChangedEventArgs e)
		{

		}
	}
}
