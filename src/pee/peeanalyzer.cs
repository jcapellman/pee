using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Text;
using System.Text.RegularExpressions;

namespace pee
{
    public class PeeAnalyzer
    {
        private readonly string _fileName;

        private string _str;    

        public PeeAnalyzer(string fileName)
        {
            _fileName = fileName;
        }

        private bool isPE()
        {
            using (var fs = File.Open(_fileName, FileMode.Open))
            {
                using (var reader = new BinaryReader(fs))
                {
                    var peHeader = reader.ReadBytes(2);

                    // PE Header is less than the minimum
                    if (peHeader.Length < 2)
                    {
                        return false;
                    }

                    // Check the first two bytes to rule out anything not DLL, EXE, SYS etc
                    if (peHeader[0] != (byte)'M' && peHeader[1] != (byte)'Z')
                    {
                        return false;
                    }
                    
                    fs.Seek(64 - 4, SeekOrigin.Begin);

                    var offset = reader.ReadInt32();
                    fs.Seek(offset, SeekOrigin.Begin);
                    peHeader = reader.ReadBytes(2);

                    // Ensure PE is properly in the header
                    if (peHeader[0] != (byte)'P' && peHeader[1] != (byte)'E')
                    {
                        return false;
                    }

                    fs.Seek(20, SeekOrigin.Current);

                    // Verify if the header indicates if its a DLL or not
                    return (reader.ReadInt16() & 0x2000) != 0x2000;
                }
            }
        }

        public bool Analyze()
        {
            if (!isPE())
            {
                Console.WriteLine($"{_fileName} is not a PE");

                return false;
            }

            var text = File.ReadAllText(_fileName, Encoding.ASCII);
            var matches = Regex.Matches(text, @"\w{2,}");

            foreach (var match in matches)
            {
                _str += $"{match}{System.Environment.NewLine}";
            }

            return true;
        }

        public override string ToString()
        {
            return _str;
        }
    }
}
