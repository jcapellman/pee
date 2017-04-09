using System.IO;
using System.Linq;
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

        public void Analyze()
        {
            var text = File.ReadAllText(_fileName, Encoding.ASCII);
            var matches = Regex.Matches(text, @"([a-zA-Z])");

            foreach (var match in matches)
            {
                _str += $"{match}{System.Environment.NewLine}";
            }
        }

        public override string ToString()
        {
            return _str;
        }
    }
}
