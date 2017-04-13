using System;
using System.IO;

namespace pee
{
    class Program
    {
        static void Main(string[] args)
        {   
            if (args[0] == "d")
            {
                var files = Directory.GetFiles(args[1]);

                var numpes = 0;

                foreach (var file in files)
                {
                    var fa = new peecheck();

                    if (fa.IsPE(file))
                    {
                        numpes++;
                    }
                }

                Console.WriteLine($"{numpes} out of {files.Length}");
            }
            else
            {
                if (!File.Exists(args[1]))
                {
                    Console.WriteLine($"File {args[1]} does not exist");
                    return;
                }

                var analyzer = new PeeAnalyzer(args[1]);

                analyzer.Analyze();

                Console.WriteLine($"Analysis: {analyzer}");
            }
        }
    }
}