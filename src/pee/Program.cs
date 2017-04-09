using System;
using System.IO;

namespace pee
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("No filename given, exiting");
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine($"File {args[0]} does not exist");
                return;
            }

            var analyzer = new PeeAnalyzer(args[0]);

            analyzer.Analyze();

            Console.WriteLine($"Analysis: {analyzer}");
        }
    }
}