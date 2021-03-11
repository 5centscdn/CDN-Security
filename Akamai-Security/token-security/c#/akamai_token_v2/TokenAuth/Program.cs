using System;
using System.Collections.Generic;
using System.Text;

namespace com.Akamai.EdgeAuth
{
    class Program
    {
        const string VERSION = "2.0.7";
        const string PRODUCT = "Akamai Token Auth Generator - C#";

        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                DisplayHelp();
                return 1;
            }
            try
            {
                Dictionary<string, string> options = ReadOptions(args);
                AkamaiTokenConfig config = new AkamaiTokenConfig();

                if (options.ContainsKey("escape_early")) config.PreEscapeAcl = bool.Parse(options["escape_early"]);
                if (options.ContainsKey("ip")) config.IP = options["ip"];
                if (options.ContainsKey("start_time")) config.StartTime = long.Parse(options["start_time"]);
                if (options.ContainsKey("end_time")) config.EndTime = long.Parse(options["end_time"]);
                if (options.ContainsKey("window")) config.Window = long.Parse(options["window"]);
                if (options.ContainsKey("url")) config.Url = options["url"];
                if (options.ContainsKey("acl")) config.Acl = options["acl"];
                if (options.ContainsKey("key")) config.Key = options["key"];
                if (options.ContainsKey("payload")) config.Payload = options["payload"];
                if (options.ContainsKey("algorithm")) config.TokenAlgorithm = (Algorithm)Enum.Parse(typeof(Algorithm), options["algorithm"]);
                if (options.ContainsKey("salt")) config.Salt = options["salt"];
                if (options.ContainsKey("session_id")) config.SessionID = options["session_id"];
                if (options.ContainsKey("field_delimiter")) config.FieldDelimiter = char.Parse(options["field_delimiter"]);

                string tokenName;
                if (!options.TryGetValue("token_name", out tokenName)) tokenName = "hdnts";

                Console.WriteLine(AkamaiTokenGenerator.GenerateToken(tokenName, config));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error parsing command line options. {0}", ex.Message);
            }
            return 0;
        }

        private static Dictionary<string, string> ReadOptions(string[] args)
        {
            Dictionary<string, string> options = new Dictionary<string, string>();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--version")
                {
                    DisplayVersion();
                    Environment.Exit(0);
                }
                else if (args[i] == "-h" || args[i].StartsWith("--help"))
                {
                    DisplayHelp();
                    Environment.Exit(0);
                }
                else if (args[i] == "-n" || args[i].StartsWith("--token_name"))
                {
                    options.Add("token_name", ReadArgValue(args, i));
                }
                else if (args[i] == "-i" || args[i].StartsWith("--ip"))
                {
                    options.Add("ip", ReadArgValue(args, i));
                }
                else if (args[i] == "-s" || args[i].StartsWith("--start_time"))
                {
                    options.Add("start_time", ReadArgValue(args, i));
                }
                else if (args[i] == "-e" || args[i].StartsWith("--end_time"))
                {
                    options.Add("end_time", ReadArgValue(args, i));
                }
                else if (args[i] == "-w" || args[i].StartsWith("--window"))
                {
                    options.Add("window", ReadArgValue(args, i));
                }
                else if (args[i] == "-u" || args[i].StartsWith("--url"))
                {
                    options.Add("url", ReadArgValue(args, i));
                }
                else if (args[i] == "-a" || args[i].StartsWith("--acl"))
                {
                    options.Add("acl", ReadArgValue(args, i));
                }
                else if (args[i] == "-k" || args[i].StartsWith("--key"))
                {
                    options.Add("key", ReadArgValue(args, i));
                }
                else if (args[i] == "-p" || args[i].StartsWith("--payload"))
                {
                    options.Add("payload", ReadArgValue(args, i));
                }
                else if (args[i] == "-A" || args[i].StartsWith("--algo"))
                {
                    options.Add("algorithm", ReadArgValue(args, i));
                }
                else if (args[i] == "-S" || args[i].StartsWith("--salt"))
                {
                    options.Add("salt", ReadArgValue(args, i));
                }
                else if (args[i] == "-I" || args[i].StartsWith("--session_id"))
                {
                    options.Add("session_id", ReadArgValue(args, i));
                }
                else if (args[i] == "-d" || args[i].StartsWith("--field_delimiter"))
                {
                    options.Add("field_delimiter", ReadArgValue(args, i));
                }
                else if (args[i] == "-x" || args[i].StartsWith("escape_early"))
                {
                    options.Add("escape_early", bool.TrueString);
                }
            }
            return options;
        }

        private static string ReadArgValue(string[] args, int i)
        {
            if (args[i].StartsWith("--"))
                return args[i].Split(new string[] {"="}, StringSplitOptions.None)[1];
            return args[++i];
        }

        private static void DisplayVersion()
        {
            Console.WriteLine("{0}{1}{2}", PRODUCT, Environment.NewLine, VERSION);
        }

        private static void DisplayHelp()
        {
            Console.WriteLine(@"
Usage: TokenAuth.exe [options]
    
Options:
    --version
            Show program's version number and exit
    -h, --help
            Show this help message and exit
    -n TOKEN_NAME, --token_name=TOKEN_NAME
            Parameter name for the new token. Default value is hdnts
    -i IP_ADDRESS, --ip=IP_ADDRESS
            IP address to restrict this token to
    -s START_TIME, --start_time=START_TIME
            What is the start time from which token will be valid
    -e END_TIME, --end_time=END_TIME
            What is the end time till which token will be valid
    -w WINDOW_SECONDS, --window=WINDOW_SECONDS
            How long is this token valid for. End Time overrides this value.
    -u URL, --url=URL
            Url path
    -a ACCESS_LIST, --acl=ACCESS_LIST
            Access control list
    -k KEY, --key=KEY
            Secret required to generate the tokens
    -p PAYLOAD, --payload=PAYLOAD
            Additional text added to the calculated token digest
    -A ALGORITHM, --algo=ALGORITHM
            Algorithm to use to generate the token. (HMACSHA1, HMACSHA256, HMACMD5) Default value is sha256.
    -S SALT, --salt=SALT
            Additional data validated by the token but NOT included in the token body
    -I SESSION_ID, --session_id=SESSION_ID
            The session identifier for single use tokens or other advanced cases
    -d FIELD_DELIMITER, --field_delimiter=FIELD_DELIMITER
            Character used to delimit token body fields. Default value is ~
    -x, --escape_early
            Causes strings to be url encoded before being used (legacy 2.0 behavior).
            ");
        }
    }
}
