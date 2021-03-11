using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace com.Akamai.EdgeAuth
{
    /// <summary>
    /// Class for setting different configuration properties for generating a token
    /// </summary>
    public class AkamaiTokenConfig
    {
        private static Regex _keyRegex = new Regex("^[a-zA-Z0-9]+$", RegexOptions.Compiled);

        public AkamaiTokenConfig()
        {
            TokenAlgorithm = Algorithm.HMACSHA256;
            IP = string.Empty;
            SessionID = string.Empty;
            Payload = string.Empty;
            Salt = string.Empty;
            FieldDelimiter = '~';
        }

        /// <summary>
        /// Gets/sets a flag that indicates whether the Acl/Url property will be escaped before being hashed. The default behavior is to escape the value.
        /// </summary>
        /// <remarks>This flag supports the new feature in GHost 6.5 wherein the EdgeAuth 2.0 token is 
        /// validated directly against the input from query/cookie without first escaping it.</remarks>
        public bool PreEscapeAcl { get; set; }

        /// <summary>
        /// Gets/sets the algorigthm to use for creating the hmac. Default value uses SHA256 based HMAC
        /// </summary>
        public Algorithm TokenAlgorithm { get; set; }

        /// <summary>
        /// Gets/sets the IP for which this token is valid
        /// </summary>
        public string IP { get; set; }

        public string IPField
        {
            get
            {
                if (string.IsNullOrEmpty(IP))
                    return string.Empty;
                else
                    return string.Format("ip={0}{1}", IP, FieldDelimiter);
            }
        }

        private long _startTime;

        /// <summary>
        /// Gets/sets the epoch time, i.e. seconds since 1/1/1970, from which the token is valid. Default value is current time
        /// </summary>
        public long StartTime
        {
            get { return _startTime == 0 ? (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds : _startTime; }
            set { _startTime = value; }
        }

        public string StartTimeField
        {
            get { return _startTime == 0 ? "" : string.Format("st={0}{1}", StartTime, FieldDelimiter); }
        }

        /// <summary>
        /// Gets/sets the epoch time, i.e. seconds since 1/1/1970, till which the token is valid.
        /// </summary>
        private long _endTime;
        public long EndTime
        {
            get { return _endTime; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException("EndTime", "Value should be greater than 0");

                _endTime = value;
            }
        }

        /// <summary>
        /// Gets/sets the duration in seconds for which this token is valid. A value of EndTime
        /// </summary>
        private long _window;
        public long Window
        {
            get { return _window; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException("Window", "Value should be greater than 0");

                _window = value;
            }
        }

        public string ExpirationField
        {
            get
            {
                if (Window == 0 && EndTime == 0)
                {
                    throw new Exception("A valid value for either 'Window' or 'EndTime' is required");
                }
                if (EndTime > 0 && EndTime <= StartTime)
                {
                    throw new Exception("Value of 'EndTime' should be greater than 'StartTime'");
                }

                return EndTime == 0
                    ? string.Format("exp={0}{1}", (StartTime + Window), FieldDelimiter)
                    : string.Format("exp={0}{1}", EndTime, FieldDelimiter);

            }
        }

        /// <summary>
        /// The access control list for which the token is valid. Example: /*
        /// </summary>
        public string Acl { get; set; }

        /// <summary>
        /// The specific URL for which the token is valid. Example: /crossdomain.xml
        /// </summary>
        public string Url { get; set; }

        public string AclField
        {
            get
            {
                ValidateUrlOrAcl();

                return string.IsNullOrEmpty(Acl)
                    ? string.Empty
                    : (PreEscapeAcl
                        ? string.Format("acl={0}{1}", Uri.EscapeDataString(Acl).Replace(",", "%2c").Replace("*", "%2a"), FieldDelimiter)
                        : string.Format("acl={0}{1}", Acl, FieldDelimiter));
            }
        }

        public string UrlField
        {
            get
            {
                ValidateUrlOrAcl();

                return string.IsNullOrEmpty(Url)
                    ? string.Empty
                    : (PreEscapeAcl
                        ? string.Format("url={0}{1}", Uri.EscapeDataString(Url), FieldDelimiter)
                        : string.Format("url={0}{1}", Url, FieldDelimiter));
            }
        }

        /// <summary>
        /// The session identifier for single use tokens or other advanced cases
        /// </summary>
        public string SessionID { get; set; }
        
        public string SessionIDField
        {
            get { return string.IsNullOrEmpty(SessionID) ? string.Empty : string.Format("id={0}{1}", SessionID, FieldDelimiter); }
        }
        
        /// <summary>
        /// Additional text added to the calculated token digest
        /// </summary>
        public string Payload { get; set; }

        public string PayloadField
        {
            get { return string.IsNullOrEmpty(Payload) ? string.Empty : string.Format("data={0}{1}", Payload, FieldDelimiter); }
        }

        /// <summary>
        /// Additional data validated by the token but NOT included in the token body
        /// </summary>
        public string Salt { get; set; }

        public string SaltField
        {
            get { return string.IsNullOrEmpty(Salt) ? string.Empty : string.Format("salt={0}{1}", Salt, FieldDelimiter); }
        }

        /// <summary>
        /// Secret required to generate the token
        /// </summary>
        private string _key;
        public string Key
        {
            get { return _key; }
            set
            {
                if (string.IsNullOrEmpty(value) || ((value.Length & 1) == 1) || !_keyRegex.IsMatch(value))
                    throw new ArgumentException("Key should be an even length alpha-numeric string", "Key");

                _key = value;
            }
        }

        /// <summary>
        /// Character used to delimit token body fields.
        /// </summary>
        public char FieldDelimiter { get; set; }

        private void ValidateUrlOrAcl()
        {
            if (string.IsNullOrEmpty(Acl) && string.IsNullOrEmpty(Url))
            {
                throw new Exception("A valid value for either 'Url' or 'Acl' is required");
            }
            if (string.IsNullOrEmpty(Acl) == false && string.IsNullOrEmpty(Url) == false)
            {
                throw new Exception("Either the 'Url' or 'Acl' value can be specified");
            }
        }

        public override string ToString()
        {
            return string.Format(@"Config:{0}\t"
                + "Algo:{1}{0}"
                + "IPField:{2}{0}"
                + "StartTimeField:{2}{0}"
                + "Window:{2}{0}"
                + "ExpirationField:{2}{0}"
                + "AclField:{2}{0}"
                + "UrlField:{2}{0}"
                + "SessionIDField:{2}{0}"
                + "PayloadField:{2}{0}"
                + "SaltField:{2}{0}"
                + "Key:{2}{0}"
                + "FieldDelimier:{2}{0}",
                Environment.NewLine,
                TokenAlgorithm,
                IPField,
                StartTimeField,
                Window,
                ExpirationField,
                AclField,
                UrlField,
                SessionIDField,
                PayloadField,
                SaltField,
                FieldDelimiter);
        }
    }
}
