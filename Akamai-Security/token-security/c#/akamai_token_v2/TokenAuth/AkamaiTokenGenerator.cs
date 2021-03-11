using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace com.Akamai.EdgeAuth
{
    /// <summary>
    /// Token generator
    /// </summary>
    public class AkamaiTokenGenerator
    {
        /// <summary>
        /// Generates a token and appends to the given url using the specified token name.
        /// </summary>
        /// <param name="url">Url to which token is to be appended as query string</param>
        /// <param name="tokenName">Name of token used as query string for the Url</param>
        /// <param name="tokenConfig">Configuration values to create token</param>
        /// <returns></returns>
        public static string GenerateToken(string url, string tokenName, AkamaiTokenConfig tokenConfig)
        {
            string token = GenerateToken(tokenConfig);
            if (url.IndexOf("?") > 0)
            {
                return string.Format("{0}&{1}={2}", url, tokenName, token);
            }
            else
            {
                return string.Format("{0}?{1}={2}", url, tokenName, token);
            }
        }

        /// <summary>
        /// Generates a token using the specified token name to be used as HTTP query strings
        /// </summary>
        /// <param name="tokenName">Name of token</param>
        /// <param name="tokenConfig">Configuration values to create token</param>
        /// <returns></returns>
        public static string GenerateToken(string tokenName, AkamaiTokenConfig tokenConfig)
        {
            return string.Format("{0}={1}", tokenName, GenerateToken(tokenConfig));
        }

        /// <summary>
        /// Generates a token
        /// </summary>
        /// <param name="tokenConfig">Configuration values to create token</param>
        /// <returns></returns>
        public static string GenerateToken(AkamaiTokenConfig tokenConfig)
        {
            string mToken = tokenConfig.IPField + tokenConfig.StartTimeField
                + tokenConfig.ExpirationField + tokenConfig.AclField
                + tokenConfig.SessionIDField + tokenConfig.PayloadField;

            string digest = mToken + tokenConfig.UrlField + tokenConfig.SaltField;

            // calculate hmac
            string hmac = CalculateHMAC(digest.TrimEnd(tokenConfig.FieldDelimiter), tokenConfig.Key, tokenConfig.TokenAlgorithm);

            return tokenConfig.PreEscapeAcl
                ? string.Format("{0}hmac={1}", mToken, hmac)
                : Uri.EscapeUriString(string.Format("{0}hmac={1}", mToken, hmac));
        }
        private static string CalculateHMAC(string data, string key, Algorithm algorithm)
        {
            StringBuilder sb = new StringBuilder();
            try
            {  
                HMAC hmac = HMAC.Create(algorithm.ToString());
                hmac.Key = Util.ToByteArray(key);

                // compute hmac
                byte[] rawHmac = hmac.ComputeHash(Encoding.ASCII.GetBytes(data));

                // convert to hex string
                foreach (var b in rawHmac)
                {
                    sb.AppendFormat("{0:x2}", b);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create token", ex);
            }

            return sb.ToString();
        }
    }
}