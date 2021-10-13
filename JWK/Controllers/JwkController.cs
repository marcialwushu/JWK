using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Org.BouncyCastle.OpenSsl;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Newtonsoft.Json;
using JWK.Models;
using System.Text;
using IdentityServer3.Core.Configuration;

namespace JWK.Controllers
{
    public class JwkController : ApiController
    {

        private const string PUBLIC_KEY = @"-----BEGIN PUBLIC KEY-----
                                    MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB5uVaCLL+DmPblCSJas1iC
                                    MqY2XI4yZ3w5mj9gcXG9RqjWiZ8hSv+In1pUl4MSVoykd/Sd3khd6kKLt5GI40Ix
                                    rs1f/DZBYdUYgNhc1pJU3AiOFx/xFmVFACwJM+fVkuJ/hXrHDsWK3AQdCcvrIBjs
                                    RstK5ZzJOHW6doMsawle1EGbhxazBglVwE6zgyMAeGehZHzekj9bliEB4Pxn4Eir
                                    VAPN6bbZ0CYygUQiKCV/L6lMR6IMtqG165rj32bOFdm3H8p/XUA5Rzn1HJe6T8JU
                                    gEJRVIMrYegHclOmxS/LhhJZ7uXuDjex6NlciBlbwWXO6RBDyupwYuY7m8DWqML3
                                    AgMBAAE=
                                    -----END PUBLIC KEY-----";
        //private object cert;
        //// Header Parameter Names
        //private const string AlgorithmHeader = "alg";
        // private const string X509ThumbprintHeader = "x5t";
        // private const string TypeHeader = "typ";
        //private const string x509ThumbprintHeader = X509ThumbprintHeader;
        //X509Certificate2 certificate;
        //private JsonObject headers;
        private readonly IdentityServerOptions options;
        private readonly string JWK_URL;


        // GET api/values
        public HttpResponseMessage Get()
        {

            var textReader = new StringReader(PUBLIC_KEY);
            var pubkeyReader = new PemReader(textReader);
            RsaKeyParameters KeyParameters = (RsaKeyParameters)pubkeyReader.ReadObject();
            var e = Base64UrlEncoder.Encode(KeyParameters.Exponent.ToByteArrayUnsigned());
            var n = Base64UrlEncoder.Encode(KeyParameters.Modulus.ToByteArrayUnsigned());
            var dict = new Dictionary<string, string>() {
                    {"e", e},
                    {"kty", "RSA"},
                    {"n", n}
                };
            var hash = SHA256.Create();
            Byte[] hashBytes = hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(dict)));
            JsonWebKey jsonWebKey = new JsonWebKey()
            {
                Kid = Base64UrlEncoder.Encode(hashBytes),
                Kty = "RSA",
                E = e,
                N = n
            };
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
            jsonWebKeySet.Keys.Add(jsonWebKey);
            _ = JsonConvert.SerializeObject(jsonWebKeySet);

            JsonJWK jsonJWK = new JsonJWK()
            {
                Kid = Base64UrlEncoder.Encode(hashBytes),
                Kty = "RSA",
                E = e,
                N = n
            };

            // Create the response
            var response = Request.CreateResponse(HttpStatusCode.OK, jsonJWK);

            // Add the "x5t" thumbprint header when signing using an X.509 certificate as defined by http://self-issued.info/docs/draft-jones-json-web-encryption.html
            //this.GetHeaders()[x509ThumbprintHeader] = EncodeBase64UrlWithNoPadding(StringToByteArray(certificate.Thumbprint));
            //response.Headers.Add("x5t", (IEnumerable<string>)headers);



            //var webKeys = new List<JsonJWK>();
            //var pubKey = options.PublicKeysForMetadata;
            //var cert64 = Convert.ToBase64String(textReader.RawData);
            //var thumbprint = Encoding.UTF8.GetString(pubKey.GetCertHash());

            // Set headers for paging
            response.Headers.Add("alg", "RSA");            
            response.Headers.Add("jku", JWK_URL);
            response.Headers.Add("kid", jsonJWK.Kid);

            return response;



             //return Json(new { Kid = jsonJWK.Kid, Kty = jsonJWK.Kty, E = jsonJWK.E , N = jsonJWK.N });

        }


        /// <summary>
        /// Encodes the specified bytes as a base64url string (as defined in RFC4648), with no padding characters ('=').
        /// </summary>
        /// <param name="arg">The bytes to encode as a base64url string with no padding.</param>
        /// <returns>Returns the encoded base64url string, with no padding.</returns>
        private static string EncodeBase64UrlWithNoPadding(byte[] arg)
        {
            // The base64url encoding is a variation of base64 encoding, described at:
            // http://en.wikipedia.org/wiki/Base64#Variants_summary_table
            string s = Convert.ToBase64String(arg); // standard base64 encoder
            s = s.TrimEnd('='); // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        /// <summary>
        /// Converts a string-encoded hex value (e.g. an X.509 Certificate thumbprint) into a byte array.
        /// </summary>
        /// <param name="str">The string to be converted to a byte array.</param>
        /// <returns>Return the byte array corresponding to the input string.</returns>
        private static byte[] StringToByteArray(string str)
        {
            //Fx.Assert(str.Length % 2 == 0, "Only even length-strings are expected.");
            byte[] bytes = new byte[str.Length / 2];
            for (int i = 0; i<str.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(str.Substring(i, 2), 16);
            }

            return bytes;
        }


        /// <summary>
        /// Decodes the specified base64url string (as defined in RFC4648) that has no padding characters ('=').
        /// </summary>
        /// <param name="arg">The base64url string that has no padding.</param>
        /// <returns>Returns the bytes decoded from the base64url string with no padding.</returns>
        private static byte[] DecodeBase64UrlWithNoPadding(string arg)
        {
            // The base64url encoding is a variation of base64 encoding, described at:
            // http://en.wikipedia.org/wiki/Base64#Variants_summary_table
            arg = arg.Replace('-', '+'); // 62nd char of encoding
            arg = arg.Replace('_', '/'); // 63rd char of encoding
            // Pad with trailing '='s
            switch (arg.Length % 4)
            {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    arg += "==";
                    break; // Two pad chars
                case 3:
                    arg += "=";
                    break; // One pad char
                default:
                    break;
            }

            return Convert.FromBase64String(arg); // standard base64 decoder
        }




        /// <summary>
        /// Verify the signature of the JSON web token given a certificate
        /// </summary>
        /// <param name="certificate">The X.509 certificate used by the cryptographic algorithm to validate the signature.</param>
        public void VerifySignature(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            //byte[] data = Encoding.UTF8.GetBytes(string.Concat(this.headerSegment, ".", this.claimSegment));
            //byte[] signature = DecodeBase64UrlWithNoPadding(this.signature);

            //RSACryptoServiceProvider rsa = certificate.PublicKey.Key as RSACryptoServiceProvider;
            
            //// Prepare the hash algorithm to use with the RSACryptoServiceProvider.
            //string hashAlgorithm = JsonWebTokenAlgorithms.GetHashAlgorithmForRsa(this.Algorithm);
            

            // Verify the signature.
            //if (!rsa.VerifyData(data, hashAlgorithm, signature))
            //    {
            //        return;
            //    }
        }




// GET api/values/5
        public string Get(int id)
        {
            
            
            
            return "value";
        }

        // POST api/values
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        public void Delete(int id)
        {

            
        }



    }
}
