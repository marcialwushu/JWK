using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Org.BouncyCastle.OpenSsl;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Web.Http.Results;
using System.Web.Mvc;
using JWK.Models;

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

        // GET api/values
        public IHttpActionResult Get()
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

            var json = JsonConvert.SerializeObject(jsonWebKeySet);

            JsonJWK jsonJWK = new JsonJWK()
            {
                Kid = Base64UrlEncoder.Encode(hashBytes),
                Kty = "RSA",
                E = e,
                N = n
            };

            return Json(new { Kid = jsonJWK.Kid, Kty = jsonJWK.Kty, E = jsonJWK.E , N = jsonJWK.N });
            
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
