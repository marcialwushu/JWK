using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JWK.Models
{
    public class JsonJWK
    {
        public string Kid { get; set; }
        public string Kty { get; set; }
        public string E { get; set; }
        public string N { get; set; }
    }
}