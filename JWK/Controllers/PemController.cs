using JWK.Models;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;

namespace JWK.Controllers
{
    public class PemController : ApiController
    {
        private const string CertPem = @"-----BEGIN CERTIFICATE-----
                                            MIIB3zCCAYWgAwIBAgIUImttQCULqkHxYbDivb1fzRNFYG8wCgYIKoZIzj0EAwIw
                                            RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
                                            dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDA5MTgxNDQyMzlaFw0yMTA5MTMx
                                            NDQyMzlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
                                            VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
                                            PQMBBwNCAARwfxEb6RX+fwiz70spEdLTfK/ite5ZGfysbalM/ZlnUjWZ+Cwk+aEc
                                            KkER2GWoZ6Fiw3PcOlQzY8dGHMdkkHhGo1MwUTAdBgNVHQ4EFgQUOYFYa+w94G7t
                                            MGD3bpM3T04WAxswHwYDVR0jBBgwFoAUOYFYa+w94G7tMGD3bpM3T04WAxswDwYD
                                            VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAxX7N6e+2NfuwR70u3AX0
                                            mx5ZP9uQhdrvOi8qDBHSMMoCIEQenUMtTfYfOU8FwT3WZO4S5JB5jvPg9hCnlXPj
                                            NwaC
                                            -----END CERTIFICATE-----";

        private const string EccPem = @"-----BEGIN EC PRIVATE KEY-----
                                            MHcCAQEEIP7n5rwD8HN7VUqcyYD5p+5jBNZQGkQEzoZ76tjXd2TmoAoGCCqGSM49
                                            AwEHoUQDQgAEcH8RG+kV/n8Is+9LKRHS03yv4rXuWRn8rG2pTP2ZZ1I1mfgsJPmh
                                            HCpBEdhlqGehYsNz3DpUM2PHRhzHZJB4Rg==
                                            -----END EC PRIVATE KEY-----";

        private static readonly RsaSecurityKey key = new RsaSecurityKey(RSA.Create("2048"));

        // GET api/values
        public IHttpActionResult Get()
        {
            Chilkat.Pfx pfx = new Chilkat.Pfx();

            bool success = pfx.LoadPfxFile("qa_data/pfx/myEccCert.p12", "MY_ECC_PFX_PASSWORD");
            if (success != true)
            {
                Console.WriteLine(pfx.LastErrorText);
            }

            // To get the contents of the PFX in JWK Set form, we must first convert
            //  to a Java KeyStore object:
            //  The alias will become the key id ("kid") the the JWK Set.
            //  The password is an input argument that becomes the password for the JavaKeyStore.
            string alias = "my_ecc_key";
            string password = "secret123";
            Chilkat.JavaKeyStore jks = pfx.ToJavaKeyStore(alias, password);
            if (pfx.LastMethodSuccess != true)
            {
                Console.WriteLine(pfx.LastErrorText);
            }

            Chilkat.StringBuilder sbJwkSet = new Chilkat.StringBuilder();
            //  The ToJwkSet method writes to sbJwkSet.
            success = jks.ToJwkSet(password, sbJwkSet);
            if (success != true)
            {
                Console.WriteLine(jks.LastErrorText);
            }

            Chilkat.JsonObject jwkSet = new Chilkat.JsonObject();
            jwkSet.LoadSb(sbJwkSet);
            jwkSet.EmitCompact = false;

            return Json(new { x5c = jwkSet.Emit()  });
            
        }
    }
}