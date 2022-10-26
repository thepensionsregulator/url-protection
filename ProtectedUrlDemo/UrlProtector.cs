using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace ProtectedUrlDemo
{
    /// <summary>
    /// Protect URL from being tampered with by including a hash of the original value
    /// </summary>
    public class UrlProtector : IUrlProtector
    {
        /// <inheritdoc />
        public string HashParameter { get; set; } = "h";

        /// <inheritdoc />
        public Uri ProtectPathAndQuery(Uri urlToProtect, string salt)
        {
            if (urlToProtect == null) { throw new ArgumentNullException(nameof(urlToProtect)); }
            if (!urlToProtect.IsAbsoluteUri) { throw new ArgumentException($"{nameof(urlToProtect)} must be an absolute URI", nameof(urlToProtect)); }
            if (string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentException($"'{nameof(salt)}' cannot be null or whitespace.", nameof(salt));
            }

            // Build up current URL as a string ready to have extra query string parameters added
            var query = HttpUtility.ParseQueryString(urlToProtect.Query);

            // Hash the URI and add it as a parameter
            query.Add(HashParameter, CreateUrlHash(urlToProtect.AbsolutePath + urlToProtect.Query?.TrimStart('?'), salt));
            return new Uri(urlToProtect.Scheme + "://" + urlToProtect.Authority + urlToProtect.AbsolutePath + "?" + query, UriKind.Absolute);
        }


        /// <inheritdoc />
        public bool CheckProtectedPathAndQuery(Uri protectedUrl, string salt)
        {
            if (protectedUrl == null) { throw new ArgumentNullException(nameof(protectedUrl)); }
            if (!protectedUrl.IsAbsoluteUri) throw new ArgumentException($"{nameof(protectedUrl)} must be an absolute URL", nameof(protectedUrl));
            if (string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentException($"'{nameof(salt)}' cannot be null or whitespace.", nameof(salt));
            }

            // Get the querystring in a usable form
            var queryString = HttpUtility.ParseQueryString(protectedUrl.Query);

            // Check we got a hash, otherwise we know straight away it's not valid
            if (string.IsNullOrEmpty(queryString[HashParameter])) { return false; }

            // Make a new querystring without the protection parameter. This should be the original protected querystring.
            var protectedQueryString = new StringBuilder();
            foreach (string name in queryString.Keys)
            {
                if (name == HashParameter) { continue; }
                if (protectedQueryString.Length > 0) { protectedQueryString.Append("&"); }
                protectedQueryString.Append(name).Append("=").Append(queryString[name]);
            }

            // Determine what the hash SHOULD be
            var expectedHash = CreateUrlHash(protectedUrl.AbsolutePath + protectedQueryString.ToString().TrimStart('?'), salt);

            // Check that against what we actually got
            var receivedHash = queryString[HashParameter];
            if (string.IsNullOrEmpty(receivedHash))
            {
                // No hash, so not valid
                return false;
            }

            // Now, see if the received and expected hashes match up
            return expectedHash == receivedHash;
        }

        /// <summary>
        /// Creates the hash used to protect a URL.
        /// </summary>
        /// <param name="hashThis">The URL to hash.</param>
        /// <param name="salt">The salt.</param>
        /// <returns></returns>
        private static string CreateUrlHash(string hashThis, string salt)
        {
            hashThis = salt + hashThis;

            var encoder = new UTF8Encoding();
            using (var algorithm = SHA256.Create())
            {
                var hashedBytes = algorithm.ComputeHash(encoder.GetBytes(hashThis));

                // Base-64 encode the results and strip out any characters that might get URL encoded and cause hash not to match
                return Regex.Replace(Convert.ToBase64String(hashedBytes), "[^A-Za-z0-9]", string.Empty);
            }
        }
    }
}
