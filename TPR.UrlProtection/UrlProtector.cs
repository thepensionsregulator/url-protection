using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace TPR.UrlProtection
{
    /// <summary>
    /// Protect URL from being tampered with by including a hash of the original value
    /// </summary>
    public class UrlProtector : IUrlProtector
    {
        /// <inheritdoc />
        public string HashParameter { get; set; } = "h";
        /// <inheritdoc />
        public ParameterLocation ParameterLocation { get; set; } = ParameterLocation.Query;
        /// <inheritdoc />
        public string? PathTemplate { get; set; }

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
            var query = HttpUtility.ParseQueryString(urlToProtect.Query ?? string.Empty);

            // Hash the URI and add it as a parameter
            query.Add(HashParameter, CreateUrlHash(urlToProtect.AbsolutePath + query, salt));
            var urlWithProtection = new Uri(urlToProtect.Scheme + "://" + urlToProtect.Authority + urlToProtect.AbsolutePath + "?" + query, UriKind.Absolute);

            if (ParameterLocation == ParameterLocation.Query)
            {
                return urlWithProtection;
            }
            else
            {
                return PlaceProtectedUrlInPath(urlWithProtection);
            }
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

            if (ParameterLocation == ParameterLocation.Path)
            {
                var extractedUrl = ExtractProtectedUrlFromPath(protectedUrl);
                if (extractedUrl == null) { return false; }
                protectedUrl = extractedUrl;
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
                protectedQueryString.Append(name).Append("=").Append(HttpUtility.UrlEncode(queryString[name]));
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

        /// <inheritdoc />
        public Uri? ExtractProtectedUrlFromPath(Uri protectedUrl)
        {
            if (ParameterLocation == ParameterLocation.Query) { return protectedUrl; }

            if (string.IsNullOrEmpty(PathTemplate)) { throw new InvalidOperationException($"{nameof(PathTemplate)} cannot be null or empty when {nameof(ParameterLocation)} is set to {nameof(ParameterLocation.Path)}"); }

            var match = Regex.Match(protectedUrl.AbsolutePath, string.Format(PathTemplate, "([A-Za-z0-9=/]+)"));
            if (!match.Success || match.Groups.Count <= 1)
            {
                return null;
            }

            if (TryUnobfuscateString(match.Groups[1].Value, out var unobfuscated))
            {
                return new Uri(protectedUrl.Scheme + "://" + protectedUrl.Authority + unobfuscated, UriKind.Absolute);
            }
            else
            {
                return null;
            }
        }

        /// <inheritdoc />
        public Uri PlaceProtectedUrlInPath(Uri urlToProtect)
        {
            if (string.IsNullOrEmpty(PathTemplate)) { throw new InvalidOperationException($"{nameof(PathTemplate)} cannot be null or empty when {nameof(ParameterLocation)} is set to {nameof(ParameterLocation.Path)}"); }

            var obfuscatedOriginalPath = ObfuscateString(urlToProtect.AbsolutePath + urlToProtect.Query);
            return new Uri(urlToProtect.Scheme + "://" + urlToProtect.Authority + string.Format(PathTemplate, obfuscatedOriginalPath), UriKind.Absolute);
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

        private static string ObfuscateString(string obfuscateThis)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(obfuscateThis));
        }

        private static bool TryUnobfuscateString(string unobfuscateThis, out string? result)
        {
            try
            {
                result = Encoding.UTF8.GetString(Convert.FromBase64String(unobfuscateThis));
                return true;
            }
            catch (FormatException)
            {
                result = null;
                return false;
            }
        }
    }
}
