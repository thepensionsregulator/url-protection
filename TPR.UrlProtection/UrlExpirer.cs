using System.Globalization;
using System.Web;

namespace TPR.UrlProtection
{
    /// <summary>
    /// Expire URLs after a given time or protect query strings from being tampered with 
    /// </summary>
    public class UrlExpirer : IUrlExpirer
    {
        private readonly IUrlProtector _urlProtector;

        /// <inheritdoc />
        public string HashParameter { get => _urlProtector.HashParameter; set => _urlProtector.HashParameter = value; }

        /// <inheritdoc />
        public string TimeParameter { get; set; } = "t";

        /// <inheritdoc />
        public ParameterLocation ParameterLocation { get => _urlProtector.ParameterLocation; set => _urlProtector.ParameterLocation = value; }

        /// <inheritdoc />
        public string? PathTemplate { get => _urlProtector.PathTemplate; set => _urlProtector.PathTemplate = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="UrlExpirer" /> class.
        /// </summary>
        /// <param name="urlProtector">A URL protector ensures the expiration time cannot be changed</param>
        /// <exception cref="System.ArgumentNullException"></exception>
        public UrlExpirer(IUrlProtector urlProtector)
        {
            _urlProtector = urlProtector ?? throw new ArgumentNullException(nameof(urlProtector));
        }


        /// <inheritdoc />
        public Uri ExpireUrl(Uri urlToExpire, string salt)
        {
            return ExpireUrl(urlToExpire, salt, DateTimeOffset.UtcNow);
        }

        /// <inheritdoc />
        public Uri ExpireUrl(Uri urlToExpire, string salt, DateTimeOffset utcTimestamp)
        {
            if (urlToExpire == null) { throw new ArgumentNullException(nameof(urlToExpire)); }
            if (!urlToExpire.IsAbsoluteUri) { throw new ArgumentException($"{nameof(urlToExpire)} must be an absolute URI", nameof(urlToExpire)); }

            // Add current time, which can be used to expire the link
            var query = HttpUtility.ParseQueryString(urlToExpire.Query);
            query.Add(TimeParameter, utcTimestamp.ToUniversalTime().ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture));
            var expiringUrl = new Uri(urlToExpire.Scheme + "://" + urlToExpire.Authority + urlToExpire.AbsolutePath + "?" + query, UriKind.Absolute);

            // Protect the URI against tampering, otherwise expiry date can be circumvented
            return _urlProtector.ProtectPathAndQuery(expiringUrl, salt);
        }

        /// <inheritdoc />
        public bool HasUrlExpired(Uri urlToCheck, string salt, int validForSeconds)
        {
            return HasUrlExpired(urlToCheck, salt, validForSeconds, DateTimeOffset.UtcNow);
        }

        /// <inheritdoc />
        public bool HasUrlExpired(Uri urlToCheck, string salt, int validForSeconds, DateTimeOffset currentUtcTime)
        {
            if (urlToCheck == null) { throw new ArgumentNullException(nameof(urlToCheck)); }
            if (!urlToCheck.IsAbsoluteUri) { throw new ArgumentException($"{nameof(urlToCheck)} must be an absolute URI", nameof(urlToCheck)); }

            // Check the querystring wasn't tampered with - if it was, it's expired
            if (!_urlProtector.CheckProtectedPathAndQuery(urlToCheck, salt)) { return true; }

            // Get the querystring in a usable form
            urlToCheck = _urlProtector.ExtractProtectedUrlFromPath(urlToCheck)!;
            var queryString = HttpUtility.ParseQueryString(urlToCheck.Query);

            // If time has been removed, expire link
            if (string.IsNullOrEmpty(queryString[TimeParameter])) { return true; }

            var linkCreated = DateTime.SpecifyKind(DateTime.ParseExact(queryString[TimeParameter]!, "yyyyMMddHHmmss", CultureInfo.InvariantCulture), DateTimeKind.Utc);
            if (currentUtcTime.ToUniversalTime().Subtract(linkCreated).TotalSeconds > validForSeconds)
            {
                // It's been too long...
                return true;
            }

            return false;
        }
    }
}
