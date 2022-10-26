namespace TPR.UrlProtection
{
    public interface IUrlExpirer
    {
        /// <summary>
        /// Name of the querystring parameter used to store the hash that prevents the time being modified.
        /// </summary>
        string HashParameter { get; set; }

        /// <summary>
        /// Sets whether to place the hash openly in the querystring or obfuscated in the path
        /// </summary>
        ParameterLocation ParameterLocation { get; set; }

        /// <summary>
        /// When <c>ParameterLocation</c> is set to <c>Path</c>, sets the format of the path to be produced, where {0} is the obfuscated original path and query
        /// </summary>
        string? PathTemplate { get; set; }

        /// <summary>
        /// Name of the querystring parameter used to store the time the URL was created.
        /// </summary>
        string TimeParameter { get; set; }

        /// <summary>
        /// Adds parameters to a URL which allow you to expire it after a set time. Set the time limit when you check if it's expired.
        /// </summary>
        /// <param name="urlToExpire">The URL to protect.</param>
        /// <param name="salt">The unique salt used to protect this URL.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">urlToExpire</exception>
        /// <exception cref="ArgumentException">urlToExpire must be an absolute URI</exception>
        Uri ExpireUrl(Uri urlToExpire, string salt);

        /// <summary>
        /// Adds parameters to a URL which allow you to expire it after a set time. Set the time limit when you check if it's expired.
        /// </summary>
        /// <param name="urlToExpire">The URL to protect.</param>
        /// <param name="salt">The unique salt used to protect this URL.</param>
        /// <param name="utcTimestamp">The UTC time from which to start the clock on expiry.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">urlToExpire</exception>
        /// <exception cref="ArgumentException">urlToExpire must be an absolute URI</exception>
        Uri ExpireUrl(Uri urlToExpire, string salt, DateTimeOffset utcTimestamp);

        /// <summary>
        /// Determines whether a URL protected by <seealso cref="ExpireUrl(Uri)"/> has expired.
        /// </summary>
        /// <param name="urlToCheck">The URL to check.</param>
        /// <param name="salt">The unique salt used to protect this URL.</param>
        /// <param name="validForSeconds">How many seconds the URL should be valid for.</param>
        /// <returns>
        /// 	<c>true</c> if the URL has expired; otherwise, <c>false</c>.
        /// </returns>
        bool HasUrlExpired(Uri urlToCheck, string salt, int validForSeconds);

        /// <summary>
        /// Determines whether a URL protected by <seealso cref="ExpireUrl(Uri)" /> has expired.
        /// </summary>
        /// <param name="urlToCheck">The URL to check.</param>
        /// <param name="salt">The unique salt used to protect this URL.</param>
        /// <param name="validForSeconds">How many seconds the URL should be valid for.</param>
        /// <param name="currentUtcTime">The current UTC time.</param>
        /// <returns>
        ///   <c>true</c> if the URL has expired; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="System.ArgumentNullException">urlToCheck</exception>
        /// <exception cref="System.ArgumentException">urlToCheck must be an absolute URI</exception>
        bool HasUrlExpired(Uri urlToCheck, string salt, int validForSeconds, DateTimeOffset currentUtcTime);
    }
}