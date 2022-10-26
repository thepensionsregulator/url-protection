namespace ProtectedUrlDemo
{
    public interface IUrlProtector
    {
        /// <summary>
        /// Name of the querystring parameter used to store the hash that prevents the time being modified.
        /// </summary>
        string HashParameter { get; set; }

        /// <summary>
        /// Signs a query string so that you can check that it hasn't been changed.
        /// </summary>
        /// <param name="urlToProtect">The URL to protect.</param>
        /// <param name="salt">The unique salt used to protect this URL.</param>
        /// <returns><c>true</c> if the protected path and query are unaltered, <c>false</c> otherwise</returns>
        bool CheckProtectedPathAndQuery(Uri protectedUrl, string salt);

        /// <summary>
        /// Checks a query string protected by <seealso cref="ProtectPathAndQuery(Uri)"/> has not been tampered with.
        /// </summary>
        /// <param name="protectedUrl">The protected URL.</param>
        /// <param name="salt">The unique salt used to protect this URL.</param>
        /// <returns>The URL with an added hash parameter</returns>
        Uri ProtectPathAndQuery(Uri urlToProtect, string salt);
    }
}