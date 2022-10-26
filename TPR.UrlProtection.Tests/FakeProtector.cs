namespace TPR.UrlProtection.Tests
{
    internal class FakeProtector : IUrlProtector
    {
        public string HashParameter { get; set; } = "h";
        public ParameterLocation ParameterLocation { get; set; } = ParameterLocation.Query;
        public string? PathTemplate { get; set; }

        public bool CheckProtectedPathAndQuery(Uri protectedUrl, string salt)
        {
            return true;
        }

        public Uri? ExtractProtectedUrlFromPath(Uri protectedUrl)
        {
            return protectedUrl;
        }

        public Uri PlaceProtectedUrlInPath(Uri urlToProtect)
        {
            return urlToProtect;
        }

        public Uri ProtectPathAndQuery(Uri urlToProtect, string salt)
        {
            return urlToProtect;
        }
    }
}
