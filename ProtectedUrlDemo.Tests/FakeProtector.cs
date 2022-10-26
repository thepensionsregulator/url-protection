namespace ProtectedUrlDemo.Tests
{
    internal class FakeProtector : IUrlProtector
    {
        public string HashParameter { get; set; } = "h";

        public bool CheckProtectedPathAndQuery(Uri protectedUrl, string salt)
        {
            return true;
        }

        public Uri ProtectPathAndQuery(Uri urlToProtect, string salt)
        {
            return urlToProtect;
        }
    }
}
