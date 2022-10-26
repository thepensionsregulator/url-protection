namespace ProtectedUrlDemo.Tests
{
    public class UrlProtectorTests
    {
        [Test]
        public void UnalteredUrlIsAllowed()
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = new UrlProtector();

            url = protector.ProtectPathAndQuery(url, salt);

            Assert.IsTrue(protector.CheckProtectedPathAndQuery(url, salt));
        }

        [Test]
        public void AlteredQueryStringIsDisallowed()
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = new UrlProtector();

            url = protector.ProtectPathAndQuery(url, salt);
            url = new Uri(url.ToString().Replace("id=1", "id=2"));

            Assert.IsFalse(protector.CheckProtectedPathAndQuery(url, salt));
        }

        [Test]
        public void AlteredPathIsDisallowed()
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = new UrlProtector();

            url = protector.ProtectPathAndQuery(url, salt);
            url = new Uri(url.ToString().Replace("protect-me", "break-me"));

            Assert.IsFalse(protector.CheckProtectedPathAndQuery(url, salt));
        }
    }
}