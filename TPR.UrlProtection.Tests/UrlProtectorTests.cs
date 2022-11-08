using System.Text.RegularExpressions;
using System.Web;

namespace TPR.UrlProtection.Tests
{
    public class UrlProtectorTests
    {
        [TestCase(ParameterLocation.Path)]
        [TestCase(ParameterLocation.Query)]
        public void UnalteredUrlIsAllowed(ParameterLocation parameterLocation)
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = CreateProtector(parameterLocation);

            url = protector.ProtectPathAndQuery(url, salt);

            Assert.That(protector.CheckProtectedPathAndQuery(url, salt), Is.True);
        }

        [TestCase(ParameterLocation.Path)]
        [TestCase(ParameterLocation.Query)]
        public void UnalteredUrlRequiringUrlEncodingIsAllowed(ParameterLocation parameterLocation)
        {
            var url = new Uri("https://www.example.org/protect-me?thing=test with spaces");
            var salt = Guid.NewGuid().ToString();
            var protector = CreateProtector(parameterLocation);

            url = protector.ProtectPathAndQuery(url, salt);

            Assert.That(protector.CheckProtectedPathAndQuery(url, salt), Is.True);
        }

        private static UrlProtector CreateProtector(ParameterLocation parameterLocation)
        {
            if (parameterLocation == ParameterLocation.Path)
            {
                return new UrlProtector { ParameterLocation = ParameterLocation.Path, PathTemplate = "/my-page/{0}" };
            }
            else
            {
                return new UrlProtector { ParameterLocation = ParameterLocation.Query };
            }
        }

        [TestCase(ParameterLocation.Path)]
        [TestCase(ParameterLocation.Query)]
        public void AlteredQueryStringIsDisallowed(ParameterLocation parameterLocation)
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = CreateProtector(parameterLocation);

            url = protector.ProtectPathAndQuery(url, salt);

            if (parameterLocation == ParameterLocation.Path) { url = protector.ExtractProtectedUrlFromPath(url); }
            url = new Uri(url!.ToString().Replace("id=1", "id=2"));
            if (parameterLocation == ParameterLocation.Path) { url = protector.PlaceProtectedUrlInPath(url); }

            Assert.That(protector.CheckProtectedPathAndQuery(url, salt), Is.False);
        }

        [TestCase(ParameterLocation.Path)]
        [TestCase(ParameterLocation.Query)]
        public void AlteredPathIsDisallowed(ParameterLocation parameterLocation)
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = CreateProtector(parameterLocation);

            url = protector.ProtectPathAndQuery(url, salt);
            if (parameterLocation == ParameterLocation.Path) { url = protector.ExtractProtectedUrlFromPath(url); }
            url = new Uri(url!.ToString().Replace("protect-me", "break-me"));
            if (parameterLocation == ParameterLocation.Path) { url = protector.PlaceProtectedUrlInPath(url); }

            Assert.That(protector.CheckProtectedPathAndQuery(url, salt), Is.False);
        }

        [TestCase(ParameterLocation.Path)]
        [TestCase(ParameterLocation.Query)]
        public void AlteredHashIsDisallowed(ParameterLocation parameterLocation)
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = CreateProtector(parameterLocation);

            url = protector.ProtectPathAndQuery(url, salt);
            if (parameterLocation == ParameterLocation.Path) { url = protector.ExtractProtectedUrlFromPath(url); }

            var query = HttpUtility.ParseQueryString(url!.Query);
            query[protector.HashParameter] = query[protector.HashParameter] + "abc";
            url = new Uri($"{url.Scheme}://{url.Authority}{url.AbsolutePath}?{query}");

            if (parameterLocation == ParameterLocation.Path) { url = protector.PlaceProtectedUrlInPath(url); }

            Assert.That(protector.CheckProtectedPathAndQuery(url, salt), Is.False);
        }

        [Test]
        public void AlteredObfuscatedUrlInPathIsDisallowed()
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = CreateProtector(ParameterLocation.Path);

            url = protector.ProtectPathAndQuery(url, salt);
            url = new Uri(url!.ToString() + "abc");

            Assert.That(protector.CheckProtectedPathAndQuery(url, salt), Is.False);
        }

        [TestCase(ParameterLocation.Path)]
        [TestCase(ParameterLocation.Query)]
        public void ParameterIsPlacedCorrectly(ParameterLocation parameterLocation)
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var protector = CreateProtector(parameterLocation);

            url = protector.ProtectPathAndQuery(url, salt);

            var query = HttpUtility.ParseQueryString(url.Query);
            if (parameterLocation == ParameterLocation.Path)
            {
                Assert.That(query[protector.HashParameter], Is.Null);
                Assert.That(Regex.IsMatch(url.ToString(), "^https://www.example.org/my-page/[A-Za-z0-9=/]+$"), Is.True);
            }
            else
            {
                Assert.That(query[protector.HashParameter], Is.Not.Null);
            }

        }

    }
}