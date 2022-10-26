namespace TPR.UrlProtection.Tests
{
    public class UrlExpirerTests
    {
        [Test]
        public void ValidUrlIsAllowed()
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var expirer = new UrlExpirer(new FakeProtector());

            url = expirer.ExpireUrl(url, salt, new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero));
            const int secondsInOneDay = 86400;
            var expired = expirer.HasUrlExpired(url, salt, secondsInOneDay, new DateTimeOffset(2022, 1, 2, 0, 0, 0, TimeSpan.Zero));

            Assert.That(expired, Is.False);
        }

        [Test]
        public void ExpiredUrlIsDisallowed()
        {
            var url = new Uri("https://www.example.org/protect-me?id=1");
            var salt = Guid.NewGuid().ToString();
            var expirer = new UrlExpirer(new FakeProtector());

            url = expirer.ExpireUrl(url, salt, new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero));
            const int secondsInOneDay = 86400;
            var expired = expirer.HasUrlExpired(url, salt, secondsInOneDay, new DateTimeOffset(2022, 1, 2, 0, 0, 1, TimeSpan.Zero));

            Assert.That(expired, Is.True);
        }
    }
}
