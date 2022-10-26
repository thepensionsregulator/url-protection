# Protect a URL from being tampered with

Sometimes changing the path or querystring of a URL could expose private information. For example, if you change the id on a form it might expose the data from another user. To protect against this you can hash the path and querystring with a secret salt, and include that hash in the URL. Checking that the hash still matches when the page is loaded ensures the URL has not been tampered with. The `UrlProtector` class enables this protection.

Before you redirect to a URL that needs to be protected, call `ProtectPathAndQuery` on the url.

You need to supply a salt, which should be unique to the resource being protected and is typically stored with that resource.

```csharp
var redirectToUrl = new Uri("https://hostname/protectme?id=1");
var uniqueSalt = Guid.NewGuid().ToString();
var protector = new UrlProtector(); // in a real application, inject IUrlProtector
protector.ParameterLocation = ParameterLocation.Path // optional, by default the URL is protected using the querystring
protector.PathTemplate = "/my-page/{0}" // only required if ParameterLocation = ParameterLocation.Path
var protectedUrl = protector.ProtectPathAndQuery(redirectToUrl, uniqueSalt);
Response.Headers.Add("Location", protectedUrl.ToString());
Response.StatusCode = 303;
```

On the next page, before you trust the `id` parameter in the querystring, check that is has not been tampered with. You'll need to supply the same salt you used to protect the URL:

```csharp
var protector = new UrlProtector();
var safeUrl = protector.CheckProtectedPathAndQuery(new Uri(Request.GetEncodedUrl()), rememberedUniqueSalt);
if (safeUrl)
{
    // application code here
}
else
{
    Response.StatusCode = 400;
    return;
}
```

## Give URLs an expiry date

Sometimes you want a URL only to work for a limited period of time, perhaps for privacy reasons so that it cannot easily be shared. You can do this by putting a date in the URL, which you check against your deadline in your application code, and then using a hash to verify that the URL has not been tampered with. The `UrlExpirer` class enables this protection. It uses `UrlProtector` to protect the querystring from being tampered with.

Before you redirect to a URL that needs to have an expiry date, call `ExpireUrl` on the url.

```csharp
var redirectToUrl = new Uri("https://hostname/protectme?id=1");
var uniqueSalt = Guid.NewGuid().ToString();
var expirer = new UrlExpirer(new UrlProtector()); // in a real application, inject IUrlExpirer
expirer.ParameterLocation = ParameterLocation.Path // optional, by default the URL is protected using the querystring
expirer.PathTemplate = "/my-page/{0}" // only required if ParameterLocation = ParameterLocation.Path
var protectedUrl = expirer.ExpireUrl(redirectToUrl, uniqueSalt);
Response.Headers.Add("Location", protectedUrl.ToString());
Response.StatusCode = 303;
```

On the next page, before you trust the `id` parameter in the querystring, check that the URL has not expired or been tampered with. This shows a time limit of 1 hour:

```csharp
var timeLimitInSeconds = 3600;
var expirer = new UrlExpirer(new UrlProtector());
var expired = expirer.HasUrlExpired(new Uri(Request.GetEncodedUrl(), rememberedUniqueSalt, timeLimitInSeconds);
if (!expired)
{
    // application code here
}
else
{
    Response.StatusCode = 400;
    return;
}
```
