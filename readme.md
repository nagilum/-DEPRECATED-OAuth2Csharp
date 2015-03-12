# OAuth2 lib for C#

A lightweight library for OAuth2 authentication.

## Prerequisite

This library uses the Newtonsoft JSON lib to parse response JSON from the
providers. You can find more information about it and how to add it here:
https://www.nuget.org/packages/Newtonsoft.Json

## Usage

Put this code on the login page:

```csharp
var clientID = 'your-apps-client-id';
var clientSecret = 'your-apps-client-secret';
var provider = 'provider to use';

// This is the URL the provider will send the user back to after authorization.
// If you set this to null it will be constructed using the URL authority and
// sub-path /login/<provider>/auth
var redirectURL = 'url-for-provider-return';

// If you have the users access-token from a previous login with the same
// provider, you can suply it here and the lib will try to refresh it so the
// user don't have to take the round-trip to the provider. Set this to null
// if you don't have it.
var accessToken = 'stored-access-token-for-user';

var oauth2 = new OAuth2(
  clientID,
  clientSecret,
  provider,
  redirectURL,
  accessToken);

// This will try and refresh the access token if you specified id, if not, the
// user will be forwarded to the providers login-page for authorization and
// the request stops here.
oauth2.Authenticate();

if (oauth2.IsAuthorized) {
  // This code will trigger if the access-token was simply refreshed (and is
  // still valid). So here you can proceed with normal access-granted stuff.
}
```

Put this code on the auth page:

```csharp
var clientID = 'your-apps-client-id';
var clientSecret = 'your-apps-client-secret';
var provider = 'provider to use';

var oauth2 = new OAuth2(
  clientID,
  clientSecret,
  provider,
  redirectURL,
  accessToken);

// Attempt to validate the code-response from the provider and retrieve a valid
// access-token.
oauth2.HandleResponse();

if (oauth2.IsAuthorized) {
  // If the lib received a valid access-token, this code will trigger, and you
  // can go about your business as normal.
}
```

## Properties

**AccessToken** (string)

The valid access token issued by the provider.

**AccessTokenExpiration** (DateTime)

Exact date-time when the access token expires.

**TokenType** (string)

Which type of token the provider issued. f.eks: Bearer, so you can use it for
API calls and the like.

**IsAuthorized** (bool)

Indicating whether or not the authentication process was completed and the user
was successfully authorized by the provider, aka the go-signal.

**UserInfo** (class)

Formatted collection of user-information provided by the provider.

**UserInfoSerialized** (string)

Serialized JSON from the provider with user-info which was used to parse
formatted info to the UserInfo class.

**Error**, **ErrorReason**, and **ErrorDescription** (string)

If an error occurred during the auth process, this is where the info about it
will be.

## Additional Functions

**AddEndpoint**

You can use this function to programatically add additional endpoints for use.
Obviously this has to be done prior to calling the ```Authenticate()``` function.

```csharp
oauth2.AddEndpoint(
  'provider-name',
  'auth-url', // URL for user-redirection to provider auth-page.
  'access-token-url', // URL for access token validation.
  'refresh-token-url', // URL for access token refresh.
  'user-info-url', // URL for user infomation gathering.
  'scope' // Provider-scope, if any.
  );
```
