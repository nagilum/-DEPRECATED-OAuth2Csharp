using System;
using System.Web.Configuration;
using System.Web.UI;

public partial class login : Page {
    protected void Page_Load(object sender, EventArgs e) {
		// We get the provider from the passed URL itself. This is configured in
		// the global.asax file.
		var provider = this.RouteData.Values["provider"].ToString();

		// We fetch the clientID and clientSecret from the web.config appSettings.
		var clientID = WebConfigurationManager.AppSettings["OAuth2_" + provider + "_ClientID"];
		var clientSecret = WebConfigurationManager.AppSettings["OAuth2_" + provider + "_ClientSecret"];

		// Fetch the access token from the session, so if we've already been logged
		// in to Facebook, we can just refresh the token.
		string accessToken = null;
		if (Session["OAuth2_" + provider + "_AccessToken"] != null)
			accessToken = Session["OAuth2_" + provider + "_AccessToken"].ToString();

		// Create a new instance of the class. If we don't provide the redirectURL
		// parameter, it will be automatically constructed as /login/<provider>/auth.
		var oauth2 = new FederatedLogin.OAuth2(
			clientID,
			clientSecret,
			provider,
			null,
			accessToken);

		// Now we're ready to init the authentication part of our routine. If we
		// didn't pass in any access-token or the token isn't valid, the user will
		// be forwarded to the provider at this time for re-validation.
		oauth2.Authenticate();

		// If we're authenticated, store the user info.
		if (oauth2.IsAuthorized) {
			Session["OAuth2_" + provider + "_AccessToken"] = oauth2.AccessToken;
			Session["OAuth2_" + provider + "_UserInfo"] = oauth2.UserInfo;
		}

		// If we encountered an error, log it!
		if (oauth2.Error != null) {
			Session["OAuth2_" + provider + "_Error"] = oauth2.Error;
			Session["OAuth2_" + provider + "_ErrorReason"] = oauth2.ErrorReason;
			Session["OAuth2_" + provider + "_ErrorDescription"] = oauth2.ErrorDescription;
		}

		// Redirect back to default.aspx.
		Response.Redirect("/");
    }
}