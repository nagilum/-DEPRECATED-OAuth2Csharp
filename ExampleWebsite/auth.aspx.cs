using System;
using System.Web.Configuration;
using System.Web.UI;

public partial class auth : Page {
    protected void Page_Load(object sender, EventArgs e) {
		// We get the provider from the passed URL itself. This is configured in
		// the global.asax file.
		var provider = this.RouteData.Values["provider"].ToString();

		// We fetch the clientID and clientSecret from the web.config appSettings.
		var clientID = WebConfigurationManager.AppSettings["OAuth2_" + provider + "_ClientID"];
		var clientSecret = WebConfigurationManager.AppSettings["OAuth2_" + provider + "_ClientSecret"];

		// Create a new instance of the class. Since this is the return trip-code
		// for this website, we don't need to give redirectURL and accessToken.
		var oauth2 = new FederatedLogin.OAuth2(
			clientID,
			clientSecret,
			provider);

		// Attempt to handle the response from the server and verify the login.
		oauth2.HandleResponse();

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