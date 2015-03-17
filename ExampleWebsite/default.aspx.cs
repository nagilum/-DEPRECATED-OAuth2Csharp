using System;
using System.Web.UI;

public partial class _default : Page {
    protected void Page_Load(object sender, EventArgs e) {
	    const string provider = "facebook";

	    var userInfo = (Session["OAuth2_" + provider + "_UserInfo"] != null ? Session["OAuth2_" + provider + "_UserInfo"] as FederatedLogin.OAuth2.OAuth2UserInfo : null);
		var error = (Session["OAuth2_" + provider + "_Error"] != null ? Session["OAuth2_" + provider + "_Error"].ToString() : null);
		var errorReason = (Session["OAuth2_" + provider + "_ErrorReason"] != null ? Session["OAuth2_" + provider + "_ErrorReason"].ToString() : null);
		var errorDescription = (Session["OAuth2_" + provider + "_ErrorDescription"] != null ? Session["OAuth2_" + provider + "_ErrorDescription"].ToString() : null);

	    if (userInfo != null)
		    this.ltInfo.Text = "Logged in as " + userInfo.Name;

	    if (error != null)
			this.ltError.Text =
			    "Error: " + error + "<br>\r\n" +
				"ErrorReason: " + errorReason + "<br>\r\n" +
				"ErrorDescription: " + errorDescription + "<br>\r\n";
    }
}