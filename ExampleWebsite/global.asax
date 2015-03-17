<%@ Application Language="C#" %>
<%@ Import Namespace="System.Web.Routing" %>
<script runat="server">
    void Application_Start(object sender, EventArgs e) {
        // Route for init of login via provider.
        RouteTable.Routes.MapPageRoute(
            "Login",
            "login/{provider}",
            "~/login.aspx",
            false,
            new RouteValueDictionary {
                {"provider", ""}
            },
            new RouteValueDictionary {
                {"provider", ".*?"}
            });

        // Route for auth after provider redirects back.
        RouteTable.Routes.MapPageRoute(
            "Login Auth",
            "login/{provider}/auth",
            "~/auth.aspx",
            false,
            new RouteValueDictionary {
                {"provider", ""}
            },
            new RouteValueDictionary {
                {"provider", ".*?"}
            });
    }  
</script>