<%@ Page Language="C#" AutoEventWireup="true" CodeFile="default.aspx.cs" Inherits="_default" %>
<!doctype html>
<html lang="en">
    <head>
        <title>OAuth2 Example Website</title>
    </head>
    <body>
        <form runat="server">
            <p>
                <a href="/login/facebook">Login with Facebook</a>
            </p>
            <p>
                <asp:Literal runat="server" ID="ltInfo"></asp:Literal>
            </p>
            <p>
                <asp:Literal runat="server" ID="ltError"></asp:Literal>
            </p>
        </form>
    </body>
</html>