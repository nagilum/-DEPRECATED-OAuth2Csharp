﻿// @file
// A lightweight library for OAuth2 authentication.
//
// @author
// Stian Hanger <pdnagilum@gmail.com>
//
// @url
// https://github.com/nagilum/OAuth2Csharp

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.Web;
using System.Web.Script.Serialization;

namespace FederatedLogin {
	/// <summary>
	/// Authorization, refresh, and validation of users through OAuth2.
	/// </summary>
	public class OAuth2 {
		/// <summary>
		/// A list of pre-defined provider endpoints.
		/// </summary>
		private readonly List<OAuth2Endpoint> endpoints = new List<OAuth2Endpoint> {
			new OAuth2Endpoint {
				Provider = "Facebook",
				AuthURL = "https://graph.facebook.com/oauth/authorize",
				AccessTokenURL = "https://graph.facebook.com/oauth/access_token",
				RefreshTokenURL = "https://graph.facebook.com/oauth/client_code",
				UserInfoURL = "https://graph.facebook.com/me"
			}
		};

		/// <summary>
		/// The current request object to use throughout the library.
		/// </summary>
		private readonly HttpRequest request = HttpContext.Current.Request;

		/// <summary>
		/// The current response object to use throughout the library.
		/// </summary>
		private readonly HttpResponse response = HttpContext.Current.Response;

		/// <summary>
		/// ClientID given by provider.
		/// </summary>
		private string clientID { get; set; }

		/// <summary>
		/// ClientSecret issued by provider.
		/// </summary>
		private string clientSecret { get; set; }

		/// <summary>
		/// Name of provider.
		/// </summary>
		private string provider { get; set; }

		/// <summary>
		/// URL for provider to redirect back to when auth is completed.
		/// </summary>
		private string redirectURL { get; set; }

		/// <summary>
		/// Access token issued by provider.
		/// </summary>
		public string AccessToken { get; private set; }

		/// <summary>
		/// Expiration date of the issued access token.
		/// </summary>
		public DateTime AccessTokenExpiration { get; private set; }

		/// <summary>
		/// The type of token issued by the provider.
		/// </summary>
		public string TokenType { get; set; }

		/// <summary>
		/// Reflects whether or not the user has been authorized.
		/// </summary>
		public bool IsAuthorized { get; private set; }

		/// <summary>
		/// Parsed user-info from serialized info from provider.
		/// </summary>
		public OAuth2UserInfo UserInfo { get; private set; }

		/// <summary>
		/// Serialized string of the user-info response from provider.
		/// </summary>
		public string UserInfoSerialized { get; private set; }

		/// <summary>
		/// General error message from provider.
		/// </summary>
		public string Error { get; set; }

		/// <summary>
		/// Reason for error, from provider.
		/// </summary>
		public string ErrorReason { get; set; }

		/// <summary>
		/// Description of error, from provider.
		/// </summary>
		public string ErrorDescription { get; set; }

		/// <summary>
		/// Initiate a new instance of the OAuth2 library.
		/// </summary>
		/// <param name="clientID">ClientID given by provider.</param>
		/// <param name="clientSecret">ClientSecret issued by provider.</param>
		/// <param name="provider">Name of provider.</param>
		/// <param name="redirectURL">URL for provider to redirect back to when auth is completed.</param>
		/// <param name="accessToken">(optional) Access token to refresh.</param>
		public OAuth2(string clientID, string clientSecret, string provider, string redirectURL = null, string accessToken = null) {
			if (string.IsNullOrWhiteSpace(clientID) ||
				string.IsNullOrWhiteSpace(clientSecret))
				throw new MissingFieldException("Both clientID and clientSecret are required!");

			var endpoint =
				this.endpoints.SingleOrDefault(ep => ep.Provider.Equals(provider, StringComparison.CurrentCultureIgnoreCase));

			if (endpoint == null)
				throw new EndpointNotFoundException("Missing endpoint for given provider: " + provider);

			if (string.IsNullOrWhiteSpace(redirectURL))
				redirectURL =
					this.request.Url.Scheme +
					"://" +
					this.request.Url.Authority +
					"/login/" + provider + "/auth";

			this.clientID = clientID;
			this.clientSecret = clientSecret;
			this.provider = provider;
			this.redirectURL = redirectURL;

			this.AccessToken = accessToken;
		}

		/// <summary>
		/// Add an endpoint.
		/// </summary>
		/// <param name="provider">Name of the provider.</param>
		/// <param name="authURL">URL for user-redirection to provider auth-page.</param>
		/// <param name="accessTokenURL">URL for access token validation.</param>
		/// <param name="refreshTokenURL">URL for access token refresh.</param>
		/// <param name="userInfoURL">URL for user infomation gathering.</param>
		/// <param name="scope">Provider-scope, if any.</param>
		public void AddEndpoint(string provider, string authURL, string accessTokenURL, string refreshTokenURL, string userInfoURL, string scope = null) {
			this.endpoints.Add(
				new OAuth2Endpoint {
					Provider = provider,
					AuthURL = authURL,
					Scope = scope
				});
		}

		/// <summary>
		/// Redirect the user to the providers auth-page, or attempt to re-validate the stored access-token.
		/// </summary>
		public void Authenticate() {
			List<Tuple<string, string>> parameters;
			string url;

			var endpoint =
				this.endpoints.Single(ep => ep.Provider.Equals(provider, StringComparison.CurrentCultureIgnoreCase));

			if (!string.IsNullOrWhiteSpace(this.AccessToken)) {
				parameters = new List<Tuple<string, string>> {
					new Tuple<string, string>("access_token", this.AccessToken),
					new Tuple<string, string>("client_id", this.clientID),
					new Tuple<string, string>("client_secret", this.clientSecret),
					new Tuple<string, string>("redirect_uri", this.redirectURL)
				};

				url =
					endpoint.RefreshTokenURL + "?" +
					this.buildQueryString(parameters);

				var resp = this.makeWebRequest(url);
				var code = "";

				try {
					code = new JavaScriptSerializer().Deserialize<OAuth2CodeResponse>(resp).Code;
				}
				catch (Exception ex) {
					this.Error = "Unable to parse JSON response.";
					this.ErrorDescription = ex.Message;
				}

				if (!string.IsNullOrWhiteSpace(code))
					this.handleCodeResponse(code);

				if (this.IsAuthorized)
					return;
			}

			parameters = new List<Tuple<string, string>> {
				new Tuple<string, string>("client_id", this.clientID),
				new Tuple<string, string>("display", "page"),
				new Tuple<string, string>("locale", "en"),
				new Tuple<string, string>("redirect_uri", this.redirectURL),
				new Tuple<string, string>("response_type", "code")
			};

			if (!string.IsNullOrWhiteSpace(endpoint.Scope))
				parameters.Add(
					new Tuple<string, string>("scope", endpoint.Scope));

			url =
				endpoint.AuthURL + "?" +
				this.buildQueryString(parameters);

			this.response.Redirect(url, true);
		}

		/// <summary>
		/// Check for OAuth2 code response and attempt to validate it.
		/// </summary>
		public void HandleResponse() {
			if (this.request.QueryString["code"] == null)
				return;

			var code = this.request.QueryString["code"];
			var error = this.request.QueryString["error"];

			if (!string.IsNullOrWhiteSpace(code)) {
				this.handleCodeResponse(code);
			}
			else if (!string.IsNullOrWhiteSpace(error)) {
				this.Error = error;
				this.ErrorReason = this.request.QueryString["error_reason"];
				this.ErrorDescription = this.request.QueryString["error_description"];
			}
		}

		/// <summary>
		/// Validate a user by checking the 'code' variable against the provider.
		/// </summary>
		/// <param name="code">Code to validate.</param>
		private void handleCodeResponse(string code) {
			var parameters = new List<Tuple<string, string>> {
				new Tuple<string, string>("client_id", this.clientID),
				new Tuple<string, string>("redirect_uri", this.redirectURL),
				new Tuple<string, string>("client_secret", this.clientSecret),
				new Tuple<string, string>("code", code)
			};

			var endpoint =
				this.endpoints.Single(ep => ep.Provider.Equals(provider, StringComparison.CurrentCultureIgnoreCase));

			var url =
				endpoint.AccessTokenURL + "?" +
				this.buildQueryString(parameters);

			var resp = this.makeWebRequest(url);

			if (this.Error != null)
				return;

			this.analyzeAccessTokenResponse(resp);

			if (string.IsNullOrWhiteSpace(this.AccessToken) &&
				!this.IsAuthorized)
				return;

			parameters = new List<Tuple<string, string>> {
				new Tuple<string, string>("access_token", this.AccessToken)
			};

			url =
				endpoint.UserInfoURL + "?" +
				this.buildQueryString(parameters);

			resp = this.makeWebRequest(url);
			this.analyzeUserInfoResponse(resp);
		}

		/// <summary>
		/// Attempt to analyze access-token response, either in string or JSON format.
		/// </summary>
		/// <param name="resp">Strong or JSON response.</param>
		private void analyzeAccessTokenResponse(string resp) {
			if (resp == null)
				return;

			this.AccessToken = null;
			this.AccessTokenExpiration = DateTime.MinValue;

			if (resp.StartsWith("{") &&
				resp.EndsWith("}")) {
				try {
					var cr = new JavaScriptSerializer().Deserialize<OAuth2CodeResponse>(resp);

					if (!string.IsNullOrWhiteSpace(cr.Access_Token))
						this.AccessToken = cr.Access_Token;

					if (cr.Expires_In > 0)
						this.AccessTokenExpiration = DateTime.Now.AddSeconds(cr.Expires_In);

					if (!string.IsNullOrWhiteSpace(cr.Token_Type))
						this.TokenType = cr.Token_Type;
				}
				catch (Exception ex) {
					this.Error = "Unable to parse JSON response.";
					this.ErrorDescription = ex.Message;
				}
			}
			else {
				foreach (var entry in resp.Split('&')) {
					if (entry.IndexOf('=') == -1)
						continue;

					var key = entry.Substring(0, entry.IndexOf('='));
					var val = entry.Substring(entry.IndexOf('=') + 1);

					switch (key) {
						case "access_token":
							this.AccessToken = val;
							break;

						case "expires":
						case "expires_in":
							int exp;
							if (int.TryParse(val, out exp))
								this.AccessTokenExpiration = DateTime.Now.AddSeconds(exp);

							break;

						case "token_type":
							this.TokenType = val;
							break;
					}
				}
			}

			this.IsAuthorized = (!string.IsNullOrWhiteSpace(this.AccessToken) &&
								 this.AccessTokenExpiration > DateTime.Now);
		}

		/// <summary>
		/// Attempt to analyze the user-info JSON object from provider.
		/// </summary>
		/// <param name="resp">Serialized JSON object.</param>
		private void analyzeUserInfoResponse(string resp) {
			if (resp == null)
				return;

			this.UserInfoSerialized = resp;

			try {
				this.UserInfo = new JavaScriptSerializer().Deserialize<OAuth2UserInfo>(resp);
			}
			catch (Exception ex) {
				this.Error = "Unable to parse JSON response.";
				this.ErrorDescription = ex.Message;
			}
		}

		/// <summary>
		/// Compiles a list of parameters into a working query-string.
		/// </summary>
		/// <param name="parameteres">Parameters to compile.</param>
		/// <returns>Compilled query-string.</returns>
		private string buildQueryString(IEnumerable<Tuple<string, string>> parameteres) {
			return
				parameteres.Aggregate("", (current, parameter) => current + ("&" + parameter.Item1 + "=" + HttpUtility.UrlEncode(parameter.Item2)))
					.Substring(1);
		}

		/// <summary>
		/// Perform a HTTP web request to a given URL.
		/// </summary>
		/// <param name="url">URL to request.</param>
		/// <returns>String of response.</returns>
		private string makeWebRequest(string url) {
			try {
				var req = WebRequest.Create(url);
				var res = req.GetResponse();
				var httpres = res as HttpWebResponse;
				var status = 0;

				if (httpres != null)
					status = (int)httpres.StatusCode;

				if (status != 200)
					return null;

				var stream = res.GetResponseStream();

				if (stream == null)
					return null;

				var reader = new StreamReader(stream);
				var resp = reader.ReadToEnd();

				reader.Close();
				stream.Close();

				return resp;
			}
			catch (Exception ex) {
				this.Error = "Unable to properly make HTTP request.";
				this.ErrorDescription = ex.Message;
			}

			return null;
		}

		/// <summary>
		/// Endpoint to use for validation.
		/// </summary>
		private class OAuth2Endpoint {
			/// <summary>
			/// Name of provider.
			/// </summary>
			public string Provider { get; set; }

			/// <summary>
			/// URL for user-redirection to provider auth-page.
			/// </summary>
			public string AuthURL { get; set; }

			/// <summary>
			/// URL for access token validation.
			/// </summary>
			public string AccessTokenURL { get; set; }

			/// <summary>
			/// URL for access token refresh.
			/// </summary>
			public string RefreshTokenURL { get; set; }

			/// <summary>
			/// URL for user infomation gathering.
			/// </summary>
			public string UserInfoURL { get; set; }

			/// <summary>
			/// Provider-scope, if any.
			/// </summary>
			public string Scope { get; set; }
		}

		/// <summary>
		/// Object for json parsed code-response from provider.
		/// </summary>
		private class OAuth2CodeResponse {
			/// <summary>
			/// Code from provider.
			/// </summary>
			public string Code { get; set; }

			/// <summary>
			/// Token issued by the provider.
			/// </summary>
			public string Access_Token { get; set; }

			/// <summary>
			/// Amount of second til token expires.
			/// </summary>
			public int Expires_In { get; set; }

			/// <summary>
			/// The type of token issued by the provider.
			/// </summary>
			public string Token_Type { get; set; }
		}

		/// <summary>
		/// Object to store providers user-info.
		/// </summary>
		public class OAuth2UserInfo {
			/// <summary>
			/// ID issued by provider.
			/// </summary>
			public string ID { get; set; }

			/// <summary>
			/// E-mail for user.
			/// </summary>
			public string Email { get; set; }

			/// <summary>
			/// First name of user.
			/// </summary>
			public string FirstName { get; set; }

			/// <summary>
			/// First name of user.
			/// </summary>
			public string First_Name { get; set; }

			/// <summary>
			/// Last name of user.
			/// </summary>
			public string LastName { get; set; }

			/// <summary>
			/// Last name of user.
			/// </summary>
			public string Last_Name { get; set; }

			/// <summary>
			/// Full name of user.
			/// </summary>
			public string Name { get; set; }

			/// <summary>
			/// Gender of user.
			/// </summary>
			public string Gender { get; set; }

			/// <summary>
			/// Locale of user.
			/// </summary>
			public string Locale { get; set; }

			/// <summary>
			/// Time-zone of user.
			/// </summary>
			public int TimeZone { get; set; }

			/// <summary>
			/// Username of user.
			/// </summary>
			public string Username { get; set; }
		}
	}
}