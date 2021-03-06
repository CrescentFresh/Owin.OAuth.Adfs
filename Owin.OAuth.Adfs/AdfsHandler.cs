﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Jil;

namespace Owin.OAuth.Adfs
{
    public class AdfsHandler : AuthenticationHandler<AdfsOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        protected string CurrentUri
        {
            get
            {
                return Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase + Request.Path + Request.QueryString;
            }
        }

        public AdfsHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                var state = EnsureSingle(Request.Query, "state");

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    _logger.WriteWarning($"{Options.AuthenticationType}: The oauth state was missing or invalid.");
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                    return new AuthenticationTicket(null, properties);

                var code = EnsureSingle(Request.Query, "code");
                if (string.IsNullOrEmpty(code))
                    return new AuthenticationTicket(null, properties);

                var token = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath)).ConfigureAwait(false);

                if (string.IsNullOrEmpty(token.AccessToken))
                {
                    _logger.WriteError($"{Options.AuthenticationType}: Access token was not found.");
                    return new AuthenticationTicket(null, properties);
                }

                var identity = new ClaimsIdentity(Options.AuthenticationType);

                return await CreateTicketAsync(identity, properties, token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.WriteError($"{Options.AuthenticationType}: Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected string BuildRedirectUri(PathString targetPath)
        {
            return Request.Scheme + "://" + Request.Host + Request.PathBase + targetPath;
        }

        protected virtual async Task<AdfsOAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                { "client_id", Options.ClientId },
                { "redirect_uri", redirectUri },
                { "code", code },
                { "grant_type", "authorization_code" },
            };

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;

            _logger.WriteInformation($"{Options.AuthenticationType}: trying code->token exchange");

            var response = await _httpClient.SendAsync(requestMessage, Context.Request.CallCancelled).ConfigureAwait(false);

            {
                IEnumerable<string> contentLength;
                response.Content.Headers.TryGetValues("Content-Length", out contentLength);
                _logger.WriteInformation(string.Format(
                    "{0}: code->token exchange response (status={1}, content-length={2})", Options.AuthenticationType,
                    response.StatusCode,
                    (contentLength ?? Enumerable.Empty<string>()).FirstOrDefault()));
            }

            response.EnsureSuccessStatusCode();

            var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            dynamic payload = JSON.DeserializeDynamic(new StreamReader(stream));

            return new AdfsOAuthTokenResponse(payload);
        }

        protected virtual async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity, AuthenticationProperties properties, AdfsOAuthTokenResponse token)
        {
            var claims = CleanClaims(token.Claims).ToList();

            if (!string.IsNullOrEmpty(Options.SubjectClaimType))
            {
                var altSubClaim = claims.FirstOrDefault(c => c.Type == Options.SubjectClaimType);
                if (altSubClaim != null)
                {
                    // replace existing sub claim
                    // TODO: is it safe to leave the existing sub claim alone?
                    claims.RemoveAll(m => m.Type == "sub");
                    claims.Add(new Claim("sub", altSubClaim.Value, altSubClaim.ValueType, token.Issuer));
                }
            }

            if (Options.SaveTokensAsClaims)
            {
                claims.Add(new Claim("access_token", token.AccessToken,
                                     ClaimValueTypes.String, token.Issuer));

                if (!string.IsNullOrEmpty(token.RefreshToken))
                {
                    claims.Add(new Claim("refresh_token", token.RefreshToken,
                                         ClaimValueTypes.String, token.Issuer));
                }

                if (!string.IsNullOrEmpty(token.TokenType))
                {
                    claims.Add(new Claim("token_type", token.TokenType,
                                         ClaimValueTypes.String, token.Issuer));
                }

                if (token.ExpiresIn != 0)
                {
                    claims.Add(new Claim("expires_in", token.ExpiresIn.ToString(),
                                         ClaimValueTypes.String, token.Issuer));
                }
            }

            var ticketIdentity = new ClaimsIdentity(claims, identity.AuthenticationType,
                identity.NameClaimType, identity.RoleClaimType);

            _logger.WriteInformation($"{Options.AuthenticationType}: creating ticket from remote token: {token.AccessToken}");

            var context = new AdfsCreatingTicketContext(Context, Options, _httpClient, token)
            {
                Identity = ticketIdentity,
                Properties = properties
            };

            await Options.Events.CreatingTicket(context).ConfigureAwait(false);

            if (context.Identity == null)
            {
                _logger.WriteWarning($"{Options.AuthenticationType}: The CreatingTicket event has set the identity to null");
                return null;
            }

            return new AuthenticationTicket(context.Identity, context.Properties);
        }

        IEnumerable<Claim> CleanClaims(IEnumerable<Claim> claims)
        {
            var exclude = new HashSet<string> { "aud", "iss", "iat", "exp", "auth_time", "authmethod", "ver", "appid" };
            return claims.Where(c => !exclude.Contains(c.Type));
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
                return;

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null)
                return;

            AuthenticationProperties properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            string state = Options.StateDataFormat.Protect(properties);

            string authorizationEndpoint =
                Options.AuthorizationEndpoint +
                    "?response_type=code" +
                    "&resource=" + Uri.EscapeDataString(Options.Resource) +
                    "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                    "&redirect_uri=" + Uri.EscapeDataString(BuildRedirectUri(Options.CallbackPath)) +
                    "&state=" + Uri.EscapeDataString(state);

            var redirectContext = new AdfsRedirectToAuthorizationContext(
                Context, Options,
                properties, authorizationEndpoint);

            await Options.Events.RedirectToAuthorizationEndpoint(redirectContext).ConfigureAwait(false);
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Request.Path == Options.CallbackPath)
            {
                return await HandleRemoteCallbackAsync().ConfigureAwait(false);
            }
            return false;
        }

        protected virtual async Task<bool> HandleRemoteCallbackAsync()
        {
            // TODO: error responses

            AuthenticationTicket ticket = await AuthenticateAsync().ConfigureAwait(false);
            if (ticket == null)
            {
                var errorContext = new AdfsErrorContext(Context,
                    new Exception("Invalid return state, unable to redirect."));

                _logger.WriteWarning($"{Options.AuthenticationType}: Error from RemoteAuthentication: " + errorContext.Error.Message);

                await Options.Events.RemoteError(errorContext).ConfigureAwait(false);

                if (errorContext.HandledResponse)
                    return true;

                if (errorContext.Skipped)
                    return false;

                Context.Response.StatusCode = 500;
                return true;
            }

            var context = new AdfsTicketReceivedContext(Context, Options, ticket);

            // REVIEW: is this safe or good?
            ticket.Properties.RedirectUri = null;

            await Options.Events.TicketReceived(context).ConfigureAwait(false);

            if (context.HandledResponse)
            {
                _logger.WriteVerbose($"{Options.AuthenticationType}: The TicketReceived event returned Handled.");
                return true;
            }

            if (context.Skipped)
            {
                _logger.WriteVerbose($"{Options.AuthenticationType}: The TicketReceived event returned Skipped.");
                return false;
            }

            if (context.Identity != null)
            {
                Context.Authentication.SignIn(context.Properties, context.Identity);
            }

            // Default redirect path is the base path
            if (string.IsNullOrEmpty(context.ReturnUri))
            {
                context.ReturnUri = "/";
            }

            if (string.IsNullOrEmpty(context.ReturnUri))
            {
                return false;
            }

            string uri = context.ReturnUri;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                uri = WebUtilities.AddQueryString(uri, "error", "access_denied");
            }
            Response.Redirect(uri);
            context.HandleResponse();
            return true;
        }

        string EnsureSingle(IReadableStringCollection collection, string name)
        {
            var values = collection.GetValues(name);
            if (values == null || values.Count == 0)
                throw new ArgumentException(string.Format("param '{0}' not found", name));
            if (values.Count > 1)
                throw new ArgumentException(string.Format("param '{0}' too many values present", name));
            return values[0];
        }
    }
}
