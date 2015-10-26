using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Jil;

namespace Owin.OAuth.Adfs
{
    public class AdfsCreatingTicketContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="AdfsCreatingTicketContext"/>
        /// </summary>
        /// <param name="context">The HTTP environment.</param>
        /// <param name="options">The options used by the authentication middleware.</param>
        /// <param name="backchannel">The HTTP client used by the authentication middleware</param>
        /// <param name="token">The tokens returned from the token endpoint.</param>
        /// <param name="user">The de-serialized user.</param>
        public AdfsCreatingTicketContext(
            IOwinContext context,
            AdfsOptions options,
            HttpClient backchannel,
            AdfsOAuthTokenResponse token)
            : base(context)
        {
            if (context == null)
                throw new ArgumentNullException("context");

            if (options == null)
                throw new ArgumentNullException("options");

            if (backchannel == null)
                throw new ArgumentNullException("backchannel");

            if (token == null)
                throw new ArgumentNullException("token");

            TokenResponse = token;
            Backchannel = backchannel;
            Options = options;
        }

        public AdfsOptions Options { get; private set; }

        /// <summary>
        /// Gets the token response returned by the authentication service.
        /// </summary>
        public AdfsOAuthTokenResponse TokenResponse { get; private set; }

        /// <summary>
        /// Gets the access token provided by the authentication service.
        /// </summary>
        public string AccessToken { get { return TokenResponse.AccessToken; } }

        /// <summary>
        /// Gets the access token type provided by the authentication service.
        /// </summary>
        public string TokenType { get { return TokenResponse.TokenType; } }

        /// <summary>
        /// Gets the refresh token provided by the authentication service.
        /// </summary>
        public string RefreshToken { get { return TokenResponse.RefreshToken; } }

        /// <summary>
        /// Gets the access token expiration time.
        /// </summary>
        public TimeSpan? ExpiresIn
        {
            get
            {
                if (TokenResponse.ExpiresIn <= 0)
                    return null;
                return TimeSpan.FromSeconds(TokenResponse.ExpiresIn);
            }
        }

        /// <summary>
        /// Gets the backchannel used to communicate with the provider.
        /// </summary>
        public HttpClient Backchannel { get; private set; }

        /// <summary>
        /// Gets the main identity exposed by <see cref="Principal"/>.
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties.
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
