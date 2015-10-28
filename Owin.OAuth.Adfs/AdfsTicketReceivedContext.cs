using System;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.OAuth.Adfs
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class AdfsTicketReceivedContext : AdfsControlContext
    {
        public AdfsTicketReceivedContext(
            IOwinContext context,
            AdfsOptions options,
            AuthenticationTicket ticket)
            : base(context)
        {
            if (options == null) throw new ArgumentNullException("options");

            Options = options;
            SignInScheme = options.SignInScheme;
            AuthenticationTicket = ticket;
            if (ticket != null)
            {
                Identity = ticket.Identity;
                Properties = ticket.Properties;
                ReturnUri = ticket.Properties.RedirectUri;
            }
        }

        public AdfsOptions Options { get; private set; }

        private ClaimsIdentity _identity;
        public ClaimsIdentity Identity
        {
            get
            {
                if (SignInScheme != null && _identity != null)
                {
                    /**
                     * Burrshit code to make the Identity.AuthenticationType match the SignInScheme,
                     * a side effect of how IAuthenticationManager.SignIn() works.
                     */
                    if (!string.Equals(_identity.AuthenticationType, SignInScheme, StringComparison.Ordinal))
                        return new ClaimsIdentity(_identity.Claims, SignInScheme, _identity.NameClaimType,
                            _identity.RoleClaimType);
                }
                return _identity;
            }
            set
            {
                _identity = value;
            }
        }

        /// <summary>
        /// Gets the authentication properties of the challenge
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }

        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings", Justification = "Represents header value")]
        public string ReturnUri { get; set; }

        public string SignInScheme { get; set; }
    }
}
