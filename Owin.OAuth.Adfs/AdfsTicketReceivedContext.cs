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
            Options = options;
            AuthenticationTicket = ticket;
            if (ticket != null)
            {
                Identity = ticket.Identity;
                Properties = ticket.Properties;
            }
        }

        public AdfsOptions Options { get; private set; }

        public ClaimsIdentity Identity { get; set; }

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
