using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.OAuth.Adfs
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the middleware.
    /// </summary>
    public class AdfsRedirectToAuthorizationContext : BaseContext
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The owin request context.</param>
        /// <param name="options"></param>
        /// <param name="properties">The authentication properties of the challenge.</param>
        /// <param name="redirectUri">The initial redirect URI.</param>
        public AdfsRedirectToAuthorizationContext(
            IOwinContext context,
            AdfsOptions options,
            AuthenticationProperties properties,
            string redirectUri)
            : base(context)
        {
            RedirectUri = redirectUri;
            Properties = properties;
            Options = options;
        }

        public AdfsOptions Options { get; }

        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Gets the authentication properties of the challenge.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }
    }
}
