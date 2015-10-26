using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace Owin.OAuth.Adfs
{
    /// <summary>
    /// Specifies callback methods which the <see cref="AdfsMiddleware"/> invokes
    /// to enable developer control over the authentication process.
    /// </summary>
    public interface IAdfsEvents
    {
        /// <summary>
        /// Invoked after the provider successfully authenticates a user. This can be used to retrieve user information.
        /// This event may not be invoked by sub-classes of OAuthAuthenticationHandler if they override CreateTicketAsync.
        /// </summary>
        /// <param name="context">Contains information about the login session.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task CreatingTicket(AdfsCreatingTicketContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to the authorize endpoint.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge.</param>
        Task RedirectToAuthorizationEndpoint(AdfsRedirectToAuthorizationContext context);

        /// <summary>
        /// Invoked when the remote authentication process has an error.
        /// </summary>
        Task RemoteError(AdfsErrorContext context);

        /// <summary>
        /// Invoked before sign in.
        /// </summary>
        Task TicketReceived(AdfsTicketReceivedContext context);
    }
}
