using System;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace Owin.OAuth.Adfs
{
    public class AdfsEvents : IAdfsEvents
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
        /// </summary>
        public Func<AdfsCreatingTicketContext, Task> OnCreatingTicket { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the RedirectToAuthorizationEndpoint method is invoked.
        /// </summary>
        public Func<AdfsRedirectToAuthorizationContext, Task> OnRedirectToAuthorizationEndpoint { get; set; }

        public Func<AdfsErrorContext, Task> OnRemoteError { get; set; }

        public Func<AdfsTicketReceivedContext, Task> OnTicketReceived { get; set; }

        /// <summary>
        /// Initializes a <see cref="AdfsEvents"/>
        /// </summary>
        public AdfsEvents()
        {
            OnCreatingTicket = context => Task.FromResult(0);
            OnRedirectToAuthorizationEndpoint = context =>
            {
                context.Response.Redirect(context.RedirectUri);
                return Task.FromResult(0);
            };
            OnRemoteError = context => Task.FromResult(0);
            OnTicketReceived = context => Task.FromResult(0);
        }

        public Task CreatingTicket(AdfsCreatingTicketContext context)
        {
            return OnCreatingTicket(context);
        }

        public Task RedirectToAuthorizationEndpoint(AdfsRedirectToAuthorizationContext context)
        {
            return OnRedirectToAuthorizationEndpoint(context);
        }

        public Task RemoteError(AdfsErrorContext context)
        {
            return OnRemoteError(context);
        }

        public Task TicketReceived(AdfsTicketReceivedContext context)
        {
            return OnTicketReceived(context);
        }
    }
}
