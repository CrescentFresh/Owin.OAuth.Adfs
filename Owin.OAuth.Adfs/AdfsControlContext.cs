using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.OAuth.Adfs
{
    public class AdfsControlContext : BaseContext
    {
        protected AdfsControlContext(IOwinContext context)
            : base(context)
        { }

        /// <summary>
        /// Gets or set the <see cref="AuthenticationTicket"/> to return if this event signals it handled the event.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; set; }

        private byte _state = 0;

        public bool HandledResponse
        {
            get { return _state == 2; }
        }

        public bool Skipped
        {
            get { return _state == 1; }
        }

        /// <summary>
        /// Discontinue all processing for this request and return to the client.
        /// The caller is responsible for generating the full response.
        /// Set the <see cref="AuthenticationTicket"/> to trigger SignIn.
        /// </summary>
        public void HandleResponse()
        {
            _state = 2;
        }

        /// <summary>
        /// Discontinue processing the request in the current middleware and pass control to the next one.
        /// SignIn will not be called.
        /// </summary>
        public void SkipToNextMiddleware()
        {
            _state = 1;
        }
    }
}
