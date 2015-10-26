using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.OAuth.Adfs
{
    public class AdfsErrorContext : AdfsControlContext
    {
        public AdfsErrorContext(IOwinContext context, Exception error)
            : base(context)
        {
            Error = error;
        }

        /// <summary>
        /// User friendly error message for the error.
        /// </summary>
        public Exception Error { get; set; }
    }
}
