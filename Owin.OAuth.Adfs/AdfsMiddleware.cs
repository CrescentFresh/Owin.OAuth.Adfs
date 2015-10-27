using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.OAuth.Adfs
{
    /// <summary>
    /// OWIN middleware for authenticating users using AD FS 3.0 (Windows Server 2012 R2) OAuth 2.0
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable", Justification = "Middleware are not disposable.")]
    internal class AdfsMiddleware : AuthenticationMiddleware<AdfsOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public AdfsMiddleware(
            OwinMiddleware next,/*FACTORIESHERE,*/
            IAppBuilder app,
            AdfsOptions options)
            : base(next, options)
        {
            if (string.IsNullOrEmpty(Options.AuthorizationEndpoint))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "BaseOAuth2Endpoint"));

            if (string.IsNullOrEmpty(Options.TokenEndpoint))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "BaseOAuth2Endpoint"));

            Uri uri;
            if (!Uri.TryCreate(Options.AuthorizationEndpoint, UriKind.Absolute, out uri))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_InvalidUri, Options.AuthorizationEndpoint));

            if (!Uri.TryCreate(Options.TokenEndpoint, UriKind.Absolute, out uri))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_InvalidUri, Options.TokenEndpoint));

            if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ClientId"));

            if (!Options.CallbackPath.HasValue)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "CallbackPath"));

            if (string.IsNullOrEmpty(Options.Resource))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "Resource"));

            if (string.IsNullOrEmpty(Options.SignInScheme))
            {
                Options.SignInScheme = app.GetDefaultSignInAsAuthenticationType();
            }

            if (string.IsNullOrEmpty(Options.SignInScheme))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "SignInScheme"));

            if (Options.Events == null)
            {
                Options.Events = new AdfsEvents();
            }

            if (Options.StateDataFormat == null)
            {
                var dataProtecter = app.CreateDataProtector(
                    typeof(AdfsMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }

            _logger = app.CreateLogger<AdfsOptions>();

            _httpClient = new HttpClient(Options.BackchannelHttpHandler ?? new HttpClientHandler());
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("AD FS OAuth2 middleware");
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        protected override AuthenticationHandler<AdfsOptions> CreateHandler()
        {
            return new AdfsHandler(_httpClient, _logger);
        }
    }
}
