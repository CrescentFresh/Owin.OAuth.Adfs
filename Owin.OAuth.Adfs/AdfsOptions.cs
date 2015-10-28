using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.OAuth.Adfs
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
        Justification = "OAuth2 is a valid word.")]
    public class AdfsOptions : AuthenticationOptions
    {
        public const string Scheme = "AdfsOAuth2";

        public AdfsOptions()
            : base(Scheme)
        {
            SubjectClaimType = "sub";
            DisplayName = "AD FS sign-on using OAuth2";
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Events = new AdfsEvents();
            SaveTokensAsClaims = true;
        }

        #region RemoteAuthenticationOptions

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with Twitter.
        /// </summary>
        /// <value>
        /// The back channel timeout.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with Twitter.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// This is used to construct the final "redirect_uri" sent to the ADFS OAuth2 endpoint.
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string DisplayName
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// Gets or sets the <see cref="IAdfsEvents"/> used to handle authentication events.
        /// </summary>
        public IAdfsEvents Events { get; set; }

        #endregion

        /// <summary>
        /// Gets or sets the id identifying the OAuth2 client registered in ADFS. This is the "ClientId"
        /// argument passed in the Add-ADFSClient powershell call.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the claim type inspected in the access token issued by the OAuth2 token
        /// endpoint used as the unique identifier for the subject. Defaults to "sub".
        /// </summary>
        public string SubjectClaimType { get; set; }

        /// <summary>
        /// Gets or sets the base address of the ADFS OAuth2 endpoint
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
            Justification = "OAuth2 is a valid word.")]
        public string BaseOAuth2Endpoint { get; set; }

        private string _authorizationEndpoint;

        /// <summary>
        /// Gets or sets the URI where the client will be redirected to authenticate.
        /// </summary>
        public string AuthorizationEndpoint
        {
            get
            {
                if (_authorizationEndpoint == null)
                {
                    if (!string.IsNullOrEmpty(BaseOAuth2Endpoint))
                        return BaseOAuth2Endpoint.TrimEnd('/') + "/authorize";
                }
                return _authorizationEndpoint;
            }
            set
            {
                _authorizationEndpoint = value;
            }
        }

        private string _tokenEndpoint;

        /// <summary>
        /// Gets or sets the URI the middleware will access to exchange the OAuth token.
        /// </summary>
        public string TokenEndpoint
        {
            get
            {
                if (_tokenEndpoint == null)
                {
                    if (!string.IsNullOrEmpty(BaseOAuth2Endpoint))
                        return BaseOAuth2Endpoint.TrimEnd('/') + "/token";
                }
                return _tokenEndpoint;
            }
            set
            {
                _tokenEndpoint = value;
            }
        }

        /// <summary>
        /// Gets or sets the authentication scheme corresponding to the middleware
        /// responsible of persisting user's identity after a successful authentication.
        /// This value typically corresponds to a cookie middleware registered in the Startup class.
        /// </summary>
        public string SignInScheme { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the 'resource' parameter (this is the relying party urn registered with
        /// the ADFS server).
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// Defines whether access and refresh tokens should be stored in the
        /// <see cref="ClaimsPrincipal"/> after a successful authentication.
        /// You can set this property to <c>false</c> to reduce the size of the final
        /// authentication cookie. The default value is <c>true</c>.
        /// </summary>
        public bool SaveTokensAsClaims { get; set; } = true;
    }
}
