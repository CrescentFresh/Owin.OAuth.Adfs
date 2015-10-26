using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.OAuth.Adfs
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
        Justification = "OAuth is a valid word.")]
    public class AdfsOAuthTokenResponse
    {
        public AdfsOAuthTokenResponse(dynamic response)
        {
            Response = response;
            AccessToken = AdfsHelper.Value<string>(response, "access_token");
            TokenType = AdfsHelper.Value<string>(response, "token_type");
            RefreshToken = AdfsHelper.Value<string>(response, "refresh_token");
            ExpiresIn = AdfsHelper.Value<string>(response, "expires_in");
        }

        public dynamic Response { get; private set; }
        public string AccessToken { get; set; }
        public string TokenType { get; set; }
        public string RefreshToken { get; set; }
        public string ExpiresIn { get; set; }
    }
}
