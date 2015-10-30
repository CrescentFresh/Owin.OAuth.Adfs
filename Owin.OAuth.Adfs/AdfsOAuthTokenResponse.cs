using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Owin.OAuth.Adfs
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
        Justification = "OAuth is a valid word.")]
    public class AdfsOAuthTokenResponse
    {
        public dynamic Response { get; private set; }
        public string AccessToken { get; set; }
        public string TokenType { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
        public string Issuer { get; set; }

        public AdfsOAuthTokenResponse(dynamic response)
        {
            Response = response;
            Parse(AdfsHelper.Value<string>(response, "access_token"));
            TokenType = AdfsHelper.Value<string>(response, "token_type");
            RefreshToken = AdfsHelper.Value<string>(response, "refresh_token");
            ExpiresIn = AdfsHelper.Value<int>(response, "expires_in");
        }

        internal void Parse(string accessToken)
        {
            /**
             * ADFS does not have a user endpoint that I know of. Need to assume
             * token is a JWT and that claims for the user are contained therein.
             */
            var token = new JwtSecurityToken(accessToken);

            AccessToken = accessToken; // only got here if token was a valid jwt
            Claims = token.Claims.ToArray();
            Issuer = token.Issuer;
        }
    }
}
