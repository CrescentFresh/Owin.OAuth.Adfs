using System;
using Owin.OAuth.Adfs;

// ReSharper disable once CheckNamespace
// Standard Owin practice
namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="Security.Adfs.OAuth2.AdfsOAuth2AuthenticationMiddleware"/>
    /// </summary>
    public static class AdfsAppBuilderExtensions
    {
        /// <summary>
        /// Authenticate users using Adfs 3.0's OAuth2 endpoints
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseAdfsOAuth2Authentication(this IAppBuilder app, AdfsOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");

            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(AdfsMiddleware), app, options);

            return app;
        }

        /// <summary>
        /// Adds the <see cref="AdfsMiddleware"/> middleware to the specified <see cref="IAppBuilder"/>, which enables Adfs 3.0's OAuth2 capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> to add the middleware to.</param>
        /// <param name="configureOptions">An action delegate to configure the provided <see cref="AdfsOptions"/>.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IAppBuilder UseAdfsOAuth2Authentication(this IAppBuilder app, Action<AdfsOptions> configureOptions)
        {
            if (app == null)
                throw new ArgumentNullException("app");

            var options = new AdfsOptions();
            if (configureOptions != null)
            {
                configureOptions(options);
            }
            return app.UseAdfsOAuth2Authentication(options);
        }
    }
}
