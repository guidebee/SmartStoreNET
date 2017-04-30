// ***********************************************************************
// Assembly         : SmartStore.WebApi
// Author           : James Shen
// Created          : 04-29-2017
//
// Last Modified By : James Shen
// Last Modified On : 04-30-2017
// ***********************************************************************
// <copyright file="SmartStoreTokenAuthorizeAttribute.cs" company="Guidebee IT">
//     Copyright (c) Guidebee IT. All rights reserved.
// </copyright>
// <summary></summary>
// ***********************************************************************
using System.Security.Principal;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace SmartStore.WebApi.Authentication
{
    /// <summary>
    /// Class SmartStoreTokenAuthorizeAttribute.
    /// </summary>
    /// <seealso cref="System.Web.Http.AuthorizeAttribute" />
    public class SmartStoreTokenAuthorizeAttribute : AuthorizeAttribute
    {
        /// <summary>
        /// The aes256 data protector
        /// </summary>
        private static readonly Aes256DataProtector Aes256DataProtector = new Aes256DataProtector();

        /// <summary>
        /// Indicates whether the specified control is authorized.
        /// </summary>
        /// <param name="actionContext">The context.</param>
        /// <returns>true if the control is authorized; otherwise, false.</returns>
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            try
            {
                var accessToken = actionContext.Request.Headers.Authorization;
                if (accessToken != null && accessToken.Scheme == "Bearer")
                {
                    var authenticationTicket =
                        new TokenDataFormat(Aes256DataProtector).Unprotect(accessToken.Parameter);
                    actionContext.RequestContext.Principal = new GenericPrincipal
                         (authenticationTicket.Identity, null);
                    return authenticationTicket.Identity.IsAuthenticated;
                }
            }
            catch
            {
                return false;
            }
            return false;
        }
    }
}