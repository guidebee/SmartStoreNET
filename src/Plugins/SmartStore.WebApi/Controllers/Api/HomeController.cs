// ***********************************************************************
// Assembly         : SmartStore.WebApi
// Author           : James Shen
// Created          : 04-28-2017
//
// Last Modified By : James Shen
// Last Modified On : 04-30-2017
// ***********************************************************************
// <copyright file="HomeController.cs" company="Guidebee IT">
//     Copyright (c) Guidebee IT. All rights reserved.
// </copyright>
// <summary></summary>
// ***********************************************************************
using System.Collections.Generic;
using System.Security.Claims;
using System.Web.Http;
using Microsoft.Owin.Security;
using SmartStore.WebApi.Authentication;

namespace SmartStore.WebApi.Controllers.Api
{

    /// <summary>
    /// Class HomeController.
    /// </summary>
    /// <seealso cref="System.Web.Http.ApiController" />
    public class HomeController : ApiController
    {
        /// <summary>
        /// Gets the hello world.
        /// </summary>
        /// <returns>System.String.</returns>
        [SmartStoreTokenAuthorize]
        public string GetHelloWorld()
        {
            return "Hello";
        }


        /// <summary>
        /// Gets the token.
        /// </summary>
        /// <returns>System.String.</returns>
        public string GetToken()
        {
            var identity = new ClaimsIdentity("Bearer");
            var propsList = new Dictionary<string, string>
            {

            };
            identity.AddClaim(new Claim(ClaimTypes.Email, "test@test.com"));
            var props = new AuthenticationProperties(propsList);
            var ticket = new AuthenticationTicket(identity, props);
            var accessToken = new TokenDataFormat(new Aes256DataProtector()).Protect(ticket);
            return accessToken;
        }
    }
}
