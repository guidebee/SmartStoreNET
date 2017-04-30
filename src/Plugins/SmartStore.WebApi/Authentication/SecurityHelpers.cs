// ***********************************************************************
// Assembly         : SmartStore.WebApi
// Author           : james
// Created          : 04-29-2017
//
// Last Modified By : james
// Last Modified On : 04-29-2017
// ***********************************************************************
// <copyright file="SecurityHelpers.cs" company="Guidebee IT">
//     Copyright (c) . All rights reserved.
// </copyright>
// <summary></summary>
// ***********************************************************************

using System;
using System.Security.Cryptography;
using System.Web;

namespace SmartStore.WebApi.Authentication
{
    /// <summary>
    /// Class RandomOAuthStateGenerator.
    /// </summary>
    public static class RandomOAuthStateGenerator
    {
        /// <summary>
        /// The random
        /// </summary>
        private static readonly RandomNumberGenerator Random = new RNGCryptoServiceProvider();

        /// <summary>
        /// Generates the specified strength in bits.
        /// </summary>
        /// <param name="strengthInBits">The strength in bits.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="System.ArgumentException">strengthInBits must be evenly divisible by 8. - strengthInBits</exception>
        public static string Generate(int strengthInBits)
        {
            const int bitsPerByte = 8;

            if (strengthInBits % bitsPerByte != 0)
            {
                throw new ArgumentException(@"strengthInBits must be evenly divisible by 8.", nameof(strengthInBits));
            }

            var strengthInBytes = strengthInBits / bitsPerByte;

            var data = new byte[strengthInBytes];
            Random.GetBytes(data);
            return HttpServerUtility.UrlTokenEncode(data);
        }
    }


}