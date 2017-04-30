// ***********************************************************************
// Assembly         : SmartStore.WebApi
// Author           : James Shen
// Created          : 04-29-2017
//
// Last Modified By : James Shen
// Last Modified On : 04-29-2017
// ***********************************************************************
// <copyright file="TokenDataFormat.cs" company="Guidebee IT">
//     Copyright (c)Guidebee IT . All rights reserved.
// </copyright>
// <summary></summary>
// ***********************************************************************


using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;

namespace SmartStore.WebApi.Authentication
{
    /// <summary>
    /// Class TokenDataFormat.
    /// </summary>
    /// <seealso cref="Microsoft.Owin.Security.ISecureDataFormat{Microsoft.Owin.Security.AuthenticationTicket}" />
    public class TokenDataFormat : ISecureDataFormat<AuthenticationTicket>
    {
        /// <summary>
        /// The protector
        /// </summary>
        private readonly IDataProtector _protector;

        /// <summary>
        /// The serializer
        /// </summary>
        private readonly TicketSerializer _serializer;

        /// <summary>
        /// The encoder
        /// </summary>
        private readonly ITextEncoder _encoder;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenDataFormat" /> class.
        /// </summary>
        /// <param name="protector">The protector.</param>
        public TokenDataFormat(IDataProtector protector)
        {
            _protector = protector;

            _serializer = new TicketSerializer();

            _encoder = TextEncodings.Base64Url;
        }

        /// <summary>
        /// Protects the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>System.String.</returns>
        public string Protect(AuthenticationTicket data)
        {
            var unencrypted = _serializer.Serialize(data);

            var encrypted = _protector.Protect(unencrypted);

            var encoded = _encoder.Encode(encrypted);

            return encoded;
        }

        /// <summary>
        /// Unprotects the specified protected text.
        /// </summary>
        /// <param name="protectedText">The protected text.</param>
        /// <returns>AuthenticationTicket.</returns>
        public AuthenticationTicket Unprotect(string protectedText)
        {
            var decoded = _encoder.Decode(protectedText);

            var unencrypted = _protector.Unprotect(decoded);

            var ticket = _serializer.Deserialize(unencrypted);

            return ticket;
        }
    }
}