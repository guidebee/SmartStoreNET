// ***********************************************************************
// Assembly         : SmartStore.WebApi
// Author           : James Shen
// Created          : 04-29-2017
//
// Last Modified By : James Shen
// Last Modified On : 04-30-2017
// ***********************************************************************
// <copyright file="Aes256DataProtector.cs" company="Guidebee IT">
//     Copyright (c) Guidebee IT. All rights reserved.
// </copyright>
// <summary></summary>
// ***********************************************************************

using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Owin.Security.DataProtection;

namespace SmartStore.WebApi.Authentication
{

    /// <summary>
    /// Class Aes256DataProtector.
    /// </summary>
    /// <seealso cref="Microsoft.Owin.Security.DataProtection.IDataProtector" />
    public class Aes256DataProtector : IDataProtector
    {

        /// <summary>
        /// The bearer token encryption key
        /// </summary>
        private const string BearerTokenEncryptionKey = "vJ_+uqqC523H&@F@CQXdndcgychT8p7fwEkJpF?x3cyfFmPA*HggUh+!kTabmxr*p85#?VbLery7q%%6Zn2KPJ&V5an&P7wPBsEX=guEU@ZCymaQbCD-jjt&Vug8#TLf";


        /// <summary>
        /// The key
        /// </summary>
        private readonly byte[] _key;

        /// <summary>
        /// Initializes a new instance of the <see cref="Aes256DataProtector"/> class.
        /// </summary>
        public Aes256DataProtector() : this(BearerTokenEncryptionKey) { }


        /// <summary>
        /// Initializes a new instance of the <see cref="Aes256DataProtector"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        private Aes256DataProtector(string key)
        {
            using (var sha1 = new SHA256Managed())
            {
                _key = sha1.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }

        /// <summary>
        /// Protects the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] Protect(byte[] data)
        {
            byte[] dataHash;
            using (var sha = new SHA256Managed())
            {
                dataHash = sha.ComputeHash(data);
            }

            using (var aesAlg = new AesManaged())
            {
                aesAlg.Key = _key;
                aesAlg.GenerateIV();
                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        msEncrypt.Write(aesAlg.IV, 0, 16);
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var bwEncrypt = new BinaryWriter(csEncrypt))
                            {
                                bwEncrypt.Write(dataHash);
                                bwEncrypt.Write(data.Length);
                                bwEncrypt.Write(data);
                            }
                        }
                        var protectedData = msEncrypt.ToArray();
                        return protectedData;
                    }
                }
            }
        }


        /// <summary>
        /// Unprotects the specified protected data.
        /// </summary>
        /// <param name="protectedData">The protected data.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="System.Security.SecurityException">Signature does not match the computed hash</exception>
        public byte[] Unprotect(byte[] protectedData)
        {
            using (var aesAlg = new AesManaged())
            {
                aesAlg.Key = _key;
                using (var msDecrypt = new MemoryStream(protectedData))
                {
                    var iv = new byte[16];
                    msDecrypt.Read(iv, 0, 16);
                    aesAlg.IV = iv;
                    using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var brDecrypt = new BinaryReader(csDecrypt))
                            {
                                var signature = brDecrypt.ReadBytes(32);
                                var len = brDecrypt.ReadInt32();
                                var data = brDecrypt.ReadBytes(len);
                                byte[] dataHash;
                                using (var sha = new SHA256Managed())
                                {
                                    dataHash = sha.ComputeHash(data);
                                }
                                if (!dataHash.SequenceEqual(signature))
                                {
                                    throw new SecurityException("Signature does not match the computed hash");
                                }
                                return data;
                            }
                        }
                    }
                }
            }
        }
    }
}