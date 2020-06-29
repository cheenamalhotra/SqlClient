// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;
using static Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider.Validator;

namespace Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider
{
    /// <summary>
    /// Implementation of column master key store provider that allows client applications to access data when a 
    /// column master key is stored in Microsoft Azure Key Vault. For more information on Always Encrypted, please refer to: https://aka.ms/AlwaysEncrypted.
    ///
    /// A Column Encryption Key encrypted with certificate store provider should be decryptable by this provider and vice versa.
    /// 
    /// Envelope Format for the encrypted column encryption key  
    ///           version + keyPathLength + ciphertextLength + keyPath + ciphertext +  signature
    /// 
    /// version: A single byte indicating the format version.
    /// keyPathLength: Length of the keyPath.
    /// ciphertextLength: ciphertext length
    /// keyPath: keyPath used to encrypt the column encryption key. This is only used for troubleshooting purposes and is not verified during decryption.
    /// ciphertext: Encrypted column encryption key
    /// signature: Signature of the entire byte array. Signature is validated before decrypting the column encryption key.
    /// </summary>
    /// <remarks>
	///	    <format type="text/markdown"><![CDATA[
    /// ## Remarks
    /// 
    /// **SqlColumnEncryptionAzureKeyVaultProvider** is implemented for Microsoft.Data.SqlClient driver and supports .NET Framework 4.6+ and .NET Core 2.1+.
    /// The provider name identifier for this implementation is "AZURE_KEY_VAULT" and it is not registered in driver by default.
    /// Client applications must call <xref=Microsoft.Data.SqlClient.SqlConnection.RegisterColumnEncryptionKeyStoreProviders> API only once in the lifetime of driver to register this custom provider by implementing a custom Authentication Callback mechanism.
    /// 
    /// Once the provider is registered, it can used to perform Always Encrypted operations by creating Column Master Key using Azure Key Vault Key Identifier URL.
    /// 
    /// ## Example
    /// 
    /// Sample C# applications to demonstrate Always Encrypted use with Azure Key Vault are available at links below:
    /// 
    /// - [Example: Using Azure Key Vault with Always Encrypted](~/connect/ado-net/sql/azure-key-vault-example.md)
    /// - [Example: Using Azure Key Vault with Always Encrypted with enclaves enabled](~/connect/ado-net/sql/azure-key-vault-enclave-example.md)
    /// ]]></format>
    /// </remarks>
    public class SqlColumnEncryptionAzureKeyVaultProvider : SqlColumnEncryptionKeyStoreProvider
    {
        #region Properties

        /// <summary>
        /// Column Encryption Key Store Provider string
        /// </summary>
        public const string ProviderName = "AZURE_KEY_VAULT";

        /// <summary>
        /// Key storage and cryptography client
        /// </summary>
        private AzureSqlKeyCryptographer KeyCryptographer { get; set; }

        /// <summary>
        /// Algorithm version
        /// </summary>
        private readonly static byte[] s_firstVersion = new byte[] { 0x01 };

        private readonly static KeyWrapAlgorithm s_keyWrapAlgorithm = KeyWrapAlgorithm.RsaOaep;

        /// <summary>
        /// List of Trusted Endpoints
        /// 
        /// </summary>
        public readonly string[] TrustedEndPoints;

        #endregion

        /// <summary>
        /// Constructor that takes a callback function to authenticate to AAD. This is used by KeyVaultClient at runtime 
        /// to authenticate to Azure Key Vault.
        /// </summary>
        /// <param name="authenticationCallback">Callback function used for authenticating to AAD.</param>
        public SqlColumnEncryptionAzureKeyVaultProvider(AuthenticationCallback authenticationCallback) :
            this(authenticationCallback, Constants.AzureKeyVaultPublicDomainNames)
        { }

        /// <summary>
        /// Constructor that takes a callback function to authenticate to AAD and a trusted endpoint. 
        /// </summary>
        /// <param name="authenticationCallback">Callback function used for authenticating to AAD.</param>
        /// <param name="trustedEndPoint">TrustedEndpoint is used to validate the master key path</param>
        public SqlColumnEncryptionAzureKeyVaultProvider(AuthenticationCallback authenticationCallback, string trustedEndPoint) :
            this(authenticationCallback, new[] { trustedEndPoint })
        { }

        /// <summary>
        /// Constructor that takes a callback function to authenticate to AAD and an array of trusted endpoints. The callback function 
        /// is used by KeyVaultClient at runtime to authenticate to Azure Key Vault.
        /// </summary>
        /// <param name="authenticationCallback">Callback function used for authenticating to AAD.</param>
        /// <param name="trustedEndPoints">TrustedEndpoints are used to validate the master key path</param>
        public SqlColumnEncryptionAzureKeyVaultProvider(AuthenticationCallback authenticationCallback, string[] trustedEndPoints)
        {
            ValidateNotNull(authenticationCallback, nameof(authenticationCallback));
            ValidateNotNull(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotEmpty(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotNullOrWhitespaceForEach(trustedEndPoints, nameof(trustedEndPoints));

            KeyCryptographer = new AzureSqlKeyCryptographer(authenticationCallback);
            TrustedEndPoints = trustedEndPoints;
        }

        // New constructors

        /// <summary>
        /// Constructor that takes an implementation of Token Credential that is capable of providing an OAuth Token.
        /// </summary>
        /// <param name="tokenCredential"></param>
        public SqlColumnEncryptionAzureKeyVaultProvider(TokenCredential tokenCredential) :
            this(tokenCredential, Constants.AzureKeyVaultPublicDomainNames)
        { }

        /// <summary>
        /// Constructor that takes an implementation of Token Credential that is capable of providing an OAuth Token and a trusted endpoint. 
        /// </summary>
        /// <param name="tokenCredential">Instance of an implementation of Token Credential that is capable of providing an OAuth Token.</param>
        /// <param name="trustedEndPoint">TrustedEndpoint is used to validate the master key path.</param>
        public SqlColumnEncryptionAzureKeyVaultProvider(TokenCredential tokenCredential, string trustedEndPoint) :
            this(tokenCredential, new[] { trustedEndPoint })
        { }

        /// <summary>
        /// Constructor that takes an instance of an implementation of Token Credential that is capable of providing an OAuth Token 
        /// and an array of trusted endpoints.
        /// </summary>
        /// <param name="tokenCredential">Instance of an implementation of Token Credential that is capable of providing an OAuth Token</param>
        /// <param name="trustedEndPoints">TrustedEndpoints are used to validate the master key path</param>
        public SqlColumnEncryptionAzureKeyVaultProvider(TokenCredential tokenCredential, string[] trustedEndPoints)
        {
            ValidateNotNull(tokenCredential, nameof(tokenCredential));
            ValidateNotNull(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotEmpty(trustedEndPoints, nameof(trustedEndPoints));
            ValidateNotNullOrWhitespaceForEach(trustedEndPoints, nameof(trustedEndPoints));

            KeyCryptographer = new AzureSqlKeyCryptographer(tokenCredential);
            TrustedEndPoints = trustedEndPoints;
        }

        #region Public methods

        /// <summary>
        /// Uses an asymmetric key identified by the key path to sign the masterkey metadata consisting of (masterKeyPath, allowEnclaveComputations bit, providerName).
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key. Path format is specific to a key store provider.</param>
        /// <param name="allowEnclaveComputations">Boolean indicating whether this key can be sent to trusted enclave</param>
        /// <returns>Encrypted column encryption key</returns>
        public override byte[] SignColumnMasterKeyMetadata(string masterKeyPath, bool allowEnclaveComputations)
        {
            ValidateNonEmptyAKVPath(masterKeyPath, isSystemOp: false);

            // Also validates key is of RSA type.
            KeyCryptographer.AddKey(masterKeyPath);
            byte[] message = CompileMasterKeyMetadata(masterKeyPath, allowEnclaveComputations);
            return KeyCryptographer.SignData(message, masterKeyPath);
        }

        /// <summary>
        /// Uses an asymmetric key identified by the key path to verify the masterkey metadata consisting of (masterKeyPath, allowEnclaveComputations bit, providerName).
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key. Path format is specific to a key store provider.</param>
        /// <param name="allowEnclaveComputations">Boolean indicating whether this key can be sent to trusted enclave</param>
        /// <param name="signature">Signature for the master key metadata</param>
        /// <returns>Boolean indicating whether the master key metadata can be verified based on the provided signature</returns>
        public override bool VerifyColumnMasterKeyMetadata(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
        {
            ValidateNonEmptyAKVPath(masterKeyPath, isSystemOp: true);

            // Also validates key is of RSA type.
            KeyCryptographer.AddKey(masterKeyPath);
            byte[] message = CompileMasterKeyMetadata(masterKeyPath, allowEnclaveComputations);
            return KeyCryptographer.VerifyData(message, signature, masterKeyPath);
        }

        /// <summary>
        /// This function uses the asymmetric key specified by the key path
        /// and decrypts an encrypted CEK with RSA encryption algorithm.
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key in AKV</param>
        /// <param name="encryptionAlgorithm">Asymmetric Key Encryption Algorithm</param>
        /// <param name="encryptedColumnEncryptionKey">Encrypted Column Encryption Key</param>
        /// <returns>Plain text column encryption key</returns>
        public override byte[] DecryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            // Validate the input parameters
            ValidateNonEmptyAKVPath(masterKeyPath, isSystemOp: true);
            ValidateEncryptionAlgorithm(encryptionAlgorithm, isSystemOp: true);
            ValidateNotNull(encryptedColumnEncryptionKey, nameof(encryptedColumnEncryptionKey));
            ValidateNotEmpty(encryptedColumnEncryptionKey, nameof(encryptedColumnEncryptionKey));
            ValidateVersionByte(encryptedColumnEncryptionKey[0], s_firstVersion[0]);

            // Also validates whether the key is RSA one or not and then get the key size
            KeyCryptographer.AddKey(masterKeyPath);

            int keySizeInBytes = KeyCryptographer.GetKeySize(masterKeyPath);

            // Get key path length
            int currentIndex = s_firstVersion.Length;
            ushort keyPathLength = BitConverter.ToUInt16(encryptedColumnEncryptionKey, currentIndex);
            currentIndex += sizeof(ushort);

            // Get ciphertext length
            ushort cipherTextLength = BitConverter.ToUInt16(encryptedColumnEncryptionKey, currentIndex);
            currentIndex += sizeof(ushort);

            // Skip KeyPath
            // KeyPath exists only for troubleshooting purposes and doesnt need validation.
            currentIndex += keyPathLength;

            // validate the ciphertext length
            if (cipherTextLength != keySizeInBytes)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Strings.InvalidCiphertextLengthTemplate,
                                                            cipherTextLength,
                                                            keySizeInBytes,
                                                            masterKeyPath),
                                            Constants.AeParamEncryptedCek);
            }

            // Validate the signature length
            int signatureLength = encryptedColumnEncryptionKey.Length - currentIndex - cipherTextLength;
            if (signatureLength != keySizeInBytes)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Strings.InvalidSignatureLengthTemplate,
                                                            signatureLength,
                                                            keySizeInBytes,
                                                            masterKeyPath),
                                            Constants.AeParamEncryptedCek);
            }

            // Get ciphertext
            byte[] cipherText = encryptedColumnEncryptionKey.Skip(currentIndex).Take(cipherTextLength).ToArray();
            currentIndex += cipherTextLength;

            // Get signature
            byte[] signature = encryptedColumnEncryptionKey.Skip(currentIndex).Take(signatureLength).ToArray();

            // Compute the hash to validate the signature
            byte[] hash = encryptedColumnEncryptionKey.Take(encryptedColumnEncryptionKey.Length - signatureLength).ToArray();

            if (null == hash)
            {
                throw new CryptographicException(Strings.NullHash);
            }

            if (!KeyCryptographer.VerifyData(hash, signature, masterKeyPath))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Strings.InvalidSignatureTemplate,
                                                            masterKeyPath),
                                            Constants.AeParamEncryptedCek);
            }

            return KeyCryptographer.UnwrapKey(s_keyWrapAlgorithm, cipherText, masterKeyPath);
        }

        /// <summary>
        /// This function uses the asymmetric key specified by the key path
        /// and encrypts CEK with RSA encryption algorithm.
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key in AKV</param>
        /// <param name="encryptionAlgorithm">Asymmetric Key Encryption Algorithm</param>
        /// <param name="columnEncryptionKey">Plain text column encryption key</param>
        /// <returns>Encrypted column encryption key</returns>
        public override byte[] EncryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            // Validate the input parameters
            ValidateNonEmptyAKVPath(masterKeyPath, isSystemOp: true);
            ValidateNotNullOrWhitespace(encryptionAlgorithm, nameof(encryptionAlgorithm));
            ValidateEncryptionAlgorithm(encryptionAlgorithm, isSystemOp: true);
            ValidateNotNull(columnEncryptionKey, nameof(columnEncryptionKey));
            ValidateNotEmpty(columnEncryptionKey, nameof(columnEncryptionKey));

            // Also validates whether the key is RSA one or not and then get the key size
            KeyCryptographer.AddKey(masterKeyPath);
            int keySizeInBytes = KeyCryptographer.GetKeySize(masterKeyPath);

            // Construct the encryptedColumnEncryptionKey
            // Format is 
            //          version + keyPathLength + ciphertextLength + ciphertext + keyPath + signature
            //
            // We currently only support one version
            byte[] version = new byte[] { s_firstVersion[0] };

            // Get the Unicode encoded bytes of cultureinvariant lower case masterKeyPath
            byte[] masterKeyPathBytes = Encoding.Unicode.GetBytes(masterKeyPath.ToLowerInvariant());
            byte[] keyPathLength = BitConverter.GetBytes((short)masterKeyPathBytes.Length);

            // Encrypt the plain text
            byte[] cipherText = KeyCryptographer.WrapKey(s_keyWrapAlgorithm, columnEncryptionKey, masterKeyPath);
            byte[] cipherTextLength = BitConverter.GetBytes((short)cipherText.Length);

            if (cipherText.Length != keySizeInBytes)
            {
                throw new CryptographicException(Strings.CipherTextLengthMismatch);
            }

            // Compute hash
            // SHA-2-256(version + keyPathLength + ciphertextLength + keyPath + ciphertext) 
            byte[] hash = version.Concat(keyPathLength).Concat(cipherTextLength).Concat(masterKeyPathBytes).Concat(cipherText).ToArray();

            // Sign the hash
            byte[] signature = KeyCryptographer.SignData(hash, masterKeyPath);

            if (signature.Length != keySizeInBytes)
            {
                throw new CryptographicException(Strings.HashLengthMismatch);
            }

            ValidateSignature(masterKeyPath, hash, signature);

            return hash.Concat(signature).ToArray();
        }

        #endregion

        #region Private methods


        /// <summary>
        /// Checks if the Azure Key Vault key path is Empty or Null (and raises exception if they are).
        /// </summary>
        internal void ValidateNonEmptyAKVPath(string masterKeyPath, bool isSystemOp)
        {
            // throw appropriate error if masterKeyPath is null or empty
            if (string.IsNullOrWhiteSpace(masterKeyPath))
            {
                string errorMessage = null == masterKeyPath
                                      ? Strings.NullAkvPath
                                      : string.Format(CultureInfo.InvariantCulture, Strings.InvalidAkvPathTemplate, masterKeyPath);

                if (isSystemOp)
                {
                    throw new ArgumentNullException(Constants.AeParamMasterKeyPath, errorMessage);
                }

                throw new ArgumentException(errorMessage, Constants.AeParamMasterKeyPath);
            }


            if (!Uri.TryCreate(masterKeyPath, UriKind.Absolute, out Uri parsedUri))
            {
                // Return an error indicating that the AKV url is invalid.
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Strings.InvalidAkvUrlTemplate, masterKeyPath), Constants.AeParamMasterKeyPath);
            }

            // A valid URI.
            // Check if it is pointing to trusted endpoint.
            foreach (string trustedEndPoint in TrustedEndPoints)
            {
                if (parsedUri.Host.EndsWith(trustedEndPoint, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            // Return an error indicating that the AKV url is invalid.
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Strings.InvalidAkvKeyPathTrustedTemplate, masterKeyPath, string.Join(", ", TrustedEndPoints.ToArray())), Constants.AeParamMasterKeyPath);
        }

        private void ValidateSignature(string masterKeyPath, byte[] message, byte[] signature)
        {
            if (!KeyCryptographer.VerifyData(message, signature, masterKeyPath))
            {
                throw new CryptographicException(Strings.InvalidSignature);
            }
        }

        private byte[] CompileMasterKeyMetadata(string masterKeyPath, bool allowEnclaveComputations)
        {
            string masterkeyMetadata = ProviderName + masterKeyPath + allowEnclaveComputations;
            return Encoding.Unicode.GetBytes(masterkeyMetadata.ToLowerInvariant());
        }

        #endregion
    }

    /// <summary>
    /// The authentication callback delegate which is to be implemented by the client code
    /// </summary>
    /// <param name="authority"> Identifier of the authority, a URL. </param>
    /// <param name="resource"> Identifier of the target resource that is the recipient of the requested token, a URL. </param>
    /// <param name="scope"> The scope of the authentication request. </param>
    /// <returns> access token </returns>
    public delegate Task<string> AuthenticationCallback(string authority, string resource, string scope);
}
