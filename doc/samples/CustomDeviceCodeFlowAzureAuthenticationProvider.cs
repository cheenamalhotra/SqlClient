﻿//<Snippet1>
using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Data.SqlClient;

namespace CustomAuthenticationProviderExamples
{
    /// <summary>
    /// Example demonstrating creating custom device code flow authentication provider and attaching it with the driver.
    /// This is helpful for applications that wish to override Callback of Device Code Result as implemented by SqlClient driver.
    /// </summary>
    public class CustomDeviceCodeFlowAzureAuthenticationProvider : SqlAuthenticationProvider
    {
        public async override Task<SqlAuthenticationToken> AcquireTokenAsync(SqlAuthenticationParameters parameters)
        {
            string clientId = "my-client-id";
            string clientName = "My Application Name";
            string s_defaultScopeSuffix = "/.default";

            string[] scopes = new string[] { parameters.Resource.EndsWith(s_defaultScopeSuffix) ? parameters.Resource : parameters.Resource + s_defaultScopeSuffix };

            IPublicClientApplication app = PublicClientApplicationBuilder.Create(clientId)
                .WithAuthority(parameters.Authority)
                .WithClientName(clientName)
                .WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient")
                .Build();

            AuthenticationResult result = await app.AcquireTokenWithDeviceCode(scopes,
                    deviceCodeResult => CustomDeviceFlowCallback(deviceCodeResult)).ExecuteAsync();
            return new SqlAuthenticationToken(result.AccessToken, result.ExpiresOn);
        }

        public override bool IsSupported(SqlAuthenticationMethod authenticationMethod)
        {
            if (authenticationMethod.Equals(SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow))
            {
                return true;
            }
            return false;
        }

        private Task CustomDeviceFlowCallback(DeviceCodeResult result)
        {
            Console.WriteLine(result.Message);
            return Task.FromResult(0);
        }
    }

    public class Program
    {
        public static void Main()
        {
            SqlAuthenticationProvider.SetProvider(SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow, new CustomDeviceCodeFlowAzureAuthenticationProvider());
            using (SqlConnection sqlConnection = new SqlConnection("Server=<myserver>.database.windows.net;Authentication=Active Directory Device Code Flow;Database=<db>;"))
            {
                sqlConnection.Open();
                Console.WriteLine("Connected successfully!");
            }
        }
    }
}
//</Snippet1>
