using Clients;
using IdentityModel;
using IdentityModel.Client;
using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;

namespace ConsoleMTLSClient
{
    public class Program
    {
        public static async Task Main()
        {
            Console.Title = "Console mTLS Client";

            var response = await RequestTokenAsync();
            response.Show();

            Console.ReadLine();
            await CallServiceAsync(response.AccessToken);
        }

        static async Task<TokenResponse> RequestTokenAsync()
        {
            var client = new HttpClient(GetHandler());

            var disco = await client.GetDiscoveryDocumentAsync("https://identityserver.local");
            if (disco.IsError) throw new Exception(disco.Error);

            var endpoint = disco
                    .TryGetValue(OidcConstants.Discovery.MtlsEndpointAliases)
                    .TryGetValue(OidcConstants.Discovery.TokenEndpoint)
                    .GetString();
            
            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = endpoint,

                ClientId = "mtls",
                Scope = "resource1.scope1"
            });

            if (response.IsError) throw new Exception(response.Error);
            return response;
        }

        static async Task CallServiceAsync(string token)
        {
            var client = new HttpClient(GetHandler())
            {
                BaseAddress = new Uri(Constants.SampleApi)
            };

            client.SetBearerToken(token);
            var response = await client.GetStringAsync("identity");

            "\n\nService claims:".ConsoleGreen();
            Console.WriteLine(JsonDocument.Parse(response));
        }

        static SocketsHttpHandler GetHandler()
        {
            var handler = new SocketsHttpHandler();
            
            var cert = new X509Certificate2("client.p12", "changeit");
            handler.SslOptions.ClientCertificates = new X509CertificateCollection { cert };

            return handler;
        }
    }
}