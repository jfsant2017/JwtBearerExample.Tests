using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using Xunit.Abstractions;

namespace JwtBearerExample.Tests
{
    public class RestrictedAccessShould: IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly HttpClient _apiClient;        

        public RestrictedAccessShould(ITestOutputHelper output)
        {
            _output = output;
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };
            _apiClient = new HttpClient(clientHandler);
        }

        public void Dispose()
        {
            _output.WriteLine($"Disposing api client");
            _apiClient.Dispose();
        }

        [Fact]
        [Trait("Category", "Public")]
        public async Task AllowAccessPublicData()
        {
            var apiResponse = await _apiClient.GetAsync("https://localhost:5001");

            Assert.True(apiResponse.IsSuccessStatusCode);
            _output.WriteLine($"AllowAccessPublicData - Status code: {apiResponse.StatusCode}");

            var stringResponse = await apiResponse.Content.ReadAsStringAsync();

            Assert.Contains("Initial data configured", stringResponse);
        }

        [Theory]
        [Trait("Category", "Public")]
        [MemberData(nameof(InternalRestrictedUrlTestData.TestData), MemberType = typeof(InternalRestrictedUrlTestData))]
        public async Task BlockUnauthorizedAccess(string uri)
        {
            var apiResponse = await _apiClient.GetAsync(uri);

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", "Login")]
        public async Task RefuseInvalidUserPassword()
        {
            var loginData = new {
                login = "user_1",
                password = "65432"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.StatusCode == HttpStatusCode.NotFound);
        }

        [Theory]
        [Trait("Category", "Authorized")]
        [InlineData("user_1", "654321")]
        [InlineData("manager_1", "123456")]
        public async Task LoginWithSuccess(string user, string password)
        {
            var loginData = new {
                login = user,
                password = password
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);
        }

        [Theory]
        [Trait("Category", "Forbidden")]
        [InlineData("user_1", "654321", "https://localhost:5001/content/manager")]
        [InlineData("manager_1", "123456", "https://localhost:5001/content/employee")]
        public async Task ForbiddenAccessAuthenticatedData(string user, string password, string url)
        {
            var loginData = new {
                login = user,
                password = password
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            _apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await _apiClient.GetAsync(url);

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Forbidden);
        }

        [Theory]
        [Trait("Category", "Authorized")]
        [MemberData(nameof(InternalRestrictedAuthorizedAccessData.AuthorizedData), MemberType = typeof(InternalRestrictedAuthorizedAccessData))]
        public async Task AllowedAccessAuthenticatedData(string user, string password, string url)
        {
            var loginData = new {
                login = user,
                password = password
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            _apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await _apiClient.GetAsync(url);

            Assert.True(apiResponse.IsSuccessStatusCode);
        }

    }
}
