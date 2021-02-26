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

        [Fact]
        [Trait("Category", "Public")]
        public async Task BlockUnauthorizedAccessManagerData()
        {
            var apiResponse = await _apiClient.GetAsync("https://localhost:5001/content/manager");

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", "Public")]
        public async Task BlockUnauthorizedAccessEmployeeData()
        {
            var apiResponse = await _apiClient.GetAsync("https://localhost:5001/content/employee");

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", "Public")]
        public async Task BlockUnauthorizedAccessAuthenticatedData()
        {
            var apiResponse = await _apiClient.GetAsync("https://localhost:5001/content/authenticated");

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

        [Fact]
        [Trait("Category", "Authorized")]
        public async Task LoginWithSuccess()
        {
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);
        }

        [Fact]
        [Trait("Category", "Authorized")]
        public async Task EmployeeAccessPublicData()
        {
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            _apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await _apiClient.GetAsync("https://localhost:5001/content/public");

            Assert.True(apiResponse.IsSuccessStatusCode);

        }

        [Fact]
        [Trait("Category", "Authorized")]
        public async Task EmployeeAccessEmployeeData()
        {
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            _apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await _apiClient.GetAsync("https://localhost:5001/content/employee");

            Assert.True(apiResponse.IsSuccessStatusCode);
        }

        [Fact]
        [Trait("Category", "Authorized")]
        public async Task EmployeeAccessManagerData()
        {
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            _apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await _apiClient.GetAsync("https://localhost:5001/content/manager");

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Forbidden);
        }
        [Fact]
        [Trait("Category", "Authorized")]
        public async Task EmployeeAccessAuthenticatedData()
        {
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await _apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            _apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await _apiClient.GetAsync("https://localhost:5001/content/authenticated");

            Assert.True(apiResponse.IsSuccessStatusCode);
        }

        // Test multiple logins

    }
}
