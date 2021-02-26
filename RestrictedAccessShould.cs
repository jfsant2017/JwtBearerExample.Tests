using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace JwtBearerExample.Tests
{
    public class RestrictedAccessShould
    {
        [Fact]
        public async Task AllowAccessPublicData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var apiResponse = await apiClient.GetAsync("https://localhost:5001");

            Assert.True(apiResponse.IsSuccessStatusCode);

            var stringResponse = await apiResponse.Content.ReadAsStringAsync();

            Assert.Contains("Initial data configured", stringResponse);
        }

        [Fact]
        public async Task BlockUnauthorizedAccessManagerData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var apiResponse = await apiClient.GetAsync("https://localhost:5001/content/manager");

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task BlockUnauthorizedAccessEmployeeData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var apiResponse = await apiClient.GetAsync("https://localhost:5001/content/employee");

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task BlockUnauthorizedAccessAuthenticatedData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var apiResponse = await apiClient.GetAsync("https://localhost:5001/content/authenticated");

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task RefuseInvalidUserPassword()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var loginData = new {
                login = "user_1",
                password = "65432"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.StatusCode == HttpStatusCode.NotFound);
        }

        [Fact]
        public async Task LoginWithSuccess()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);
        }

        [Fact]
        public async Task EmployeeAccessPublicData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await apiClient.GetAsync("https://localhost:5001/content/public");

            Assert.True(apiResponse.IsSuccessStatusCode);

        }

        [Fact]
        public async Task EmployeeAccessEmployeeData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await apiClient.GetAsync("https://localhost:5001/content/employee");

            Assert.True(apiResponse.IsSuccessStatusCode);
        }

        [Fact]
        public async Task EmployeeAccessManagerData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await apiClient.GetAsync("https://localhost:5001/content/manager");

            Assert.True(apiResponse.StatusCode == HttpStatusCode.Forbidden);
        }
        [Fact]
        public async Task EmployeeAccessAuthenticatedData()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };

            var apiClient = new HttpClient(clientHandler);
            var loginData = new {
                login = "user_1",
                password = "654321"
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");

            var apiResponse = await apiClient.PostAsync("https://localhost:5001/user/login", content);

            Assert.True(apiResponse.IsSuccessStatusCode);

            var response = await apiResponse.Content.ReadAsStringAsync();

            dynamic authData = JObject.Parse(response);
            string token =  (string)authData["token"];

            apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            apiResponse = await apiClient.GetAsync("https://localhost:5001/content/authenticated");

            Assert.True(apiResponse.IsSuccessStatusCode);
        }
    }
}
