using NUnit.Framework;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Net;

namespace AuthApiTests
{
    [TestFixture]
    // Add OrderAttribute to ensure tests run in sequence
    [Order(1)]
    public class AuthTests
    {
        private static HttpClient _client;
        private const string BaseUrl = "http://localhost:5200";

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            _client = new HttpClient();
        }

        private async Task<HttpResponseMessage> PostAsync(string path, object body)
        {
            var json = JsonConvert.SerializeObject(body);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            return await _client.PostAsync($"{BaseUrl}{path}", content);
        }

        private async Task<HttpResponseMessage> GetAsync(string path, string token = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"{BaseUrl}{path}");
            if (!string.IsNullOrEmpty(token))
                request.Headers.Add("Authorization", $"Bearer {token}");

            return await _client.SendAsync(request);
        }

        [Test]
        [Order(1)]
        public async Task Register_ValidUser_ShouldSucceed()
        {
            // Ensure consistent test user
            var response = await PostAsync("/api/auth/register", new
            {
                username = "testuser1",
                email = "test1@example.com",
                password = "SecurePass123!@#"
            });

            // It might return BadRequest if user already exists
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK).Or.EqualTo(HttpStatusCode.BadRequest));

            // If BadRequest, check if it's because user exists
            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                var content = await response.Content.ReadAsStringAsync();
                Assert.That(content, Does.Contain("already exists").Or.Contain("already registered").IgnoreCase);
            }
        }

        [Test]
        [Order(2)]
        public async Task Login_ValidUser_ShouldReturnToken()
        {
            var response = await PostAsync("/api/auth/login", new
            {
                username = "testuser1",
                password = "SecurePass123!@#"
            });

            var body = await response.Content.ReadAsStringAsync();
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Contain("token"));
        }

        [Test]
        [Order(3)]
        public async Task Register_WeakPassword_ShouldFail()
        {
            var response = await PostAsync("/api/auth/register", new
            {
                username = "testuser2",
                email = "test2@example.com",
                password = "weak"
            });

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [Test]
        [Order(4)]
        public async Task Register_InvalidEmail_ShouldFail()
        {
            var response = await PostAsync("/api/auth/register", new
            {
                username = "testuser3",
                email = "invalid-email",
                password = "SecurePass123!@#"
            });

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [Test]
        [Order(5)]
        public async Task Register_InvalidUsername_ShouldFail()
        {
            var response = await PostAsync("/api/auth/register", new
            {
                username = "t@",
                email = "test3@example.com",
                password = "SecurePass123!@#"
            });

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [Test]
        [Order(6)]
        public async Task Login_InvalidPassword_ShouldFail()
        {
            var response = await PostAsync("/api/auth/login", new
            {
                username = "testuser1",
                password = "WrongPassword123!@#"
            });

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        [Test]
        [Order(7)]
        public async Task Register_SQLInjection_ShouldFail()
        {
            var response = await PostAsync("/api/auth/register", new
            {
                username = "admin' OR '1'='1",
                email = "sql1@test.com",
                password = "SecurePass123!@#"
            });

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [Test]
        [Order(8)]
        public async Task Register_XSSInjection_ShouldFail()
        {
            var response = await PostAsync("/api/auth/register", new
            {
                username = "<script>alert('xss')</script>",
                email = "xss1@test.com",
                password = "SecurePass123!@#"
            });

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            _client.Dispose();
        }
    }
}