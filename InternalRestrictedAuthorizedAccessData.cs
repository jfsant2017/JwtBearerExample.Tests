using System.Collections.Generic;

namespace JwtBearerExample.Tests
{
    public class InternalRestrictedAuthorizedAccessData
    {
        private static readonly List<object[]> Data = new List<object[]>
        {
                new object[] { "user_1", "654321", "https://localhost:5001/content/public" },
                new object[] { "user_1", "654321", "https://localhost:5001/content/employee" },
                new object[] { "user_1", "654321", "https://localhost:5001/content/authenticated" },
                new object[] { "manager_1", "123456", "https://localhost:5001/content/public" },
                new object[] { "manager_1", "123456", "https://localhost:5001/content/manager" },
                new object[] { "manager_1", "123456", "https://localhost:5001/content/authenticated" }
        };

        public static IEnumerable<object[]> AuthorizedData => Data;
    }
}
