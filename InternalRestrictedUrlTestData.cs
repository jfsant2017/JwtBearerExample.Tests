using System.Collections.Generic;

namespace JwtBearerExample.Tests
{
    public class InternalRestrictedUrlTestData
    {
        private static readonly List<object[]> Data = new List<object[]>
        {
                new object[] { "https://localhost:5001/content/manager" },
                new object[] { "https://localhost:5001/content/employee" },
                new object[] { "https://localhost:5001/content/authenticated" }
        };

        public static IEnumerable<object[]> TestData => Data;
    }
}