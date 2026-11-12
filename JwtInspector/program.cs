using System;
using System.Text;

namespace JwtInspector
{
    class Program
    {
        public static string DecodeBase64Url(string base64Url)
        {
            if (string.IsNullOrWhiteSpace(base64Url))
            {
                return string.Empty;
            }

            string base64 = base64Url.Replace('-', '+').Replace('_', '/');

            int remainder = base64.Length % 4;
            if (remainder > 0)
            {
                base64 = base64.PadRight(base64.Length + (4 - remainder), '=');
            }

            try
            {
                byte[] bytes = Convert.FromBase64String(base64);

                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return string.Empty;
            }
        }

        public static (string headerJson, string payloadJson, string status, long exp) CheckJwt(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return (string.Empty, string.Empty, "INVALID", 0);
            }

            string[] parts = token.Split('.');
            if (parts.Length != 3)
            {
                return (string.Empty, string.Empty, "INVALID", 0);
            }

            string headerJson = DecodeBase64Url(parts[0]);
            if (string.IsNullOrEmpty(headerJson))
            {
                return (string.Empty, string.Empty, "INVALID", 0);
            }

            string payloadJson = DecodeBase64Url(parts[1]);
            if (string.IsNullOrEmpty(payloadJson))
            {
                return (string.Empty, string.Empty, "INVALID", 0);
            }

            if (headerJson.ToLower().Contains("\"alg\":\"none\""))
            {
                return (headerJson, payloadJson, "ALG_NONE", 0);
            }

            string expKey = "\"exp\":";
            int expIndex = payloadJson.IndexOf(expKey, StringComparison.Ordinal);
            if (expIndex == -1)
            {
                return (headerJson, payloadJson, "NO_EXP", 0);
            }

            int startIndex = expIndex + expKey.Length;
            while (startIndex < payloadJson.Length && char.IsWhiteSpace(payloadJson[startIndex]))
            {
                startIndex++;
            }

            int endIndex = startIndex;
            while (endIndex < payloadJson.Length && (char.IsDigit(payloadJson[endIndex]) || payloadJson[endIndex] == '-'))
            {
                endIndex++;
            }

            string expString = payloadJson.Substring(startIndex, endIndex - startIndex);
            if (!long.TryParse(expString, out long exp))
            {
                return (string.Empty, string.Empty, "INVALID", 0);
            }

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (exp < now)
            {
                return (headerJson, payloadJson, "EXPIRED", exp);
            }

            return (headerJson, payloadJson, "VALID", exp);
        }

        public static string GetRiskLevel(string status)
        {
            if (status == "ALG_NONE")
            {
                return "CRITICAL";
            }

            if (status == "INVALID" || status == "EXPIRED")
            {
                return "HIGH";
            }

            if (status == "NO_EXP")
            {
                return "MEDIUM";
            }

            return "LOW";
        }

        public static void Main(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("Usage: dotnet run -- <token>");
                return;
            }

            string token = args[0];

            var result = CheckJwt(token);

            string risk = GetRiskLevel(result.status);

            Console.WriteLine($"Token: {token}");
            Console.WriteLine($"Header: {result.headerJson}");
            Console.WriteLine($"Payload: {result.payloadJson}");
            Console.WriteLine($"Exp: {result.exp}");
            Console.WriteLine($"Status: {result.status}");
            Console.WriteLine($"Risk: {risk}");

            return;
        }
    }
}