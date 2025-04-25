using System.Text.RegularExpressions;
using System.Web;

namespace SafeVault.Helpers;

public static class RequestHelpers
{
    private const int MinPasswordLength = 12;
    private const int MaxPasswordLength = 128;
    private const int MinUsernameLength = 3;
    private const int MaxUsernameLength = 50;

    private static readonly string[] SuspiciousPatterns = new[]
    {
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "alert(",
        "eval(",
        "document.cookie",
        "window.location",
        "<img",
        "<iframe",
        "data:",
        "&#",
        "&lt;",
        "&gt;",
        "/*",
        "*/",
        "--",
        ";--",
        "/*--",
        "//--",
        "union select",
        "exec(",
        "execute(",
        "concat(",
        "group_concat"
    };

    public static (bool isValid, string error) ValidateUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return (false, "Username cannot be empty");

        if (username.Length < MinUsernameLength || username.Length > MaxUsernameLength)
            return (false, $"Username must be between {MinUsernameLength} and {MaxUsernameLength} characters");

        if (!Regex.IsMatch(username, "^[a-zA-Z0-9_]+$"))
            return (false, "Username can only contain letters, numbers, and underscores");

        if (ContainsSuspiciousPatterns(username))
            return (false, "Username contains potentially malicious content");

        return (true, null);
    }

    public static (bool isValid, string error) ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return (false, "Email cannot be empty");

        email = Regex.Replace(email, @"[^\w\@\.\-]", "");

        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            if (email.Contains('<') || email.Contains('>') || email.Contains('"') || email.Contains('\''))
                return (false, "Email contains invalid characters");

            if (addr.Address != email)
                return (false, "Invalid email format");

            if (ContainsSuspiciousPatterns(email))
                return (false, "Email contains potentially malicious content");

            return (true, null);
        }
        catch
        {
            return (false, "Invalid email format");
        }
    }

    public static (bool isValid, string error) ValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            return (false, "Password cannot be empty");

        if (password.Length < MinPasswordLength || password.Length > MaxPasswordLength)
            return (false, $"Password must be between {MinPasswordLength} and {MaxPasswordLength} characters");

        var hasUppercase = Regex.IsMatch(password, "[A-Z]");
        var hasLowercase = Regex.IsMatch(password, "[a-z]");
        var hasDigit = Regex.IsMatch(password, "[0-9]");
        var hasSpecialChar = Regex.IsMatch(password, "[^A-Za-z0-9]");

        if (!hasUppercase || !hasLowercase || !hasDigit || !hasSpecialChar)
            return (false, "Password must contain uppercase, lowercase, numbers, and special characters");

        return (true, null);
    }

    public static string SanitizeInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        return HttpUtility.HtmlEncode(input.Trim());
    }

    private static bool ContainsSuspiciousPatterns(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        var lowerInput = input.ToLowerInvariant();
        return SuspiciousPatterns.Any(pattern => lowerInput.Contains(pattern.ToLowerInvariant()));
    }
}