using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Helpers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    public AuthController(
        UserManager<User> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var (isValidUsername, usernameError) = RequestHelpers.ValidateUsername(request.Username);
        if (!isValidUsername)
            return BadRequest(new { error = usernameError });

        var (isValidEmail, emailError) = RequestHelpers.ValidateEmail(request.Email);
        if (!isValidEmail)
            return BadRequest(new { error = emailError });

        var (isValidPassword, passwordError) = RequestHelpers.ValidatePassword(request.Password);
        if (!isValidPassword)
            return BadRequest(new { error = passwordError });

        var sanitizedUsername = RequestHelpers.SanitizeInput(request.Username);
        var sanitizedEmail = RequestHelpers.SanitizeInput(request.Email);

        var user = new User
        {
            UserName = sanitizedUsername,
            Email = sanitizedEmail
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        var roleName = request.IsAdmin ? "Admin" : "User";
        if (!await _roleManager.RoleExistsAsync(roleName))
            await _roleManager.CreateAsync(new IdentityRole(roleName));

        await _userManager.AddToRoleAsync(user, roleName);
        var token = await GenerateJwtToken(user);

        return Ok(new { token, message = $"Registration successful as {roleName}" });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto request)
    {
        var (isValidUsername, usernameError) = RequestHelpers.ValidateUsername(request.Username);
        if (!isValidUsername)
            return BadRequest(new { error = usernameError });

        var sanitizedUsername = RequestHelpers.SanitizeInput(request.Username);
        var user = await _userManager.FindByNameAsync(sanitizedUsername);

        if (user == null)
            return Unauthorized(new { error = "Invalid username or password" });

        var isValidPassword = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!isValidPassword)
        {
            await _userManager.AccessFailedAsync(user);
            return Unauthorized(new { error = "Invalid username or password" });
        }

        if (await _userManager.IsLockedOutAsync(user))
            return Unauthorized(new { error = "Account is locked. Please try again later." });

        await _userManager.ResetAccessFailedCountAsync(user);
        var token = await GenerateJwtToken(user);
        return Ok(new { token, message = "Login successful" });
    }

    [HttpGet("users")]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetAllUsers()
    {
        var users = await _userManager.Users
            .Select(u => new UserDto
            {
                Id = u.Id,
                Username = u.UserName ?? string.Empty,
                Email = u.Email ?? string.Empty
            })
            .ToListAsync();

        return Ok(users);
    }

    [HttpGet("profile")]
    [Authorize]
    public async Task<ActionResult<UserDto>> GetProfile()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
            return NotFound(new { error = "User identity not found" });

        var user = await _userManager.FindByNameAsync(username);
        if (user == null)
            return NotFound(new { error = "User not found" });

        return Ok(new UserDto
        {
            Id = user.Id,
            Username = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty
        });
    }

    private async Task<string> GenerateJwtToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ??
            throw new InvalidOperationException("JWT Key not found in configuration")));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddHours(Convert.ToDouble(
            _configuration["Jwt:ExpirationHours"] ?? "24"));

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: expires,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}