using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API;

public class AccountController : BaseApiController
{
    private readonly DataContext _dataContext;
    private readonly ITokenService _tokenService;

    public AccountController(DataContext dataContext, ITokenService tokenService)
    {
        _dataContext = dataContext;
        _tokenService = tokenService;
    }

    [HttpPost("register")] // POST api/account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if(await UserExists(registerDto.Username))
        {
            return BadRequest("Username is taken.");
        }

        using HMACSHA512 hmac = new();

        var user = new AppUser
        {
            Username = registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        _dataContext.Users.Add(user);
        await _dataContext.SaveChangesAsync();

        return new UserDto
        {
            Username = user.Username,
            Token = _tokenService.CreateToken(user)
        };
    }

    [HttpPost("login")] // POST api/account/login
    public async Task<ActionResult<UserDto>> Login (LoginDto loginDto)
    {
        AppUser user = await _dataContext.Users.SingleOrDefaultAsync(u => u.Username == loginDto.Username);

        if(user == null)
        {
            return Unauthorized();
        }

        using HMACSHA512 hmac = new(user.PasswordSalt);

        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (int i = 0; i < computedHash.Length; i++)
        {
            if(computedHash[i] != user.PasswordHash[i])
            {
                return Unauthorized("Invalid password.");
            }
        }

        return new UserDto
        {
            Username = user.Username,
            Token = _tokenService.CreateToken(user)
        };
    }

    private async Task<bool> UserExists(string username)
    {
        return await _dataContext.Users.AnyAsync(u => u.Username == username.ToLower());
    }
}
