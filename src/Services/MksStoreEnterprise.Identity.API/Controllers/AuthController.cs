using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MksStoreEnterprise.Identity.API.Extensions;
using System;
using System.Linq;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using static MksStoreEnterprise.Identity.API.Models.UserViewModels;

namespace MksStoreEnterprise.Identity.API.Controllers
{
    [ApiController]
    [Route("api/identity")]
    public class AuthController : Controller
    {
        //Global
        private readonly SignInManager<IdentityUser> __signinManager;
        private readonly UserManager<IdentityUser> __userManager;
        private readonly AppSettings __appSettings;

        //Constructor
        public AuthController(SignInManager<IdentityUser> signinManager, UserManager<IdentityUser> userManager, IOptions<AppSettings> appSettings)
        {
            __signinManager = signinManager;
            __userManager = userManager;
            __appSettings = appSettings.Value;
        }

        //Methods
        [HttpPost("newAccount")]
        public async Task<ActionResult> Register(UserRegistry _userRegistry)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            IdentityUser user = new IdentityUser
            {
                UserName = _userRegistry.email,
                Email = _userRegistry.email,
                EmailConfirmed = true
            };

            IdentityResult result = await __userManager.CreateAsync(user, _userRegistry.password);
            if (result.Succeeded)
            {
                await __signinManager.SignInAsync(user, false);
                return Ok(
                     await this.GenerateJWT(_userRegistry.email)
                );
            }

            return BadRequest();
        }

        [HttpPost("authenticate")]
        public async Task<ActionResult> Login(UserLogin _userLogin)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var result = await __signinManager.PasswordSignInAsync(_userLogin.email, _userLogin.password, false, true);
            if (result.Succeeded)
            {
                return Ok(
                    await this.GenerateJWT(_userLogin.email)
                );
            }

            return BadRequest();
        }

        [NonAction]
        public async Task<UserResponseLogin> GenerateJWT(string _email)
        {
            IdentityUser user = await __userManager.FindByEmailAsync(_email);
            IList<Claim> claims = await __userManager.GetClaimsAsync(user);
            IList<string> roles = await __userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

            foreach (string userRole in roles)
            {
                claims.Add(new Claim("role", userRole));
            }

            ClaimsIdentity identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.ASCII.GetBytes(__appSettings.Secret);

            SecurityToken token = tokenHandler.CreateToken(new SecurityTokenDescriptor { 
                Issuer = __appSettings.Emitter,
                Audience = __appSettings.ValidAt,
                Subject = identityClaims,
                Expires = DateTime.UtcNow.AddHours(__appSettings.ExpirationHours),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            });

            string encodedToken = tokenHandler.WriteToken(token);
            UserResponseLogin response = new UserResponseLogin()
            {
                AccessToken = encodedToken,
                ExpiresIn = TimeSpan.FromHours(__appSettings.ExpirationHours).TotalSeconds,
                UserToken = new UserToken()
                {
                    Id = user.Id,
                    Email = user.Email,
                    Claims = claims.Select(w => new UserClaim {
                        Type = w.Type,
                        Value = w.Value
                    })
                }
            };

            return response;
        }

        [NonAction]
        private static long ToUnixEpochDate(DateTime _date)
        => (long)Math.Round((_date.ToUniversalTime() - new DateTimeOffset(170, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalMilliseconds);
    }
}