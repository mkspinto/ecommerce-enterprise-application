using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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

        //Constructor
        public AuthController(SignInManager<IdentityUser> signinManager, UserManager<IdentityUser> userManager)
        {
            __signinManager = signinManager;
            __userManager = userManager;
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
                return Ok();
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
                return Ok();
            }

            return BadRequest();
        }
    }
}
