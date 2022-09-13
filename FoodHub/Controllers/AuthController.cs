using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FoodHub.Models;
using FoodHub.Data;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthController(
            SignInManager<User> signInManager,
            UserManager<User> userManager,
            ApplicationDbContext dbContext,
            IConfiguration configuration,
            RoleManager<IdentityRole> roleManager
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = dbContext;
            _configuration = configuration;
            _roleManager = roleManager;
        }



        [HttpPost]
        public async Task<ActionResult<UserDto>> PostUser(RegisterUserDto data)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            if (
                (Enum.GetNames(typeof(UserRoles)).Length - 2) < data.Role
                )
            {
                return BadRequest(new
                {
                    Status = false,
                    Message = "Please choose a valid role number"
                });
            }

            if (await _userManager.FindByEmailAsync(data.Email) != null)
            {
                return BadRequest(new
                {
                    Status = false,
                    Message = "The user with this Email already exist"
                });
            }

            //User user = data.MakeUserObject();
            //User user = (UserRoles)data.Role switch
            //{
            //    UserRoles.Accountant => new Accountant(),
            //    UserRoles.Cashier => new Cashier(),
            //    UserRoles.Waiter => new Waiter(),
            //    UserRoles.Chef => new Chef(),
            //    UserRoles.Delivery => new Delivery(),
            //    UserRoles.Supplier => new Supplier(),
            //    UserRoles.Customer => new Customer(),
            //    UserRoles.Admin => new Admin(),
            //    _ => new User(),
            //};

            data.Role = data.Role == 0 ? data.Role + 1 : data.Role;

            string role = ((UserRoles)data.Role).ToString();

            var roleExist = await _roleManager.RoleExistsAsync(role);
            if (!roleExist)
            {
                //create the roles and seed them to the database: Question 1
                await _roleManager.CreateAsync(new IdentityRole(role));
            }

            User user = new()
            {
                Name = $"{data.FirstName} {data.MiddleName} {data.LastName}",
                UserName = data.UserName,
                Email = data.Email,
                PhoneNumber = data.PhoneNumber,
                EmailConfirmed = true
            };
            var createPowerUser = await _userManager.CreateAsync(user, data.Password);
            if (createPowerUser.Succeeded)
            {
                //here we tie the new user to the role
                await _userManager.AddToRoleAsync(user, role);
            }

            return CreatedAtAction("GetUser", new { id = user.Id }, user);
        }

        [HttpGet]
        public  ActionResult<IEnumerable<Object>> GetAllRoles()
        {
            var code = (int)(Enum.Parse(typeof(UserRoles), "Visitor"));
            var roles = _roleManager.Roles.Where(x => x.Name == "Client" || x.Name == "Visitor").Select(x=> new
            {
                
                role = x.Name
            }).ToList();
            var data = new List<Object>();
            foreach(var x in roles)
            {
                data.Add(new { });
            }
            return roles;
        }

        // Login Api + methods
        [AllowAnonymous]
        [HttpPost("token")]
        public async Task<IActionResult> Token(TokenRequestDTO tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(tokenRequest.Email);
                if (user != null)
                {
                    var result = await _signInManager.CheckPasswordSignInAsync(user, tokenRequest.Password, false);
                    if (result.Succeeded)
                    {
                        string token = await JwtGeneration(user.Email);
                        string refresh = RefreshTokenGeneration();
                        user.RefreshToken = refresh;
                        //TODO: case: RefreshTokenExpireDate
                        //user.CreatedDate = DateTime.UtcNow.AddDays(7); 
                        await _userManager.UpdateAsync(user);
                        return Ok(new TokenResponse()
                        {
                            Token = token,
                            Status = "Authenticated",
                            RefreshToken = refresh
                        });
                    }
                    else
                    {
                        return BadRequest(new TokenResponse()
                        {
                            Token = null,
                            Status = "Wrong Email or Password",
                            RefreshToken = null,
                        });
                    }
                }
                else
                {
                    return BadRequest(new TokenResponse()
                    {
                        Token = null,
                        Status = "Wrong Email or Password",
                        RefreshToken = null,
                    });
                }
            }
            else
            {
                return BadRequest(new TokenResponse()
                {
                    Token = null,
                    Status = "Failed",
                    RefreshToken = null,
                });
            }

        }


        // Refresh token Api + methods
        [AllowAnonymous]
        [HttpPost("token/refresh")]
        public async Task<IActionResult> RefreshToken(RefreshTokenReqDTO RefreshModel)
        {
            try
            {
                var user = _context.Users.Where(
                    U => U.RefreshToken == RefreshModel.RefreshToken
                    ).FirstOrDefault();

                // TODO: IF we want to validate refresh token expiry date ->
                // add this(|| user.CreatedDate < DateTime.UtcNow) + remove comment
                // from case: RefreshTokenExpireDate
                if ((user == null))
                {
                    return BadRequest(new TokenResponse()
                    {
                        Token = null,
                        Status = "Login required",
                        RefreshToken = null,
                    });
                }
                else
                {
                    var output = GetInfoJwtToken(RefreshModel.Token);
                    var token = GenerateAccessToken(output.Claims);
                    var refreshToken = RefreshTokenGeneration();
                    user.RefreshToken = refreshToken;
                    await _userManager.UpdateAsync(user);

                    return Ok(new TokenResponse()
                    {
                        Token = token,
                        Status = "Authenticated",
                        RefreshToken = refreshToken,
                    });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new TokenResponse()
                {
                    Token = null,
                    Status = ex.Message,
                    RefreshToken = null,
                });
            }

        }


        private async Task<string> JwtGeneration(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var roles = await _userManager.GetRolesAsync(user);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var tokenDes = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Iss, _configuration["Jwt:Issuer"].ToString()),
                    new Claim(JwtRegisteredClaimNames.Aud, _configuration["Jwt:Audience"].ToString()),
                    new Claim("uid", user.Id)
                }),
                Expires = DateTime.UtcNow.AddHours(6),
                SigningCredentials = signingCredentials
            };

            tokenDes.Subject.AddClaims(roles.Select(role => new Claim(ClaimsIdentity.DefaultRoleClaimType, role)));
            var token = jwtTokenHandler.CreateToken(tokenDes);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            return jwtToken;
        }

        private string RefreshTokenGeneration()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetInfoJwtToken(string JwtToken)
        {
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = symmetricSecurityKey,
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(JwtToken, tokenValidationParameters, out SecurityToken securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principal;
        }

        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
            var InputClaims = new ClaimsIdentity();
            foreach (var claim in claims)
            {
                InputClaims.AddClaim(claim);
            }

            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var tokenDes = new SecurityTokenDescriptor
            {
                Subject = InputClaims,
                Expires = DateTime.UtcNow.AddHours(6),
                SigningCredentials = signinCredentials

            };
            var token = jwtTokenHandler.CreateToken(tokenDes);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            return jwtToken;
        }
    }

    public class TokenRequestDTO
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = null!;
        [Required]
        [MinLength(8)]
        public string Password { get; set; } = null!;
    }

    public class TokenResponse
    {
        public string? Token { get; set; }
        public string Status { get; set; } = null!;
        public string? RefreshToken { get; set; }
    }

    public class RefreshTokenReqDTO
    {
        [Required]
        public string Token { get; set; } = null!;
        [Required]
        public string RefreshToken { get; set; } = null!;
    }
}
