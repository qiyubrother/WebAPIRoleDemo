using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

using Microsoft.Extensions.Caching.Distributed;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WebAPIRoleDemo;

namespace jwtRoleDemo.Controllers
{
    [EnableCors("AllowCors"), Route("api/[controller]")]
    public class LoginController : Controller
    {
        private readonly JwtIssuerOptions _jwtOptions;
        private readonly ILogger _logger;
        private readonly IDistributedCache _distributedCache;
        //private readonly JsonSerializerSettings _serializerSettings;
        public LoginController(IOptions<JwtIssuerOptions> jwtOptions, ILoggerFactory loggerFactory, IDistributedCache distributedCache)
        {
            _jwtOptions = jwtOptions.Value;
            ThrowIfInvalidOptions(_jwtOptions);

            _logger = loggerFactory.CreateLogger<LoginController>();

            _distributedCache = distributedCache;

        }

        [HttpGet]
        [AllowAnonymous]
        public string Get()
        {
            return "Login API";
        }

        // POST api/values
        [HttpPost]
        [AllowAnonymous]
        public async Task<JsonResult> UserLoginAsyncController([FromBody]ApplicationUser applicationUser)
        {
            var identity = await GetClaimsIdentity(applicationUser);
            if (identity == null)
            {
                _logger.LogInformation($"Invalid username ({applicationUser.UserName}) or password ({applicationUser.MD5Pass})");
                return new JsonResult(JsonConvert.SerializeObject(new { ErrorCode = "-1", ErrorMessage = "Invalid username or password", Access_Token = "" }));
            }

            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, await _jwtOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Aud, _jwtOptions.Audience),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                identity.FindFirst(JwtRegisteredClaimNames.Sid),
                identity.FindFirst("Role"),
            };

            // Create the JWT security token and encode it.
            var jwt = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                claims: claims,
                notBefore: _jwtOptions.NotBefore,
                expires: _jwtOptions.Expiration,
                signingCredentials: _jwtOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            return new JsonResult(JsonConvert.SerializeObject(new { ErrorCode = "0", ErrorMessage = "OK", AccessToken = encodedJwt }));
        }


        private void ThrowIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator));
            }
        }
        private long ToUnixEpochDate(DateTime date)
            => (long)Math.Round((date.ToLocalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

        private Task<ClaimsIdentity> GetClaimsIdentity(ApplicationUser user)
        {
            return Task.FromResult(new ClaimsIdentity(new GenericIdentity(user.UserName, "Token"),
                new[]
                {
                    new Claim("Role", "SysAdmin"),
                }));
        }
    }

    public class ApplicationUser
    {
        public string UserName { get; set; }
        public string MD5Pass { get; set; }
    }
}
