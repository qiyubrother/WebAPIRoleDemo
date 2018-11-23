using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace WebAPIRoleDemo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }
        private const string SecretKey = "needtogetthisfromenvironment";
        private readonly SymmetricSecurityKey _signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SecretKey));

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
            //services.AddMvc();
            // 跨域访问
            services.AddCors(
                options => options.AddPolicy("AllowCors",
                builder =>
                {
                    builder
                    //.WithOrigins("http://iot.nnhuman.cn") //AllowSpecificOrigins;
                    //.WithOrigins("http://localhost:4456", "http://localhost:4457") //AllowMultipleOrigins;
                    .AllowAnyOrigin() //AllowAllOrigins;

                    //.WithMethods("GET") //AllowSpecificMethods;
                    //.WithMethods("GET", "PUT") //AllowSpecificMethods;
                    //.WithMethods("GET", "PUT", "POST") //AllowSpecificMethods;
                    .WithMethods("GET", "PUT", "POST", "DELETE") //AllowSpecificMethods;
                                                                 //.AllowAnyMethod() //AllowAllMethods;

                    //.WithHeaders("Accept", "Content-type", "Origin", "X-Custom-Header");  //AllowSpecificHeaders;
                    .AllowAnyHeader(); //AllowAllHeaders;
                })
            );
            // Add framework services. 增加验证规则，认证全部接口。
            services.AddOptions();
            services.AddMvc(config =>
            {
                var policy = new AuthorizationPolicyBuilder()
                                 .RequireAuthenticatedUser()
                                 .Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            });

            // Get options from app settings
            var jwtAppSettingOptions = Configuration.GetSection(nameof(JwtIssuerOptions));

            // Configure JwtIssuerOptions
            services.Configure<JwtIssuerOptions>(options =>
            {
                options.Issuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                options.Audience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)];
                options.SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
            });

            // 使用规则验证.
            services.AddAuthorization(options =>
            {
                //options.AddPolicy("SysAdmin",
                //  policy => policy.RequireClaim("Role", "SysAdmin"));

                //options.AddPolicy("HotelAdminOnly",
                //    policy => policy.RequireClaim("Role", "HotelAdmin"));

                //options.AddPolicy("SysAdmin",
                //                  policy => policy.RequireClaim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Iss, jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)]));

                options.AddPolicy("SysAdmin",
                                  policy => policy.RequireClaim("Role", "SysAdmin"));
                options.AddPolicy("HotelAdmin",
                                  policy => policy.RequireClaim("Role", "HotelAdmin", "SysAdmin"));
                //options.AddPolicy("GeneralUser",
                //                  policy => policy.RequireClaim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Iss, jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)]));
                //options.AddPolicy("AdminRole",
                //                  policy => policy.RequireRole("Admin"));
            });
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)],

                        ValidateAudience = true,
                        ValidAudience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)],

                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = _signingKey,

                        RequireExpirationTime = true,
                        ValidateLifetime = true,

                        ClockSkew = TimeSpan.Zero
                    };
                });

            // 增加redis缓存
            //services.AddDistributedRedisCache(option =>
            //{
            //    option.Configuration = "127.0.0.1";
            //    option.InstanceName = "master";
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseCors("AllowCors");

            app.UseMvc();
        }
    }
}
