using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace WebAPIRoleDemo.Controllers
{
    [EnableCors("AllowCors"), Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class TestController : ControllerBase
    {
        // GET: api/Test
        [HttpGet]
        [Authorize(Policy = "HotelAdmin")]
        //[AllowAnonymous]
        public IEnumerable<string> Get()
        {
            return new string[] { "test1", "test2" };
        }
    }
}
