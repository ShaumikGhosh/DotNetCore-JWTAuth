using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuth.Controllers
{
    [Authorize]
    [ApiController]
    public class DataController : ControllerBase
    {
        [HttpGet]
        [Route("api/users")]
        public IActionResult Index()
        {
            return Ok(new
            {
                Name = "Shaumik Ghosh",
                Email = "shaumik.gh@gmail.com"
            });
        }
    }
}
