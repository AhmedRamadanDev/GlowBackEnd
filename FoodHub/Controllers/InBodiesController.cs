using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FoodHub.Data;
using FoodHub.Models;
using FoodHub.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;

namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class InBodiesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly UserManager<User> _userManager;
        public InBodiesController(ApplicationDbContext context, UserManager<User> userManager, IWebHostEnvironment hostEnvironmen)
        {
            _context = context;
            _webHostEnvironment = hostEnvironmen;
            _userManager = userManager;
        }

        // GET: api/InBodies
        [HttpGet]
        public async Task<ActionResult<IEnumerable<InBody>>> GetInBody()
        {
          if (_context.InBody == null)
          {
              return NotFound();
          }
            return await _context.InBody.ToListAsync();
        }

        // GET: api/InBodies/5
        [HttpGet("{id}")]
        public async Task<ActionResult<InBody>> GetInBody(int id)
        {
          if (_context.InBody == null)
          {
              return NotFound();
          }
            var inBody = await _context.InBody.FindAsync(id);

            if (inBody == null)
            {
                return NotFound();
            }

            return inBody;
        }

        // PUT: api/InBodies/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutInBody(int id, InBody inBody)
        {
            if (id != inBody.Id)
            {
                return BadRequest();
            }

            _context.Entry(inBody).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!InBodyExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/InBodies
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult> PostInBody([FromForm] InBodyDto inBodyDto)
        {
          if (_context.InBody == null)
          {
              return Problem("Entity set 'ApplicationDbContext.InBody'  is null.");
          }
            var user = await _userManager.FindByIdAsync(inBodyDto.ClientId);
            var inBody = new InBody
            {
                Age = inBodyDto.Age,
                Fat = inBodyDto.Fat,
                Gender = inBodyDto.Gender,
                Height = inBodyDto.Height,
                Metabolic = inBodyDto.Metabolic,
                Muscle = inBodyDto.Muscle,
                Water = inBodyDto.Water,
                Weight = inBodyDto.Weight,
                User = user,
                Picture = FileHelper.UploadedFile(inBodyDto.Picture,_webHostEnvironment.WebRootPath, "TODO: fix ngrok to get a fixed domain", "Category")
            };
            _context.inBodies.Add(inBody);
            await _context.SaveChangesAsync();
            return Ok(new {
            message = "create successfully"
            });
        }

        // DELETE: api/InBodies/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteInBody(int id)
        {
            if (_context.InBody == null)
            {
                return NotFound();
            }
            var inBody = await _context.InBody.FindAsync(id);
            if (inBody == null)
            {
                return NotFound();
            }

            _context.InBody.Remove(inBody);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool InBodyExists(int id)
        {
            return (_context.InBody?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
