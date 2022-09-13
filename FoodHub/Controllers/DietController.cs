using FoodHub.Data;
using FoodHub.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Nutritionist")]
    public class DietController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;
        public DietController(
            ApplicationDbContext dbContext, UserManager<User> userManager
            )
        {
            _userManager = userManager;
            _context = dbContext;
        }
        // GET: DietController
        public ActionResult Index()
        {
            return View();
        }

        // GET: DietController/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: DietController/Create
        [HttpPost]
        public async Task<ActionResult> Create(dietDto dietDto)
        {
            var userEmail = User.FindFirstValue(ClaimTypes.Email);
            var users = new List<User>();
            users.Add(await _userManager.FindByEmailAsync(userEmail));
            var client = await _userManager.FindByIdAsync(dietDto.ClientId);
            if (Equals(client, null))
            {
                return BadRequest(new
                {
                    message = "client's id is uncorrect"
                });
            }
            users.Add(client);
            var diet = new diet
            {
                User = users,
                Description = dietDto.Description,
                Foods = new List<Food>()
            };
            foreach(var food in dietDto.Foods.ToList())
            {
                if(_context.Foods.Any(x=>x.Meal == food))
                {
                    var item =await _context.Foods.Where(x => x.Meal == food).FirstAsync();
                    diet.Foods.Add(item);
                }
                else
                {
                    var item = new Food { Meal = food };
                    await _context.Foods.AddAsync(item);
                }
            }
           await _context.SaveChangesAsync();
           await _context.diets.AddAsync(diet);
           await _context.SaveChangesAsync();
            return Ok(new
            {
                Status = true,
                Message = false
            });
        }

        // POST: DietController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: DietController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: DietController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: DietController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: DietController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}
