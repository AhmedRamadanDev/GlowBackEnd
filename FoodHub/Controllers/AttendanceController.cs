using FoodHub.Data;
using FoodHub.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FoodHub.Controllers
{
    [Route("api/[controller]")]
    [Authorize(Roles = "reception")]
    [ApiController]
    public class AttendanceController : Controller
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _context;

        public AttendanceController(
            SignInManager<User> signInManager,
            UserManager<User> userManager,
            ApplicationDbContext dbContext
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = dbContext;
            
        }
        [HttpGet("start/{email}")]
        public async Task<IActionResult> AddAttendance(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user == null)
            {
                return NotFound();
            }
            var attendance = new Attendance
            {
                From = DateTime.Now.ToString("HH:mm"),
                Date = DateTime.Today,
                User = user,
                Status = false
            };
            await _context.Attendances.AddAsync(attendance);
            await _context.SaveChangesAsync();
            return Ok();
        }
        [HttpGet("end/{email}")]
        public async Task<IActionResult> EndAttendance(string email)
        {
            var attendance = _context.Attendances.Where(x => x.User.Email == email && x.Status == false).FirstOrDefault();
            attendance.Status = true;
            attendance.To = DateTime.Now.ToString("HH:mm");
            _context.Entry(attendance).State = EntityState.Modified;
            try
            {
                await _context.SaveChangesAsync();
                return Ok();
            }
            catch (DbUpdateConcurrencyException)
            {
                    return NotFound();
            }
            return Ok();
        }
        public IActionResult Index()
        {
            return View();
        }
    }
}
