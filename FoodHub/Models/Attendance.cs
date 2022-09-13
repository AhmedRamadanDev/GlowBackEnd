using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FoodHub.Models
{
    public class Attendance
    {
        public Guid Id { get; set; }
        public string From { get; set; }
        public string? To { get; set; }
        public DateTime Date { get; set; }
        public User User { get; set; }
        public bool Status { get; set; }
    }
}
