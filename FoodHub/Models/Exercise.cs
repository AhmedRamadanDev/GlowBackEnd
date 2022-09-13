using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FoodHub.Models
{
    public class Exercise
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public User User { get; set; }
    }
}
