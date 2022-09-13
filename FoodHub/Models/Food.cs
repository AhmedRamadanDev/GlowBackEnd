using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FoodHub.Models
{
    public class Food
    {
        public Guid Id { get; set; }
        public string Meal { get; set; }
        public ICollection<diet>? Diets { get; set; } 
    }
}
