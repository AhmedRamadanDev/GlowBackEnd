using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FoodHub.Models
{
    public class InBody
    {
        public int Id { get; set; }
        public User User { get; set; }
        public int Muscle { get; set; }
        public int Fat { get; set; }
        public int Water { get; set; }
        public int Metabolic { get; set; }
        public int Height { get; set; }
        public int Weight { get; set; }
        public int Age { get; set; }
        public int Gender { get; set; }
        public string Picture { get; set; }
    }
    public class InBodyDto
    {
        
        public string ClientId { get; set; }
        public int Muscle { get; set; }
        public int Fat { get; set; }
        public int Water { get; set; }
        public int Metabolic { get; set; }
        public int Height { get; set; }
        public int Weight { get; set; }
        public int Age { get; set; }
        public int Gender { get; set; }
        public IFormFile Picture { get; set; }
    }
}
