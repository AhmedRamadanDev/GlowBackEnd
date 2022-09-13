using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace FoodHub.Models
{
    public class diet
    {
        [Key]
        public int Id { get; set; }
        
        public ICollection<User> User { get; set; }
       public string Description { get; set; }
        public ICollection<Food> Foods { get; set; }
        public DateTime Date { get; set; } = DateTime.UtcNow;
    }
    public class dietDto
    {
        public int Id { get; set; }
        public string Description { get; set; }
        public ICollection<string> Foods { get; set; }
        public string ClientId { get; set; }
    }
}
