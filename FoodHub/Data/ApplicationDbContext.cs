using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.ApiAuthorization.IdentityServer;
using Microsoft.EntityFrameworkCore;
using Duende.IdentityServer.EntityFramework.Options;
using Microsoft.Extensions.Options;
using FoodHub.Models;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.AspNetCore.Identity;

namespace FoodHub.Data
{
    public class ApplicationDbContext : ApiAuthorizationDbContext<User>
    {
        public ApplicationDbContext(
            DbContextOptions<ApplicationDbContext> options,
            IOptions<OperationalStoreOptions> operationalStoreOptions
            ) : base(options, operationalStoreOptions)
        {
        }

        public DbSet<diet> diets { get; set; }
        public DbSet<Exercise> Exercises { get; set; }
        public DbSet<Report> Reports { get; set; }
        public DbSet<Rating> Ratings { get; set; }
        public DbSet<Attendance> Attendances { get; set; }
        public DbSet<Food> Foods { get; set; }
        public DbSet<InBody> inBodies { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            

            


            //    builder.Entity<Item>()
            //        .HasKey(nameof(Item.Id), nameof(Item.Number));

            //    builder.Entity<Category>()
            //        .HasKey(nameof(Category.Id), nameof(Category.Number));

            //    builder.Entity<Addon>()
            //        .HasKey(nameof(Addon.Id), nameof(Addon.Number));

            //    builder.Entity<CookingState>()
            //        .HasKey(nameof(CookingState.Id), nameof(CookingState.Number));

            //    builder.Entity<Recipe>()
            //        .HasKey(nameof(Recipe.Id), nameof(Recipe.Number));

            //    builder.Entity<Ingredient>()
            //        .HasKey(nameof(Ingredient.Id), nameof(Ingredient.Number));

            //    builder.Entity<Discount>()
            //        .HasKey(nameof(Discount.Id), nameof(Discount.Number));

            //    builder.Entity<SKU>()
            //        .HasKey(nameof(SKU.Id), nameof(SKU.Number));

            //    builder.Entity<ItemSize>()
            //        .HasKey(nameof(ItemSize.Id), nameof(ItemSize.Number));

            //    builder.Entity<Order>()
            //        .HasKey(nameof(Order.Id), nameof(Order.Number));
        }
        public static async Task CreateRoles(IServiceProvider serviceProvider)
        {
            RoleManager<IdentityRole> roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            
            string Sales = "Sales";
            string Employee = "Employee";
            string Nutritionist = "Nutritionist";


            await roleManager.CreateAsync(new IdentityRole(Sales));
            await roleManager.CreateAsync(new IdentityRole(Employee));
            await roleManager.CreateAsync(new IdentityRole(Nutritionist));
        }
        public DbSet<FoodHub.Models.InBody>? InBody { get; set; }

    }
}