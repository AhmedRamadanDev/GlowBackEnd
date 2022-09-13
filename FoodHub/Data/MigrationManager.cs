//using Microsoft.EntityFrameworkCore;
//using FoodHub.Models;
//using Microsoft.AspNetCore.Identity;

//namespace FoodHub.Data
//{
//    public static class MigrationManager
//    {
//        public static WebApplication MigrateDatabase(this WebApplication webApp)
//        {
//            using (var scope = webApp.Services.CreateScope())
//            {
//                using var appContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

//                using var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

//                using var loggerFactory = scope.ServiceProvider.GetRequiredService<ILoggerFactory>();
//                var logger = loggerFactory.CreateLogger("app");

//                try
//                {
//                    SeedUserAsync(userManager, appContext);
//                }
//                catch (Exception ex)
//                {
//                    //Log errors or do anything you think it's needed
//                    throw;
//                }
//            }
//            return webApp;
//        }


//        public static void SeedUserAsync(UserManager<User> userManager,
//                                               DbContext dbContext)
//        {
//            if (!userManager.Users.Any())
//            {

//                userManager.CreateAsync(new User
//                {
//                    Name = "محمد عبدالحميد زكي",
//                    PhoneNumber = "+201141962411",
//                    UserName = "superuser1",
//                    Email = "askme557@gmail.com",
//                    EmailConfirmed = true,
//                }, "123Pa$$word!");


//            };
//        }
//    }
//}
