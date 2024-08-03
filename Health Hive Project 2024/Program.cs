using Health_Hive_Project_2024.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddRoles<IdentityRole>() // Add this line to configure RoleManager for IdentityRole
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

//Create a scope to resolve services
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ApplicationDbContext>();

    // Initialize RoleManager
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

    // Check if "Admin" role exists, if not, create it
    if (!roleManager.RoleExistsAsync("Admin").Result)
    {
        var role = new IdentityRole("Admin");
        roleManager.CreateAsync(role).Wait();
    }

    //// Check if "Nurse" role exists, if not, create it
    //if (!roleManager.RoleExistsAsync("Nurse").Result)
    //{
    //    var role = new IdentityRole("Nurse");
    //    roleManager.CreateAsync(role).Wait();
    //}

    //// Check if "Surgeon" role exists, if not, create it
    //if (!roleManager.RoleExistsAsync("Surgeon").Result)
    //{
    //    var role = new IdentityRole("Surgeon");
    //    roleManager.CreateAsync(role).Wait();
    //}

    //// Check if "Pharmacist" role exists, if not, create it
    //if (!roleManager.RoleExistsAsync("Pharmacist").Result)
    //{
    //    var role = new IdentityRole("Pharmacist");
    //    roleManager.CreateAsync(role).Wait();
    //}

    //// Check if "Anaesthesiologist" role exists, if not, create it
    //if (!roleManager.RoleExistsAsync("Anaesthesiologist").Result)
    //{
    //    var role = new IdentityRole("Anaesthesiologist");
    //    roleManager.CreateAsync(role).Wait();
    //}
}
//TRYING TO ADD ROLES TO THE DATABASE





app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
