using ArtizanWebProject.Data;
using ArtizanWebProject.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Cryptography;
using System.Text;

namespace ArtizanWebProject.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            ApplicationDbContext context,
            IWebHostEnvironment webHostEnvironment,
            ILogger<AccountController> logger)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
            _logger = logger;
        }

        public IActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    _logger.LogInformation("E-posta için kayıt işlemi başlatılıyor: {Email}", model.Email);

                    if (_context.Users.Any(u => u.Email == model.Email))
                    {
                        _logger.LogWarning("Kayıt başarısız oldu: E-posta zaten mevcut: {Email}", model.Email);
                        ModelState.AddModelError("Email", "E-posta zaten mevcut");
                        return View(model);
                    }

                    var user = new User
                    {
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        Email = model.Email,
                        Password = HashPassword(model.Password),
                        Phone = model.Phone,
                        CreatedAt = DateTime.UtcNow
                    };

                    // Log user data before saving (excluding sensitive information)
                    _logger.LogInformation("Yeni kullanıcı kaydedilmeye çalışılıyor: {FirstName} {LastName}, Email: {Email}",
                        user.FirstName, user.LastName, user.Email);

                    _context.Users.Add(user);
                    var result = await _context.SaveChangesAsync();

                    _logger.LogInformation("Kullanıcı başarıyla oluşturuldu. Etkilenen kayıtlar: {result}", result);

                    TempData["SuccessMessage"] = "Hesap başarıyla oluşturuldu! Lütfen giriş yapın.";
                    return RedirectToAction("Login");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "E-posta için kullanıcı kaydı sırasında hata oluştu: {Email}", model.Email);
                    ModelState.AddModelError("", "Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.");
                    return View(model);
                }
            }
            else
            {
                _logger.LogWarning("Kayıt sırasında geçersiz model durumu");
                foreach (var modelState in ModelState.Values)
                {
                    foreach (var error in modelState.Errors)
                    {
                        _logger.LogWarning("Doğrulama hatası: {ErrorMessage}", error.ErrorMessage);
                    }
                }
            }

            return View(model);
        }

        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    _logger.LogInformation("Email için giriş girişimi: {Email}", model.Email);

                    var user = _context.Users.FirstOrDefault(u => u.Email == model.Email);

                    if (user != null && VerifyPassword(model.Password, user.Password))
                    {
                        await SignInUser(user);
                        _logger.LogInformation("Kullanıcı başarıyla giriş yaptı: {Email}", model.Email);
                        return RedirectToAction("Index", "Home");
                    }

                    _logger.LogWarning(" {Email}", model.Email);
                    ModelState.AddModelError("Email için başarısız giriş girişimi:", "Invalid email or password.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Email giriş sırasında hata oluştu : {Email}", model.Email);
                    ModelState.AddModelError("", "Giriş sırasında bir hata oluştu. Lütfen tekrar deneyin.");
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("Kullanıcı çıkış yaptı: {Email}", userEmail);
            return RedirectToAction("Register", "Account");
        }

        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashedBytes);
            }
        }

        private bool VerifyPassword(string password, string hashedPassword)
        {
            return HashPassword(password) == hashedPassword;
        }

        private async Task SignInUser(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                new AuthenticationProperties { IsPersistent = true });

            _logger.LogInformation(" Kullanıcı için oluşturulan kimlik doğrulama çerezi: {Email}", user.Email);
        }
    }
}