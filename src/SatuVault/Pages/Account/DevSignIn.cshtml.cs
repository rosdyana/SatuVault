using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SatuVault.Audit;
using SatuVault.Data;
using SatuVault.Security;

namespace SatuVault.Pages.Account;

/// <summary>
/// Local trial without an Entra tenant: only in Development with SatuVault:DevLogin=true.
/// Everywhere else this page is a 404 and the app signs in through Entra ID.
/// </summary>
public sealed class DevSignInModel(Users users, AuditLog audit, IWebHostEnvironment env, IConfiguration config) : PageModel
{
    [BindProperty] public string Email { get; set; } = "";
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    private bool Enabled => env.IsDevelopment() && config.GetValue<bool>("SatuVault:DevLogin");

    public IActionResult OnGet() => Enabled ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync()
    {
        if (!Enabled) return NotFound();
        var email = Email.Trim().ToLowerInvariant();
        if (!email.Contains('@')) return Page();
        var (user, created) = await users.UpsertFromSignInAsync("dev-tenant", $"dev:{email}", email, email.Split('@')[0]);
        if (user.Disabled) return Redirect("~/Account/Disabled");
        await audit.WriteAsync(user.Id, HttpContext.RequestInfo(), "auth.signin", "user", user.Id, new { firstSignIn = created, dev = true });
        await HttpContext.SignInAsync(SignIns.Principal(user.Id, user.Name));
        return LocalRedirect(Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : "~/");
    }
}
