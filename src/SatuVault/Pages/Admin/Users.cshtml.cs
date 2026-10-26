using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Admin;

public sealed class UsersModel(VaultService vault, Users users) : AppPageModel
{
    public List<UserRecord> List { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync()
    {
        if (!Me.IsAdmin) return NotFound();
        List = await users.ListAsync();
        return Page();
    }

    /// <summary>One handler for all admin actions on a user; each needs the admin's own code.</summary>
    public Task<IActionResult> OnPostAsync(string userId, string action, string code) => Act(async () =>
    {
        if (!Me.IsAdmin) return NotFound();
        switch (action)
        {
            case "grant-admin": await vault.SetAdminAsync(Me, Req, userId, true, code); break;
            case "revoke-admin": await vault.SetAdminAsync(Me, Req, userId, false, code); break;
            case "disable": await vault.SetDisabledAsync(Me, Req, userId, true, code); break;
            case "enable": await vault.SetDisabledAsync(Me, Req, userId, false, code); break;
            case "reset-totp": await vault.ResetTotpAsync(Me, Req, userId, code); break;
            default: throw new InvalidInputException("Unknown action");
        }
        Flash = "Done.";
        return RedirectToPage();
    }, () => RedirectToPage());
}
