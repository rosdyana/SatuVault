using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Security;

namespace SatuVault.Pages;

/// <summary>The installer enters the token printed by `init` (plus a code) to become the first admin.</summary>
public sealed class SetupModel(SetupToken setup, Users users) : AppPageModel
{
    [BindProperty] public string Token { get; set; } = "";
    [BindProperty] public string Code { get; set; } = "";

    public async Task<IActionResult> OnGetAsync() => await setup.IsDoneAsync() ? Redirect("~/") : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        if (await setup.IsDoneAsync()) return Redirect("~/");
        var check = await users.VerifyCodeAsync(Me.Id, Code);
        if (!check.Ok)
        {
            ModelState.AddModelError("", "Wrong authenticator code.");
            return Page();
        }
        switch (await setup.ClaimAsync(Me.Id, Req, Token))
        {
            case SetupOutcome.Ok:
                Flash = "You are now the SatuVault admin. Next: create a team.";
                return Redirect("~/Teams");
            case SetupOutcome.BadToken:
                ModelState.AddModelError("", "That setup token is not valid.");
                return Page();
            case SetupOutcome.NoTokenFile:
                ModelState.AddModelError("", "No setup token found on the server. Run `SatuVault init` first.");
                return Page();
            default:
                return Redirect("~/");
        }
    }
}
