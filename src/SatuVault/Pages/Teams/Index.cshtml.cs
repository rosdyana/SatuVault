using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Teams;

public sealed class IndexModel(VaultService vault, Data.Teams teams, Users users) : AppPageModel
{
    public List<Team> List { get; private set; } = [];
    public Dictionary<string, int> MemberCounts { get; private set; } = [];

    [BindProperty] public string NewName { get; set; } = "";
    [BindProperty] public string ManagerEmail { get; set; } = "";

    public async Task OnGetAsync()
    {
        List = await teams.ListAsync(Me.VisibleTeamIds);
        foreach (var t in List) MemberCounts[t.Id] = (await teams.MembersAsync(t.Id)).Count;
        if (string.IsNullOrEmpty(ManagerEmail)) ManagerEmail = Me.User.Email;
    }

    public async Task<IActionResult> OnPostCreateAsync() => await Act(async () =>
    {
        var manager = await users.FindByEmailAsync(ManagerEmail) ?? throw new InvalidInputException("No user with that email has signed in yet.");
        var id = await vault.CreateTeamAsync(Me, Req, NewName, manager.Id);
        Flash = $"Team “{NewName.Trim()}” created.";
        return RedirectToPage("Details", new { id });
    }, () => RedirectToPage());
}
