using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Teams;

public sealed class DetailsModel(VaultService vault, Data.Teams teams, Users users) : AppPageModel
{
    public Team Team { get; private set; } = null!;
    public List<(TeamMember Member, UserRecord? User)> Members { get; private set; } = [];

    [BindProperty] public string Email { get; set; } = "";
    [BindProperty] public TeamRole Role { get; set; } = TeamRole.Member;
    [BindProperty] public string NewName { get; set; } = "";

    public async Task<IActionResult> OnGetAsync(string id) => await Act(async () =>
    {
        Team = await vault.GetTeamAsync(Me, id);
        NewName = Team.Name;
        var members = await teams.MembersAsync(id);
        var byId = await users.GetManyAsync(members.Select(m => m.UserId));
        Members = members.Select(m => (m, byId.GetValueOrDefault(m.UserId)))
            .OrderByDescending(x => x.m.Role).ThenBy(x => x.Item2?.Email).ToList();
        return Page();
    }, () => Redirect("~/Teams"));

    public Task<IActionResult> OnPostAddAsync(string id) => Act(async () =>
    {
        await vault.SetMemberAsync(Me, Req, id, Email, Role);
        Flash = $"{Email} is now a {Role.ToString().ToLowerInvariant()} of this team.";
        return RedirectToPage(new { id });
    }, () => RedirectToPage(new { id }));

    public Task<IActionResult> OnPostRoleAsync(string id, string userId, TeamRole role) => Act(async () =>
    {
        var u = await users.GetAsync(userId) ?? throw new NotFoundException();
        await vault.SetMemberAsync(Me, Req, id, u.Email, role);
        Flash = "Role updated.";
        return RedirectToPage(new { id });
    }, () => RedirectToPage(new { id }));

    public Task<IActionResult> OnPostRemoveAsync(string id, string userId) => Act(async () =>
    {
        await vault.RemoveMemberAsync(Me, Req, id, userId);
        Flash = "Member removed.";
        return RedirectToPage(new { id });
    }, () => RedirectToPage(new { id }));

    public Task<IActionResult> OnPostRenameAsync(string id) => Act(async () =>
    {
        await vault.RenameTeamAsync(Me, Req, id, NewName);
        Flash = "Team renamed.";
        return RedirectToPage(new { id });
    }, () => RedirectToPage(new { id }));

    public Task<IActionResult> OnPostDeleteAsync(string id) => Act(async () =>
    {
        await vault.DeleteTeamAsync(Me, Req, id);
        Flash = "Team deleted.";
        return Redirect("~/Teams");
    }, () => RedirectToPage(new { id }));
}
