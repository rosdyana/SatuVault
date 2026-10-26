using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Items;

public sealed class DetailsModel(VaultService vault, Data.Servers servers, Data.Teams teams, Users users) : AppPageModel
{
    public Item Item { get; private set; } = null!;
    public Server? Server { get; private set; }
    public Team? Team { get; private set; }
    public Dictionary<string, UserRecord> UsersById { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync(string id) => await Act(async () =>
    {
        Item = await vault.GetItemAsync(Me, id);
        Server = Item.ServerId is null ? null : await servers.GetAsync(Item.ServerId) is { DeletedAt: null } s ? s : null;
        Team = await teams.GetAsync(Item.TeamId);
        UsersById = await users.GetManyAsync([Item.CreatedBy, Item.UpdatedBy]);
        return Page();
    }, () => Redirect("~/Items"));

    public async Task<IActionResult> OnPostDeleteAsync(string id) => await Act(async () =>
    {
        await vault.SetItemDeletedAsync(Me, Req, id, true);
        Flash = "Item deleted. A team manager can restore it.";
        return Redirect("~/Items");
    }, () => RedirectToPage(new { id }));

    public async Task<IActionResult> OnPostRestoreAsync(string id) => await Act(async () =>
    {
        await vault.SetItemDeletedAsync(Me, Req, id, false);
        Flash = "Item restored.";
        return RedirectToPage(new { id });
    }, () => RedirectToPage(new { id }));
}
