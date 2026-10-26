using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Items;

public sealed class HistoryModel(VaultService vault, Data.Items items, Users users) : AppPageModel
{
    public Item Item { get; private set; } = null!;
    public List<ItemVersion> Versions { get; private set; } = [];
    public Dictionary<string, UserRecord> UsersById { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync(string id) => await Act(async () =>
    {
        Item = await vault.GetItemAsync(Me, id);
        Versions = await items.VersionsAsync(id);
        UsersById = await users.GetManyAsync(Versions.Select(v => v.ChangedBy).Append(Item.UpdatedBy));
        return Page();
    }, () => Redirect("~/Items"));
}
