using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;

namespace SatuVault.Pages.Items;

public sealed class IndexModel(Data.Items items, Data.Servers servers, Data.Teams teams, Users users) : AppPageModel
{
    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true)] public string? Team { get; set; }
    [BindProperty(SupportsGet = true)] public bool Deleted { get; set; }

    public List<Item> Results { get; private set; } = [];
    public Dictionary<string, Team> TeamsById { get; private set; } = [];
    public Dictionary<string, Server> ServersById { get; private set; } = [];
    public Dictionary<string, UserRecord> UsersById { get; private set; } = [];

    public async Task OnGetAsync()
    {
        var visible = Me.VisibleTeamIds.Where(t => Team is null || t == Team).ToList();
        // Only managers (and admins) see the recycle bin of their teams.
        if (Deleted) visible = visible.Where(Me.CanManage).ToList();
        TeamsById = (await teams.ListAsync(Me.VisibleTeamIds)).ToDictionary(t => t.Id);
        ServersById = (await servers.ListAsync(visible)).ToDictionary(s => s.Id);
        var all = await items.ListAsync(visible, Deleted);
        // Everything is encrypted in MySQL, so search runs here over decrypted metadata.
        Results = string.IsNullOrWhiteSpace(Q)
            ? all
            : all.Where(i => Matches(i, Q.Trim())).ToList();
        UsersById = await users.GetManyAsync(Results.Select(i => i.UpdatedBy));
    }

    private bool Matches(Item i, string q) =>
        new[] { i.Meta.Title, i.Meta.Username, i.Meta.Url, i.Meta.Tags, i.ServerId is { } s && ServersById.TryGetValue(s, out var srv) ? srv.Info.Hostname : null }
            .Any(v => v?.Contains(q, StringComparison.OrdinalIgnoreCase) == true);
}
