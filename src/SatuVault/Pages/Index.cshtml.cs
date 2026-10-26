using SatuVault.Data;
using SatuVault.Security;

namespace SatuVault.Pages;

public sealed class IndexModel(Data.Items items, Data.Servers servers, Data.Teams teams, Users users, SetupToken setup) : AppPageModel
{
    public int ItemCount { get; private set; }
    public int ServerCount { get; private set; }
    public List<Team> MyTeams { get; private set; } = [];
    public List<Item> Recent { get; private set; } = [];
    public Dictionary<string, Team> TeamsById { get; private set; } = [];
    public Dictionary<string, UserRecord> UsersById { get; private set; } = [];
    public bool SetupPending { get; private set; }

    public async Task OnGetAsync()
    {
        var visible = Me.VisibleTeamIds;
        var all = await items.ListAsync(visible);
        ItemCount = all.Count;
        Recent = all.OrderByDescending(i => i.UpdatedAt).Take(5).ToList();
        ServerCount = (await servers.ListAsync(visible)).Count;
        TeamsById = (await teams.ListAsync(visible)).ToDictionary(t => t.Id);
        MyTeams = TeamsById.Values.Where(t => Me.Roles.ContainsKey(t.Id)).OrderBy(t => t.Name).ToList();
        UsersById = await users.GetManyAsync(Recent.Select(i => i.UpdatedBy));
        SetupPending = !await setup.IsDoneAsync();
    }
}
