using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;

namespace SatuVault.Pages.Servers;

public sealed class IndexModel(Data.Servers servers, Data.Teams teams) : AppPageModel
{
    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true)] public string? Team { get; set; }
    [BindProperty(SupportsGet = true)] public bool Deleted { get; set; }

    public List<Server> Results { get; private set; } = [];
    public Dictionary<string, Team> TeamsById { get; private set; } = [];

    public async Task OnGetAsync()
    {
        var visible = Me.VisibleTeamIds.Where(t => Team is null || t == Team).ToList();
        if (Deleted) visible = visible.Where(Me.CanManage).ToList();
        TeamsById = (await teams.ListAsync(Me.VisibleTeamIds)).ToDictionary(t => t.Id);
        var all = await servers.ListAsync(visible, Deleted);
        Results = string.IsNullOrWhiteSpace(Q) ? all : all.Where(s => Matches(s.Info, Q.Trim())).ToList();
    }

    private static bool Matches(ServerInfo s, string q) =>
        new[] { s.Hostname, s.IpAddress, s.Os, s.AssetId, s.Environment, s.Location, s.Notes, s.Cpu, s.Ram, s.Disk }
            .Any(v => v?.Contains(q, StringComparison.OrdinalIgnoreCase) == true);
}
