using System.Text;
using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Servers;

public sealed class DetailsModel(VaultService vault, Data.Items items, Data.Teams teams, Users users) : AppPageModel
{
    public Server Server { get; private set; } = null!;
    public Team? Team { get; private set; }
    public List<Item> Credentials { get; private set; } = [];
    public Dictionary<string, UserRecord> UsersById { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync(string id) => await Act(async () =>
    {
        Server = await vault.GetServerAsync(Me, id);
        Team = await teams.GetAsync(Server.TeamId);
        Credentials = await items.ListAsync([Server.TeamId], serverId: id);
        UsersById = await users.GetManyAsync([Server.UpdatedBy]);
        return Page();
    }, () => Redirect("~/Servers"));

    /// <summary>.rdp file for the built-in Remote Desktop client. Never contains a password.</summary>
    public async Task<IActionResult> OnGetRdpAsync(string id) => await Act(async () =>
    {
        var s = await vault.GetServerAsync(Me, id);
        await vault.LogRdpDownloadAsync(Me, Req, s);
        var address = s.Info.IpAddress ?? s.Info.Hostname;
        var rdp = new StringBuilder()
            .Append("full address:s:").Append(address).Append("\r\n")
            .Append("prompt for credentials:i:1\r\n")
            .Append("authentication level:i:2\r\n")
            .ToString();
        var safeName = string.Concat(s.Info.Hostname.Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' ? c : '_'));
        return File(Encoding.UTF8.GetBytes(rdp), "application/x-rdp", $"{safeName}.rdp");
    }, () => RedirectToPage(new { id }));

    public async Task<IActionResult> OnPostDeleteAsync(string id) => await Act(async () =>
    {
        await vault.SetServerDeletedAsync(Me, Req, id, true);
        Flash = "Server deleted. A team manager can restore it.";
        return Redirect("~/Servers");
    }, () => RedirectToPage(new { id }));

    public async Task<IActionResult> OnPostRestoreAsync(string id) => await Act(async () =>
    {
        await vault.SetServerDeletedAsync(Me, Req, id, false);
        Flash = "Server restored.";
        return RedirectToPage(new { id });
    }, () => RedirectToPage(new { id }));
}
