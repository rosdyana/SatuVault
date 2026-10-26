using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Servers;

public sealed class EditModel(VaultService vault, Data.Teams teams) : AppPageModel
{
    public sealed class InputModel
    {
        public string? TeamId { get; set; }
        public string Hostname { get; set; } = "";
        public string? IpAddress { get; set; }
        public string? Os { get; set; }
        public string? Cpu { get; set; }
        public string? Ram { get; set; }
        public string? Disk { get; set; }
        public string? AssetId { get; set; }
        public string? Environment { get; set; }
        public string? Location { get; set; }
        public string? Notes { get; set; }
        public int Version { get; set; }

        public ServerInfo ToInfo() => new(Hostname, IpAddress, Os, Cpu, Ram, Disk, AssetId, Environment, Location, Notes);
    }

    [BindProperty] public InputModel Input { get; set; } = new();
    [BindProperty(SupportsGet = true)] public string? Id { get; set; }

    public bool IsNew => Id is null;
    public List<Team> EditableTeams { get; private set; } = [];

    private async Task LoadAsync() =>
        EditableTeams = (await teams.ListAsync(Me.VisibleTeamIds)).Where(t => Me.CanEdit(t.Id)).ToList();

    public async Task<IActionResult> OnGetAsync(string? team) => await Act(async () =>
    {
        if (!IsNew)
        {
            var s = await vault.GetServerAsync(Me, Id!);
            if (s.DeletedAt is not null) return RedirectToPage("Details", new { id = Id });
            var i = s.Info;
            Input = new InputModel
            {
                TeamId = s.TeamId, Hostname = i.Hostname, IpAddress = i.IpAddress, Os = i.Os, Cpu = i.Cpu, Ram = i.Ram, Disk = i.Disk,
                AssetId = i.AssetId, Environment = i.Environment, Location = i.Location, Notes = i.Notes, Version = s.Version,
            };
        }
        else
        {
            Input.TeamId = team;
        }
        await LoadAsync();
        if (IsNew && EditableTeams.Count == 0)
        {
            FlashError = "You need to be in a team to add servers.";
            return Redirect("~/Servers");
        }
        return Page();
    }, () => Redirect("~/Servers"));

    public async Task<IActionResult> OnPostAsync() => await Form(async () =>
    {
        if (IsNew)
        {
            if (string.IsNullOrEmpty(Input.TeamId)) throw new InvalidInputException("Choose a team");
            var id = await vault.CreateServerAsync(Me, Req, Input.TeamId, Input.ToInfo());
            Flash = "Server saved.";
            return RedirectToPage("Details", new { id });
        }
        await vault.UpdateServerAsync(Me, Req, Id!, Input.Version, Input.ToInfo());
        Flash = "Server saved.";
        return RedirectToPage("Details", new { id = Id });
    }, LoadAsync);
}
