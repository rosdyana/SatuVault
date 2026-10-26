using Microsoft.AspNetCore.Mvc;
using SatuVault.Data;
using SatuVault.Services;

namespace SatuVault.Pages.Items;

public sealed class EditModel(VaultService vault, Data.Servers servers, Data.Teams teams) : AppPageModel
{
    public sealed class InputModel
    {
        public string? TeamId { get; set; }
        public ItemKind Kind { get; set; } = ItemKind.Credential;
        public string Title { get; set; } = "";
        public string? Username { get; set; }
        public string? Url { get; set; }
        public string? Tags { get; set; }
        public string? ServerId { get; set; }
        public string? Password { get; set; }
        public string? SecretText { get; set; }
        public string? Notes { get; set; }
        /// <summary>Set by the page script after "Load current secrets": the fields then replace everything.</summary>
        public bool SecretLoaded { get; set; }
        public int Version { get; set; }
    }

    [BindProperty] public InputModel Input { get; set; } = new();
    [BindProperty(SupportsGet = true)] public string? Id { get; set; }

    public bool IsNew => Id is null;
    public List<Team> EditableTeams { get; private set; } = [];
    public List<Server> TeamServers { get; private set; } = [];

    private async Task LoadListsAsync()
    {
        EditableTeams = (await teams.ListAsync(Me.VisibleTeamIds)).Where(t => Me.CanEdit(t.Id)).ToList();
        var teamIds = IsNew ? EditableTeams.Select(t => t.Id) : [Input.TeamId!];
        TeamServers = await servers.ListAsync(teamIds);
    }

    public async Task<IActionResult> OnGetAsync(string? team) => await Act(async () =>
    {
        if (!IsNew)
        {
            var item = await vault.GetItemAsync(Me, Id!);
            if (item.DeletedAt is not null) return RedirectToPage("Details", new { id = Id });
            Input = new InputModel
            {
                TeamId = item.TeamId, Kind = item.Kind, Title = item.Meta.Title, Username = item.Meta.Username,
                Url = item.Meta.Url, Tags = item.Meta.Tags, ServerId = item.ServerId, Version = item.Version,
            };
        }
        else
        {
            Input.TeamId = team;
        }
        await LoadListsAsync();
        if (IsNew && EditableTeams.Count == 0)
        {
            FlashError = "You need to be in a team to add items.";
            return Redirect("~/Items");
        }
        return Page();
    }, () => Redirect("~/Items"));

    public async Task<IActionResult> OnPostAsync() => await Form(async () =>
    {
        var meta = new ItemMeta(Input.Title, Input.Username, Input.Url, Input.Tags);
        var serverId = string.IsNullOrEmpty(Input.ServerId) ? null : Input.ServerId;
        if (IsNew)
        {
            if (string.IsNullOrEmpty(Input.TeamId)) throw new InvalidInputException("Choose a team");
            var secret = new ItemSecret(N(Input.Password), N(Input.SecretText), N(Input.Notes));
            var id = await vault.CreateItemAsync(Me, Req, Input.TeamId, Input.Kind, serverId, meta, secret);
            Flash = "Item saved.";
            return RedirectToPage("Details", new { id });
        }
        var existing = await vault.GetItemAsync(Me, Id!);
        Input.TeamId = existing.TeamId;
        await vault.UpdateItemAsync(Me, Req, Id!, Input.Version, serverId, meta,
            new SecretPatch(Input.Password, Input.SecretText, Input.Notes, Input.SecretLoaded));
        Flash = "Item saved.";
        return RedirectToPage("Details", new { id = Id });
    }, async () =>
    {
        // Never echo typed secrets back into the page.
        Input.Password = Input.SecretText = Input.Notes = null;
        Input.SecretLoaded = false;
        if (!IsNew) Input.TeamId = (await vault.GetItemAsync(Me, Id!)).TeamId;
        await LoadListsAsync();
    });

    private static string? N(string? s) => string.IsNullOrEmpty(s) ? null : s;
}
