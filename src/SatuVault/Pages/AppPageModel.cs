using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SatuVault.Audit;
using SatuVault.Data;
using SatuVault.Security;
using SatuVault.Services;

namespace SatuVault.Pages;

public abstract class AppPageModel : PageModel
{
    protected AppUser Me => HttpContext.RequireAppUser();
    protected RequestInfo Req => HttpContext.RequestInfo();

    [TempData] public string? Flash { get; set; }
    [TempData] public string? FlashError { get; set; }

    /// <summary>For actions that redirect afterwards (Post/Redirect/Get): errors become a flash message.</summary>
    protected async Task<IActionResult> Act(Func<Task<IActionResult>> action, Func<IActionResult> onError)
    {
        try
        {
            return await action();
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
        catch (ForbiddenException e)
        {
            FlashError = e.Message;
            return onError();
        }
        catch (Exception e) when (e is AppException or ConcurrencyException)
        {
            FlashError = e.Message;
            return onError();
        }
    }

    /// <summary>For forms that re-render on error with the user's input kept.</summary>
    protected async Task<IActionResult> Form(Func<Task<IActionResult>> action, Func<Task> reload)
    {
        try
        {
            return await action();
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
        catch (Exception e) when (e is AppException or ConcurrencyException)
        {
            ModelState.AddModelError("", e.Message);
            await reload();
            return Page();
        }
    }

}

/// <summary>Display helpers shared by the views.</summary>
public static class Fmt
{
    public static TimeZoneInfo Zone { get; set; } = TimeZoneInfo.Utc;

    public static string Time(DateTime utc) =>
        TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), Zone).ToString("yyyy-MM-dd HH:mm:ss") + (Zone == TimeZoneInfo.Utc ? " UTC" : "");

    public static string Time(DateTime? utc) => utc is null ? "" : Time(utc.Value);

    public static string Date(DateTime utc) =>
        TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), Zone).ToString("d MMM yyyy, HH:mm", System.Globalization.CultureInfo.InvariantCulture);

    public static string User(IReadOnlyDictionary<string, UserRecord> users, string? id) =>
        id is null ? "system" : users.TryGetValue(id, out var u) ? u.Email : id[..8];
}
