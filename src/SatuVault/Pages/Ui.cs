using System.Globalization;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace SatuVault.Pages;

/// <summary>Small view helpers: icons from wwwroot/icons.svg and readable timestamps.</summary>
public static class Ui
{
    /// <summary>A decorative Phosphor icon; the button or link next to it carries the text.</summary>
    public static IHtmlContent Icon(this IHtmlHelper html, string name, string? cls = null)
    {
        var href = $"{html.ViewContext.HttpContext.Request.PathBase}/icons.svg#{name}";
        return new HtmlString($"""<svg class="icon{(cls is null ? "" : " " + cls)}" aria-hidden="true" focusable="false"><use href="{HtmlEncoder.Default.Encode(href)}"></use></svg>""");
    }

    /// <summary>"12 min ago" with the exact local time on hover; older than a week shows the date.</summary>
    public static IHtmlContent When(this IHtmlHelper html, DateTime? utc, bool exact = false)
    {
        if (utc is null) return HtmlString.Empty;
        var u = DateTime.SpecifyKind(utc.Value, DateTimeKind.Utc);
        var full = Fmt.Time(u);
        var age = DateTime.UtcNow - u;
        var text = exact ? full
            : age < TimeSpan.FromMinutes(1) ? "just now"
            : age < TimeSpan.FromHours(1) ? $"{(int)age.TotalMinutes} min ago"
            : age < TimeSpan.FromDays(1) ? $"{(int)age.TotalHours} h ago"
            : age < TimeSpan.FromDays(7) ? $"{(int)age.TotalDays} d ago"
            : Fmt.Date(u);
        var iso = u.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        return new HtmlString($"""<time datetime="{iso}" title="{HtmlEncoder.Default.Encode(full)}">{HtmlEncoder.Default.Encode(text)}</time>""");
    }
}
