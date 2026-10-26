using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using QRCoder;
using SatuVault.Audit;
using SatuVault.Crypto;
using SatuVault.Data;
using SatuVault.Security;

namespace SatuVault.Pages;

/// <summary>First sign-in (or after an admin reset): link an authenticator app before anything else.</summary>
public sealed class EnrollModel(Users users, AuditLog audit, IOptions<SatuOptions> options) : AppPageModel
{
    public string QrDataUri { get; private set; } = "";
    public string ManualKey { get; private set; } = "";

    [BindProperty] public string Code { get; set; } = "";

    public async Task<IActionResult> OnGetAsync()
    {
        if (Me.User.TotpEnrolled) return Redirect("~/");
        var secret = await users.GetPendingSecretAsync(Me.Id) ?? await users.BeginEnrollmentAsync(Me.Id);
        Show(secret);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (Me.User.TotpEnrolled) return Redirect("~/");
        var r = await users.ConfirmEnrollmentAsync(Me.Id, Code);
        if (r.Ok)
        {
            await audit.WriteAsync(Me.Id, Req, "totp.enroll", "user", Me.Id);
            Flash = "Authenticator linked. You'll need a code from it for every reveal or copy.";
            return Redirect("~/");
        }
        await audit.WriteAsync(Me.Id, Req, r.Outcome == TotpOutcome.Locked ? "totp.locked" : "totp.failed", "user", Me.Id, new { action = "enroll" });
        ModelState.AddModelError("", r.Outcome == TotpOutcome.Locked
            ? $"Too many wrong codes. Try again after {Fmt.Time(r.LockedUntil)}."
            : "That code didn't match. Check the time on your phone and try the newest code.");
        var secret = await users.GetPendingSecretAsync(Me.Id);
        if (secret is null) return RedirectToPage();
        Show(secret);
        return Page();
    }

    private void Show(byte[] secret)
    {
        var uri = Totp.ProvisioningUri(secret, options.Value.TotpIssuer, Me.User.Email);
        using var gen = new QRCodeGenerator();
        using var data = gen.CreateQrCode(uri, QRCodeGenerator.ECCLevel.M);
        QrDataUri = "data:image/png;base64," + Convert.ToBase64String(new PngByteQRCode(data).GetGraphic(8));
        ManualKey = string.Join(' ', Base32.Encode(secret).Chunk(4).Select(c => new string(c)));
    }
}
