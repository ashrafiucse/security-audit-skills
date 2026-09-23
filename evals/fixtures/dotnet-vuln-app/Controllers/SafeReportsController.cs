using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

public class SafeReportsController : Controller
{
    // Auth-guarded data surface
    [Authorize(Policy = "Staff")]
    public IActionResult All(string title)
    {
        var repo = new SafeReportRepository();
        return Json(repo.Search(title));
    }

    // Redirect behind a local-URL allowlist check
    public IActionResult Leave()
    {
        var next = Request.Query["next"];
        if (!Url.IsLocalUrl(next)) return RedirectToAction("Index");
        return Redirect(next);
    }

    // Argument list form: no concatenated shell string
    public IActionResult ConvertReport(int id)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "pdf2txt",
            UseShellExecute = false
        };
        psi.ArgumentList.Add($"report-{id}.pdf");
        return Content("");
    }

    // Mass assignment guarded: explicit allowlist bind
    [HttpPost]
    public IActionResult UpdateUser(UserModel model)
    {
        var user = Db.Users.Find(model.Id);
        user.Name = model.Name;
        Db.SaveChanges();
        return Ok();
    }
}
