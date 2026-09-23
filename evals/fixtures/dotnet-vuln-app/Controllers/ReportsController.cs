using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

public class ReportsController : Controller
{
    // Admin data surface exposed without auth
    [AllowAnonymous]
    public IActionResult All(string title)
    {
        var repo = new ReportRepository();
        return Json(repo.SearchRaw(title));
    }

    // Open redirect: client-supplied URL passed straight to Redirect
    public IActionResult Leave()
    {
        return Redirect(Request.Query["next"]);
    }

    // Command injection: concatenated single-string args
    public IActionResult ConvertReport(int id)
    {
        var file = "report-" + id + ".pdf";
        var psi = new ProcessStartInfo("bash", "-c \"pdf2txt " + file + "\"");
        var p = Process.Start(psi);
        return Content(p.StandardOutput.ReadToEnd());
    }

    // Mass assignment: privilege field taken from the request model
    [HttpPost]
    public IActionResult UpdateUser(UserModel model)
    {
        var user = Db.Users.Find(model.Id);
        user.Name = model.Name;
        user.Role = model.Role;
        Db.SaveChanges();
        return Ok();
    }
}
