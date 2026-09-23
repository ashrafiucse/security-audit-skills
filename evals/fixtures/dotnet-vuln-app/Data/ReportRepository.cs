using System.Data;
using System.Linq;
using Dapper;
using Microsoft.Data.SqlClient;

public class ReportRepository
{
    private readonly IDbConnection _db =
        new SqlConnection("Server=replica.example-fake.com;Database=reports;User Id=svc;Password=Fake2AlsoEval;");

    // EF Core interpolated raw SQL — SQLi
    public object ByAuthor(string author)
    {
        return _ctx.Reports
            .FromSqlRaw($"SELECT * FROM Reports WHERE Author = '{author}'")
            .ToList();
    }

    // Dapper string concatenation — SQLi
    public dynamic SearchRaw(string title)
    {
        return _db.Query("SELECT * FROM Reports WHERE Title = '" + title + "'");
    }
}
