using System.Data;
using System.Linq;
using Dapper;
using Microsoft.Data.SqlClient;

public class SafeReportRepository
{
    private readonly IDbConnection _db =
        new SqlConnection("Server=replica.example-fake.com;Database=reports;User Id=svc;Password=Fake2AlsoEval;");

    // EF Core interpolated API parameterizes by contract — safe form
    public object ByAuthor(string author)
    {
        return _ctx.Reports
            .FromSqlInterpolated($"SELECT * FROM Reports WHERE Author = {author}")
            .ToList();
    }

    // Dapper parameter object — safe form
    public dynamic Search(string title)
    {
        return _db.Query(
            "SELECT * FROM Reports WHERE Title = @Title",
            new { Title = title });
    }
}
