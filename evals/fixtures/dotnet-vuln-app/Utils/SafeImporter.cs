using System.IO;
using System.Text.Json;

public class SafeImporter
{
    // JSON, no polymorphic type names — safe form
    public ReportImport Import(Stream body)
    {
        using var reader = new StreamReader(body);
        return JsonSerializer.Deserialize<ReportImport>(reader.ReadToEnd());
    }

    // DTD off, resolver null — safe form
    public string ReadConfig(Stream s)
    {
        var settings = new System.Xml.XmlReaderSettings
        {
            DtdProcessing = System.Xml.DtdProcessing.Ignore,
            XmlResolver = null
        };
        using var reader = System.Xml.XmlReader.Create(s, settings);
        reader.MoveToContent();
        return reader.ReadInnerXml();
    }
}
