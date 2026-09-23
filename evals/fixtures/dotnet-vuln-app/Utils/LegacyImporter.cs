using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml;

public class LegacyImporter
{
    // Untrusted deserialization: BinaryFormatter on request bytes
    public ReportImport Import(Stream body)
    {
        var fmt = new BinaryFormatter();
        return (ReportImport)fmt.Deserialize(body);
    }

    // XXE: DTD processing enabled on untrusted XML
    public string ReadConfig(Stream s)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        using var reader = XmlReader.Create(s, settings);
        reader.MoveToContent();
        return reader.ReadInnerXml();
    }
}
