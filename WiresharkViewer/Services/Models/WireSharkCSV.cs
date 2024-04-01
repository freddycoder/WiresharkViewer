namespace WiresharkViewer.Services.Models;

public class WireSharkCSV
{
    public int No { get; set; }

    public string? Time { get; set; }

    public string Source { get; set; } = "";

    public string Destination { get; set; } = "";

    public string Protocol { get; set; } = "";

    public string? Couche { get; set; }

    public int Length { get; set; }

    public string Info { get; set; } = "";
}
