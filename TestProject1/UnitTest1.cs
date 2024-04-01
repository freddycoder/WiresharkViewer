using AutoFixture.Xunit2;
using System.Text;
using WiresharkViewer.Services;

namespace TestProject1;

public class UnitTest1
{
    static private string[]? pcap;

    public UnitTest1()
    {
        if (pcap == null)
        {
            pcap = File.ReadAllLines(@"C:\Users\jacqu\source\repos\WiresharkViewer\export-1.csv");
        }
    }

    [Fact]
    public void RouterAsus()
    {
        var networkReport = new NetworkReport();
        var sb = new StringBuilder();

        networkReport.GenerateReport(pcap, sb);

        Assert.Empty(sb.ToString());

        var router = networkReport.devices?.Single(d => d.IPv4?.ToString() == "192.168.50.1");

        Assert.NotNull(router);
        Assert.Equal("ASUSTekCOMPU_9a:63:18", router.Name);
        Assert.Equal("c8:7f:54:9a:63:18", router.MAC);
        Assert.Contains("ARP", router.Protocols);
        Assert.Contains("IGMPv3", router.Protocols);
    }

    [Fact]
    public void MiniHP()
    {
        var networkReport = new NetworkReport();
        var sb = new StringBuilder();

        networkReport.GenerateReport(pcap, sb);

        Assert.Empty(sb.ToString());

        var router = networkReport.devices?.Single(d => d.IPv4?.ToString() == "192.168.50.168");

        Assert.NotNull(router);
        Assert.Equal("HewlettPacka_55:49:73", router.Name);
        Assert.Equal("48:0f:cf:55:49:73", router.MAC);
    }

    [Fact]
    public void DVR()
    {
        var networkReport = new NetworkReport();
        var sb = new StringBuilder();

        networkReport.GenerateReport(pcap, sb);

        Assert.Empty(sb.ToString());

        var router = networkReport.devices?.Single(d => d.IPv4?.ToString() == "192.168.50.174");

        Assert.NotNull(router);
        Assert.Equal("Cisco_79:23:4c", router.Name);
        Assert.Contains("UDP", router.Protocols);
    }

    [Fact]
    public void DefaultRoute()
    {
        var networkReport = new NetworkReport();
        var sb = new StringBuilder();

        networkReport.GenerateReport(pcap, sb);

        Assert.Empty(sb.ToString());

        var router = networkReport.devices?.SingleOrDefault(d => d.IPv4?.ToString() == "0.0.0.0");

        Assert.Null(router);
    }
}