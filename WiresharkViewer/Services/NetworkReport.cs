using System.Net;
using System.Text;
using WiresharkViewer.Extensions;
using WiresharkViewer.Services.Models;

namespace WiresharkViewer.Services;

public partial class NetworkReport
{
    private readonly string[] pcap;

    public WireSharkCSV[]? structureCSV { get; set; }

    public IEnumerable<IGrouping<string, WireSharkCSV>>? uniqueIP { get; set; }

    public SortedSet<Device>? devices { get; set; }

    public NetworkReport()
    {
        pcap = new string[0];
    }

    public void GenerateReport(string[]? pcap, StringBuilder errorMessages)
    {
        if (pcap == null)
        {
            return;
        }

        structureCSV = ParseCSV(pcap, errorMessages);

        uniqueIP = structureCSV.GroupBy(c => c.Source);

        devices = new SortedSet<Device>();

        foreach (var line in structureCSV)
        {
            if (IsIPv4(line.Source) &&
                line.Source.StartsWith("255") == false &&
                line.Source.StartsWith("224") == false &&
                line.Source != "0.0.0.0")
            {
                var d = devices.FirstOrDefault(d => d.IPv4?.ToString() == line.Source);

                if (d == null)
                {
                    devices.Add(new Device 
                    { 
                        IPv4 = IPAddress.Parse(line.Source) 
                    });
                }
                else
                {
                    d.Protocols.Add(line.Protocol);
                }
            }

            if (IsIPv4(line.Destination) &&
                line.Destination.StartsWith("255") == false &&
                line.Destination.StartsWith("224") == false &&
                line.Destination != "0.0.0.0")
            {
                var d = devices.FirstOrDefault(d => d.IPv4?.ToString() == line.Destination);

                if (d == null)
                {
                    devices.Add(new Device 
                    { 
                        IPv4 = IPAddress.Parse(line.Destination) 
                    });
                }
                else
                {
                    d.Protocols.Add(line.Protocol);
                }
            }

            if (line.Protocol == "ARP" && 
                line.Info.StartsWith("Who has "))
            {
                // parse both ip adresse in the arp info
                // arp info look like this: Who has 192.168.50.1? Tell 192.168.50.168

                var regex = IPv4Regex();

                var matches = regex.Matches(line.Info);

                if (matches.Count == 2)
                {
                    var ip1 = matches[0].Value;
                    var ip2 = matches[1].Value;

                    if (ip2 != "0.0.0.0" && !devices.Any(d => d.IPv4?.ToString() == ip2))
                    {
                        devices.Add(DevicesExtensions.NewDevicesFromIPv4(line, ip2, line.Source));
                    }

                    if (ip1 != "0.0.0.0" && !devices.Any(d => d.IPv4?.ToString() == ip1))
                    {
                        devices.Add(DevicesExtensions.NewDevicesFromIPv4(line, ip1, line.Destination));
                    }
                }
            }

            if (line.Protocol == "ARP" && 
                line.Info.Contains("Gratuitous ARP for") &&
                line.Source != "0.0.0.0")
            {
                var regex = IPv4Regex();

                var matches = regex.Matches(line.Info);

                var d = devices.FirstOrDefault(d => d.IPv4?.ToString() == matches[0].Value);

                if (d == null) 
                {
                    devices.Add(DevicesExtensions.NewDevicesFromIPv4(line, matches[0].Value, line.Source));
                }
                else
                {
                    d.Name = line.Source;
                }
            }

            if (line.Protocol == "ARP" && 
                line.Info.Contains("is at ") && 
                line.Destination != "Broadcast" &&
                line.Source != "0.0.0.0")
            {
                // save the mac adresse in the device
                // a regex that parse a mac adresse look like this: 00:00:00:00:00:00

                var regex = MACAddress();

                var matches = regex.Matches(line.Info);

                if (matches.Count == 1)
                {
                    var mac = matches[0].Value;

                    var device = devices.FirstOrDefault(d => d.Name == line.Source);

                    if (device != null)
                    {
                        device.MAC = mac;
                    }
                }
            }
        }
    }

    private static WireSharkCSV[] ParseCSV(string[]? pcap, StringBuilder errorMessages)
    {
        if (pcap == null)
        {
            return new WireSharkCSV[0];
        }

        return pcap.Skip(1).Select(l =>
        {
            Console.WriteLine($"Parse: {l}");

            var cells = l.Split(',');

            try
            {
                return new WireSharkCSV
                {
                    No = int.Parse(cells[0].Replace("\"", "")),
                    Time = cells[1].Replace("\"", ""),
                    Source = cells[2].Replace("\"", ""),
                    Destination = cells[3].Replace("\"", ""),
                    Protocol = cells[4].Replace("\"", ""),
                    Length = int.Parse(cells[5].Replace("\"", "")),
                    Info = cells[6].Replace("\"", "")
                };
            }
            catch (Exception inner)
            {
                Console.Error.WriteLine($"Error parsing line: {l}");
                errorMessages.AppendLine($"Error parsing line: {l}. {inner.Message}");
                return new WireSharkCSV();
            }
        }).ToArray();
    }

    private bool IsIPv4(string source)
    {
        return IPv4Regex().IsMatch(source);
    }

    [System.Text.RegularExpressions.GeneratedRegex("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b")]
    private static partial System.Text.RegularExpressions.Regex IPv4Regex();
    
    [System.Text.RegularExpressions.GeneratedRegex("\\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\\b")]
    private static partial System.Text.RegularExpressions.Regex MACAddress();
}
