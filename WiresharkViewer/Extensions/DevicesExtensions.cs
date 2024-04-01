using System.Net;
using WiresharkViewer.Services.Models;

namespace WiresharkViewer.Extensions;

public static class DevicesExtensions
{
    public static Device NewDevicesFromIPv4(WireSharkCSV wireSharkCSV, string ipv4, string name)
    {
        var d = new Device
        {
            IPv4 = IPAddress.Parse(ipv4),
            Name = name
        };

        if (!string.IsNullOrWhiteSpace(wireSharkCSV.Protocol))
        {
            d.Protocols.Add(wireSharkCSV.Protocol);
        }

        return d;
    }
}
