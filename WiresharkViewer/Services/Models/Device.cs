using System.Net;

namespace WiresharkViewer.Services.Models;

public class Device : IComparable<Device>
{
    public string? Name { get; set; }

    public IPAddress? IPv4 { get; set; }

    public IPAddress? IPv6 { get; set; }

    public string? MAC { get; set; }

    public HashSet<string> Protocols { get; set; } = new HashSet<string>();

    public override bool Equals(object? obj)
    {
        return base.Equals(obj);
    }

    public override int GetHashCode()
    {
        return IPv4?.GetHashCode() ?? Name?.GetHashCode() ?? IPv6?.GetHashCode() ?? MAC?.GetHashCode() ?? 0;
    }

    public override string ToString()
    {
        return $"{Name}: {IPv4}: {IPv6}: {MAC}";
    }

    public int CompareTo(Device? other)
    {
        var ba = IPv4?.GetAddressBytes();
        var bb = other?.IPv4?.GetAddressBytes();

        if (ba == bb) return 0;

        if (ba == null) return 1;

        if (bb == null) return -1;

        return ba[^1].CompareTo(bb[^1]);
    }
}
