using System;
using System.Collections.Generic;
using MiniWireshark.Models;

namespace MiniWireshark.Core.Filtering;

/// <summary>Nature de la valeur renvoyée par un champ, qui détermine comment la comparaison est évaluée.</summary>
internal enum FieldKind
{
    /// <summary>Simple test de présence de couche (ex: "tcp", "arp") — pas de comparaison possible.</summary>
    Protocol,
    Number,
    NumberList,
    Flag,
    String,
    StringList
}

internal sealed record FieldDescriptor(FieldKind Kind, Func<CapturedPacket, object?> Accessor);

/// <summary>
/// Table des champs reconnus par le filtre display, façon Wireshark (ip.addr, tcp.port, tcp.flags.syn...).
/// Ajouter un champ ici suffit à le rendre utilisable dans une expression de filtre.
/// </summary>
internal static class FieldRegistry
{
    public static readonly IReadOnlyDictionary<string, FieldDescriptor> Fields =
        new Dictionary<string, FieldDescriptor>(StringComparer.OrdinalIgnoreCase)
        {
            // Présence de couche protocolaire
            ["eth"] = new(FieldKind.Protocol, p => p.Ethernet != null),
            ["ip"] = new(FieldKind.Protocol, p => p.IPv4 != null),
            ["tcp"] = new(FieldKind.Protocol, p => p.Tcp != null),
            ["udp"] = new(FieldKind.Protocol, p => p.Udp != null),
            ["arp"] = new(FieldKind.Protocol, p => p.Arp != null),
            ["icmp"] = new(FieldKind.Protocol, p => p.Icmp != null),
            ["ipv6"] = new(FieldKind.Protocol, p => p.IPv6 != null),
            ["dns"] = new(FieldKind.Protocol, p => p.Dns != null),

            // Trame
            ["frame.len"] = new(FieldKind.Number, p => (long)p.Length),

            // Ethernet
            ["eth.type"] = new(FieldKind.Number, p => p.Ethernet != null ? (long)p.Ethernet.EtherType : null),
            ["eth.src"] = new(FieldKind.String, p => p.Ethernet?.SourceMac.ToString()),
            ["eth.dst"] = new(FieldKind.String, p => p.Ethernet?.DestinationMac.ToString()),
            ["eth.addr"] = new(FieldKind.StringList, p => p.Ethernet is { } eth
                ? new[] { eth.SourceMac.ToString(), eth.DestinationMac.ToString() }
                : null),

            // IPv4
            ["ip.proto"] = new(FieldKind.Number, p => p.IPv4 != null ? (long)p.IPv4.Protocol : null),
            ["ip.ttl"] = new(FieldKind.Number, p => p.IPv4 != null ? (long)p.IPv4.Ttl : null),
            ["ip.len"] = new(FieldKind.Number, p => p.IPv4 != null ? (long)p.IPv4.TotalLength : null),
            ["ip.src"] = new(FieldKind.String, p => p.IPv4?.SourceAddress.ToString()),
            ["ip.dst"] = new(FieldKind.String, p => p.IPv4?.DestinationAddress.ToString()),
            ["ip.addr"] = new(FieldKind.StringList, p => p.IPv4 is { } ip
                ? new[] { ip.SourceAddress.ToString(), ip.DestinationAddress.ToString() }
                : null),

            // TCP
            ["tcp.srcport"] = new(FieldKind.Number, p => p.Tcp != null ? (long)p.Tcp.SourcePort : null),
            ["tcp.dstport"] = new(FieldKind.Number, p => p.Tcp != null ? (long)p.Tcp.DestinationPort : null),
            ["tcp.port"] = new(FieldKind.NumberList, p => p.Tcp is { } tcp
                ? new long[] { tcp.SourcePort, tcp.DestinationPort }
                : null),
            ["tcp.seq"] = new(FieldKind.Number, p => p.Tcp != null ? (long)p.Tcp.SequenceNumber : null),
            ["tcp.ack"] = new(FieldKind.Number, p => p.Tcp != null ? (long)p.Tcp.AcknowledgmentNumber : null),
            ["tcp.len"] = new(FieldKind.Number, p => p.Tcp != null ? (long)p.Tcp.PayloadLength : null),
            ["tcp.window_size"] = new(FieldKind.Number, p => p.Tcp != null ? (long)p.Tcp.WindowSize : null),
            ["tcp.flags.syn"] = new(FieldKind.Flag, p => p.Tcp != null ? (bool?)p.Tcp.Syn : null),
            ["tcp.flags.ack"] = new(FieldKind.Flag, p => p.Tcp != null ? (bool?)p.Tcp.Ack : null),
            ["tcp.flags.fin"] = new(FieldKind.Flag, p => p.Tcp != null ? (bool?)p.Tcp.Fin : null),
            ["tcp.flags.rst"] = new(FieldKind.Flag, p => p.Tcp != null ? (bool?)p.Tcp.Rst : null),
            ["tcp.flags.psh"] = new(FieldKind.Flag, p => p.Tcp != null ? (bool?)p.Tcp.Psh : null),
            ["tcp.flags.urg"] = new(FieldKind.Flag, p => p.Tcp != null ? (bool?)p.Tcp.Urg : null),
            ["tcp.stream"] = new(FieldKind.Number, p => p.TcpStreamIndex.HasValue ? (long)p.TcpStreamIndex.Value : null),
            
            // UDP
            ["udp.srcport"] = new(FieldKind.Number, p => p.Udp != null ? (long)p.Udp.SourcePort : null),
            ["udp.dstport"] = new(FieldKind.Number, p => p.Udp != null ? (long)p.Udp.DestinationPort : null),
            ["udp.port"] = new(FieldKind.NumberList, p => p.Udp is { } udp
                ? new long[] { udp.SourcePort, udp.DestinationPort }
                : null),
            ["udp.len"] = new(FieldKind.Number, p => p.Udp != null ? (long)p.Udp.Length : null),

            // IPv6
            ["ipv6.src"] = new(FieldKind.String, p => p.IPv6?.SourceAddress.ToString()),
            ["ipv6.dst"] = new(FieldKind.String, p => p.IPv6?.DestinationAddress.ToString()),
            ["ipv6.addr"] = new(FieldKind.StringList, p => p.IPv6 is { } ip6
                ? new[] { ip6.SourceAddress.ToString(), ip6.DestinationAddress.ToString() }
                : null),
            ["ipv6.hlim"] = new(FieldKind.Number, p => p.IPv6 != null ? (long)p.IPv6.HopLimit : null),

            // ICMP / ICMPv6
            ["icmp.type"] = new(FieldKind.Number, p => p.Icmp != null ? (long)p.Icmp.Type : null),
            ["icmp.code"] = new(FieldKind.Number, p => p.Icmp != null ? (long)p.Icmp.Code : null),

            // ARP
            ["arp.opcode"] = new(FieldKind.Number, p => p.Arp != null ? (long)p.Arp.Opcode : null),
            ["arp.src.proto_ipv4"] = new(FieldKind.String, p => p.Arp?.SenderProtocolAddress.ToString()),
            ["arp.dst.proto_ipv4"] = new(FieldKind.String, p => p.Arp?.TargetProtocolAddress.ToString()),

            // DNS
            ["dns.qry.name"] = new(FieldKind.String, p => p.Dns is { Questions.Count: > 0 } dns ? dns.Questions[0].Name : null),
            ["dns.flags.response"] = new(FieldKind.Flag, p => p.Dns != null ? (bool?)p.Dns.IsResponse : null),
            
            // TLS
            ["tls"] = new(FieldKind.Protocol, p => p.Tls != null),
            ["tls.handshake.extensions_server_name"] = new(FieldKind.String, p => p.Tls?.ServerName),
        };
}