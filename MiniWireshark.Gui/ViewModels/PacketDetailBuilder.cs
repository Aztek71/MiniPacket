using System.Collections.Generic;
using MiniWireshark.Core.Analysis;
using MiniWireshark.Models;
using MiniWireshark.Core.Processes;

namespace MiniWireshark.Gui.ViewModels;

/// <summary>
/// Construit l'arbre de detail affiche quand on selectionne un paquet dans la liste.
/// Un noeud racine par couche protocolaire presente, avec ses champs en enfants.
/// </summary>
public static class PacketDetailBuilder
{
    public static IReadOnlyList<PacketDetailNode> Build(CapturedPacket packet)
    {
        var roots = new List<PacketDetailNode>();

        var frame = new PacketDetailNode($"Frame {packet.Number}: {packet.Length} bytes captured");
        frame.Add($"Timestamp: {packet.Timestamp:HH:mm:ss.fff}");
        if (packet.ProcessName is not null)
            frame.Add($"Processus : {packet.ProcessDisplay}");
        roots.Add(frame);

        if (packet.Ethernet is { } eth)
        {
            var node = new PacketDetailNode($"Ethernet II, Src: {eth.SourceMac}, Dst: {eth.DestinationMac}");
            node.Add($"Destination: {eth.DestinationMac}");
            node.Add($"Source: {eth.SourceMac}");
            node.Add($"Type: {eth.EtherTypeName} (0x{eth.EtherType:X4})");
            roots.Add(node);
        }

        if (packet.Arp is { } arp)
        {
            var node = new PacketDetailNode($"Address Resolution Protocol ({arp.OpcodeName})");
            node.Add($"Opcode: {arp.OpcodeName} ({arp.Opcode})");
            node.Add($"Sender MAC: {arp.SenderHardwareAddress}");
            node.Add($"Sender IP: {arp.SenderProtocolAddress}");
            node.Add($"Target MAC: {arp.TargetHardwareAddress}");
            node.Add($"Target IP: {arp.TargetProtocolAddress}");
            roots.Add(node);
        }

        if (packet.IPv4 is { } ip)
        {
            var node = new PacketDetailNode($"Internet Protocol Version 4, Src: {ip.SourceAddress}, Dst: {ip.DestinationAddress}");
            node.Add($"Header Length: {ip.HeaderLength} bytes");
            node.Add($"Total Length: {ip.TotalLength}");
            node.Add($"Time to Live: {ip.Ttl}");
            node.Add($"Protocol: {ip.ProtocolName} ({ip.Protocol})");
            node.Add($"Source: {ip.SourceAddress}");
            node.Add($"Destination: {ip.DestinationAddress}");
            roots.Add(node);
        }

        if (packet.IPv6 is { } ip6)
        {
            var node = new PacketDetailNode($"Internet Protocol Version 6, Src: {ip6.SourceAddress}, Dst: {ip6.DestinationAddress}");
            node.Add($"Payload Length: {ip6.PayloadLength} bytes");
            node.Add($"Next Header: {ip6.ProtocolName} ({ip6.NextHeader})");
            node.Add($"Hop Limit: {ip6.HopLimit}");
            node.Add($"Source: {ip6.SourceAddress}");
            node.Add($"Destination: {ip6.DestinationAddress}");
            roots.Add(node);
        }

        if (packet.Icmp is { } icmp)
        {
            var node = new PacketDetailNode($"Internet Control Message Protocol, {icmp.TypeName}");
            node.Add($"Type: {icmp.Type} ({icmp.TypeName})");
            node.Add($"Code: {icmp.Code}");
            if (icmp.Identifier != 0 || icmp.Sequence != 0)
            {
                node.Add($"Identifier: {icmp.Identifier}");
                node.Add($"Sequence: {icmp.Sequence}");
            }
            roots.Add(node);
        }

        if (packet.Tcp is { } tcp)
        {
            var node = new PacketDetailNode($"Transmission Control Protocol, Src Port: {tcp.SourcePort}, Dst Port: {tcp.DestinationPort}");
            node.Add($"Source Port: {tcp.SourcePort}");
            node.Add($"Destination Port: {tcp.DestinationPort}");
            node.Add($"Sequence Number: {tcp.SequenceNumber}");
            node.Add($"Acknowledgment Number: {tcp.AcknowledgmentNumber}");
            node.Add($"Window Size: {tcp.WindowSize}");
            node.Add($"Flags: {tcp.FlagsSummary}");
            node.Add($"Payload Length: {tcp.PayloadLength} bytes");
            roots.Add(node);
        }
        
        if (packet.Tls is { } tls)
        {
            string sni = tls.ServerName ?? "(non lu : message tronque ou extension absente)";
            var node = new PacketDetailNode("Transport Layer Security (Client Hello)");
            node.Add($"Server Name (SNI): {sni}");
            roots.Add(node);
        }

        if (packet.Udp is { } udp)
        {
            var node = new PacketDetailNode($"User Datagram Protocol, Src Port: {udp.SourcePort}, Dst Port: {udp.DestinationPort}");
            node.Add($"Source Port: {udp.SourcePort}");
            node.Add($"Destination Port: {udp.DestinationPort}");
            node.Add($"Length: {udp.Length}");
            node.Add($"Payload Length: {udp.PayloadLength} bytes");
            roots.Add(node);
        }

        if (packet.Dns is { } dns)
        {
            var node = new PacketDetailNode($"Domain Name System ({(dns.IsResponse ? "response" : "query")})");
            node.Add($"Transaction ID: 0x{dns.Id:x4}");
            node.Add($"Flags: {(dns.IsResponse ? "response" : "query")}");

            if (dns.Questions.Count > 0)
            {
                var questions = node.Add($"Questions: {dns.Questions.Count}");
                foreach (var q in dns.Questions)
                    questions.Add($"{q.Name}: type {q.TypeName}, class {q.Class}");
            }

            if (dns.Answers.Count > 0)
            {
                var answers = node.Add($"Answers: {dns.Answers.Count}");
                foreach (var a in dns.Answers)
                    answers.Add($"{a.Name}: type {a.TypeName}, ttl {a.Ttl}" + (a.Data is not null ? $", data {a.Data}" : string.Empty));
            }

            roots.Add(node);
        }

        if (packet.Anomalies.Count > 0)
        {
            var node = new PacketDetailNode($"Analyse : {packet.Anomalies.Count} anomalie(s) détectée(s)");
            foreach (var anomaly in packet.Anomalies)
            {
                string severity = anomaly.Severity switch
                {
                    AnomalySeverity.Error => "Erreur",
                    AnomalySeverity.Warning => "Attention",
                    _ => "Info"
                };
                node.Add($"[{severity}] {anomaly.Label} : {anomaly.Description}");
            }
            roots.Add(node);
        }

        return roots;
    }
}