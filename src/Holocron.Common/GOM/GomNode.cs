using System.Text;

namespace Holocron.Common.GOM;

/// <summary>
/// Represents a raw GOM (Game Object Model) database node parsed from a PBUK (DBLB) bucket.
/// </summary>
public sealed class GomNode
{
    public ulong NodeId { get; init; }
    public ulong DefinitionId { get; init; }
    public byte[] RawData { get; init; } = Array.Empty<byte>();
    public Dictionary<ulong, object> Fields { get; } = new();

    public override string ToString() => $"GOM Node 0x{NodeId:X16} (Def: 0x{DefinitionId:X16}, Data: {RawData.Length} bytes)";
}
