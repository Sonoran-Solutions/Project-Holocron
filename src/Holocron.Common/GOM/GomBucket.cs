using System.Buffers.Binary;
using System.Text;

namespace Holocron.Common.GOM;

/// <summary>
/// Parser for SWTOR PBUK (Package Bucket) files containing GOM DBLB nodes.
/// </summary>
public sealed class GomBucket
{
    public uint Version { get; }
    public List<GomNode> Nodes { get; } = new();

    public GomBucket(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8 || data[0] != 'P' || data[1] != 'B' || data[2] != 'U' || data[3] != 'K')
        {
            throw new InvalidDataException("Invalid PBUK magic header.");
        }

        Version = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        int offset = 8;

        // Parse DBLB nodes
        while (offset + 16 <= data.Length)
        {
            if (data[offset] == 'D' && data[offset + 1] == 'B' && data[offset + 2] == 'L' && data[offset + 3] == 'B')
            {
                offset += 4;
                if (offset + 20 > data.Length) break;

                ulong nodeId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));
                offset += 8;

                uint dataSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
                offset += 4;

                if (offset + (int)dataSize > data.Length) break;

                byte[] rawNodeData = data.Slice(offset, (int)dataSize).ToArray();
                offset += (int)dataSize;

                var node = new GomNode
                {
                    NodeId = nodeId,
                    RawData = rawNodeData
                };

                Nodes.Add(node);
            }
            else
            {
                offset++;
            }
        }
    }
}
