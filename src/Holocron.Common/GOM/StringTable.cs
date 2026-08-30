using System.Buffers.Binary;
using System.Text;

namespace Holocron.Common.GOM;

/// <summary>
/// Parser for SWTOR Localization String Tables (.stb).
/// Contains mapped game strings (dialogue, quest texts, item names, ability tooltips).
/// </summary>
public sealed class StringTable
{
    private readonly Dictionary<ulong, string> _strings = new();

    public IReadOnlyDictionary<ulong, string> Strings => _strings;

    public StringTable(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8) return;

        // Check STB magic (0x01 0x00 0x00 ...)
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));

        int offset = 8;
        for (uint i = 0; i < count && offset + 12 <= data.Length; i++)
        {
            ulong stringId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));
            offset += 8;

            int stringLen = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
            offset += 4;

            if (stringLen > 0 && offset + stringLen <= data.Length)
            {
                string text = Encoding.UTF8.GetString(data.Slice(offset, stringLen));
                _strings[stringId] = text;
                offset += stringLen;
            }
        }
    }

    public string? GetString(ulong id) => _strings.TryGetValue(id, out var str) ? str : null;
}
