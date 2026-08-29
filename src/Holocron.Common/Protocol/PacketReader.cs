using System.Text;

namespace Holocron.Common.Protocol;

/// <summary>
/// Deserializer for binary packets received from SWTOR client or server.
/// </summary>
public sealed class PacketReader
{
    private readonly MemoryStream _stream;
    private readonly BinaryReader _reader;

    public Opcode Opcode { get; }
    public uint Type { get; }
    public ushort ContentVersion { get; }
    public ushort TransportVersion { get; }

    public int RemainingBytes => (int)(_stream.Length - _stream.Position);

    public PacketReader(byte[] payload)
    {
        if (payload == null || payload.Length < 12)
            throw new ArgumentException("Payload is too short to contain a valid 12-byte header.", nameof(payload));

        _stream = new MemoryStream(payload);
        _reader = new BinaryReader(_stream, Encoding.UTF8);

        Opcode = (Opcode)_reader.ReadUInt32();
        Type = _reader.ReadUInt32();
        ContentVersion = _reader.ReadUInt16();
        TransportVersion = _reader.ReadUInt16();
    }

    public byte ReadByte() => _reader.ReadByte();
    public bool ReadBoolean() => _reader.ReadByte() != 0;
    public short ReadInt16() => _reader.ReadInt16();
    public ushort ReadUInt16() => _reader.ReadUInt16();
    public int ReadInt32() => _reader.ReadInt32();
    public uint ReadUInt32() => _reader.ReadUInt32();
    public long ReadInt64() => _reader.ReadInt64();
    public ulong ReadUInt64() => _reader.ReadUInt64();
    public float ReadFloat() => _reader.ReadSingle();
    public double ReadDouble() => _reader.ReadDouble();
    public byte[] ReadBytes(int count) => _reader.ReadBytes(count);

    public string ReadString()
    {
        ushort length = _reader.ReadUInt16();
        byte[] bytes = _reader.ReadBytes(length);
        return Encoding.UTF8.GetString(bytes);
    }

    public string ReadLongString()
    {
        ulong length = _reader.ReadUInt64();
        byte[] bytes = _reader.ReadBytes((int)length);
        return Encoding.UTF8.GetString(bytes);
    }

    public uint ReadPackedUInt32()
    {
        uint result = 0;
        int shift = 0;
        while (true)
        {
            byte b = _reader.ReadByte();
            result |= (uint)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                break;
            shift += 7;
        }
        return result;
    }
}
