using System.Buffers.Binary;
using System.Text;

namespace Holocron.Common.Protocol;

/// <summary>
/// Serializer for binary packets conforming to SWTOR / HeroEngine stream format.
/// </summary>
public sealed class PacketWriter
{
    private readonly MemoryStream _stream;
    private readonly BinaryWriter _writer;

    public Opcode Opcode { get; }
    public uint Type { get; set; }
    public ushort ContentVersion { get; set; }
    public ushort TransportVersion { get; set; }

    public PacketWriter(Opcode opcode, uint type = 0, ushort contentVersion = 0x08, ushort transportVersion = 0x00)
    {
        Opcode = opcode;
        Type = type;
        ContentVersion = contentVersion;
        TransportVersion = transportVersion;

        _stream = new MemoryStream(256);
        _writer = new BinaryWriter(_stream, Encoding.UTF8);

        // Reserve header space (Opcode: 4B, Type: 4B, ContentV: 2B, TransportV: 2B = 12B)
        _writer.Write((uint)Opcode);
        _writer.Write(Type);
        _writer.Write(ContentVersion);
        _writer.Write(TransportVersion);
    }

    public PacketWriter WriteByte(byte value) { _writer.Write(value); return this; }
    public PacketWriter WriteBoolean(bool value) { _writer.Write(value ? (byte)1 : (byte)0); return this; }
    public PacketWriter WriteInt16(short value) { _writer.Write(value); return this; }
    public PacketWriter WriteUInt16(ushort value) { _writer.Write(value); return this; }
    public PacketWriter WriteInt32(int value) { _writer.Write(value); return this; }
    public PacketWriter WriteUInt32(uint value) { _writer.Write(value); return this; }
    public PacketWriter WriteInt64(long value) { _writer.Write(value); return this; }
    public PacketWriter WriteUInt64(ulong value) { _writer.Write(value); return this; }
    public PacketWriter WriteFloat(float value) { _writer.Write(value); return this; }
    public PacketWriter WriteDouble(double value) { _writer.Write(value); return this; }

    public PacketWriter WriteBytes(ReadOnlySpan<byte> data)
    {
        _writer.Write(data);
        return this;
    }

    /// <summary>
    /// Writes length-prefixed UTF-8 string (uint16 length + bytes).
    /// </summary>
    public PacketWriter WriteString(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        _writer.Write((ushort)bytes.Length);
        _writer.Write(bytes);
        return this;
    }

    /// <summary>
    /// Writes length-prefixed 64-bit string (uint64 length + bytes) used in dynamic character properties.
    /// </summary>
    public PacketWriter WriteLongString(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        _writer.Write((ulong)bytes.Length);
        _writer.Write(bytes);
        return this;
    }

    /// <summary>
    /// Writes variable-length packed integer.
    /// </summary>
    public PacketWriter WritePackedUInt32(uint value)
    {
        while (value >= 0x80)
        {
            _writer.Write((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }
        _writer.Write((byte)value);
        return this;
    }

    public byte[] ToByteArray()
    {
        _writer.Flush();
        return _stream.ToArray();
    }
}
