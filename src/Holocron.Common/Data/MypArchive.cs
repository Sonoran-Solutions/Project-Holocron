using System.IO.Compression;
using System.Text;
using ZstdSharp;

namespace Holocron.Common.Data;

/// <summary>
/// Represents a file entry within a Mythic Package (MYP / .tor) archive.
/// </summary>
public sealed class MypFileEntry
{
    public ulong FileOffset { get; init; }
    public uint HeaderSize { get; init; }
    public uint CompressedSize { get; init; }
    public uint UncompressedSize { get; init; }
    public ulong Hash { get; init; }
    public uint PrimaryHash => (uint)(Hash & 0xFFFFFFFF);
    public uint SecondaryHash => (uint)(Hash >> 32);
    public uint Crc { get; init; }
    public ushort CompressionMethod { get; init; } // 0 = uncompressed, 1 = compressed (Zstd / zlib)
    public string? KnownFilename { get; set; }

    public override string ToString()
    {
        return KnownFilename != null
            ? $"{KnownFilename} ({UncompressedSize:N0} bytes, offset: 0x{FileOffset:X8})"
            : $"0x{Hash:X16} ({UncompressedSize:N0} bytes, offset: 0x{FileOffset:X8})";
    }
}

/// <summary>
/// High-performance reader for SWTOR Mythic Package (MYP / .tor) archives.
/// Supports both legacy zlib and modern 64-bit Zstandard (Zstd) compression formats.
/// </summary>
public sealed class MypArchive : IDisposable
{
    private readonly FileStream _stream;
    private readonly BinaryReader _reader;
    private readonly List<MypFileEntry> _entries = new();
    private readonly Dictionary<ulong, MypFileEntry> _hashLookup = new();
    private static readonly Decompressor _zstdDecompressor = new();

    public string FilePath { get; }
    public uint Version { get; private set; }
    public uint BuildFlag { get; private set; }
    public ulong FirstTableOffset { get; private set; }
    public uint BlockSize { get; private set; }
    public uint TotalFiles { get; private set; }
    public IReadOnlyList<MypFileEntry> Entries => _entries;

    public MypArchive(string filePath)
    {
        FilePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        _stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024);
        _reader = new BinaryReader(_stream, Encoding.UTF8, leaveOpen: true);
        ReadHeader();
        ReadTable();
    }

    private void ReadHeader()
    {
        Span<byte> magic = stackalloc byte[4];
        if (_stream.Read(magic) != 4 || magic[0] != 'M' || magic[1] != 'Y' || magic[2] != 'P' || magic[3] != 0)
        {
            throw new InvalidDataException($"File '{FilePath}' is not a valid MYP archive (invalid magic header).");
        }

        Version = _reader.ReadUInt32();
        BuildFlag = _reader.ReadUInt32();
        FirstTableOffset = _reader.ReadUInt64();
        BlockSize = _reader.ReadUInt32();
        TotalFiles = _reader.ReadUInt32();
    }

    private void ReadTable()
    {
        ulong currentTableOffset = FirstTableOffset;

        while (currentTableOffset != 0 && currentTableOffset < (ulong)_stream.Length)
        {
            _stream.Seek((long)currentTableOffset, SeekOrigin.Begin);
            uint entryCount = _reader.ReadUInt32();
            ulong nextTableOffset = _reader.ReadUInt64();

            for (uint i = 0; i < entryCount; i++)
            {
                ulong fileOffset = _reader.ReadUInt64();
                uint headerSize = _reader.ReadUInt32();
                uint compressedSize = _reader.ReadUInt32();
                uint uncompressedSize = _reader.ReadUInt32();
                ulong hash = _reader.ReadUInt64();
                uint crc = _reader.ReadUInt32();
                ushort compressionMethod = _reader.ReadUInt16();

                // Skip empty / sentinel entries
                if (fileOffset == 0 && hash == 0)
                    continue;

                var entry = new MypFileEntry
                {
                    FileOffset = fileOffset,
                    HeaderSize = headerSize,
                    CompressedSize = compressedSize,
                    UncompressedSize = uncompressedSize,
                    Hash = hash,
                    Crc = crc,
                    CompressionMethod = compressionMethod
                };

                _entries.Add(entry);
                _hashLookup.TryAdd(hash, entry);
            }

            currentTableOffset = nextTableOffset;
        }
    }

    /// <summary>
    /// Extracts a file entry into memory, automatically handling uncompressed, Zstd, or zlib formats.
    /// </summary>
    public byte[] Extract(MypFileEntry entry)
    {
        if (entry.FileOffset == 0 || entry.CompressedSize == 0)
            return Array.Empty<byte>();

        _stream.Seek((long)(entry.FileOffset + entry.HeaderSize), SeekOrigin.Begin);
        byte[] data = _reader.ReadBytes((int)entry.CompressedSize);

        if (entry.CompressionMethod == 0 || entry.CompressedSize == entry.UncompressedSize)
        {
            return data;
        }

        // Check for Zstandard magic header: 0xFD2FB528 (little-endian: 0x28, 0xB5, 0x2F, 0xFD)
        if (data.Length >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD)
        {
            lock (_zstdDecompressor)
            {
                return _zstdDecompressor.Unwrap(data, (int)entry.UncompressedSize).ToArray();
            }
        }

        // Fallback to ZLib / Deflate
        try
        {
            using var memoryStream = new MemoryStream(data);
            using var zlibStream = new ZLibStream(memoryStream, CompressionMode.Decompress);
            using var outputStream = new MemoryStream((int)entry.UncompressedSize);
            zlibStream.CopyTo(outputStream);
            return outputStream.ToArray();
        }
        catch
        {
            using var memoryStream = new MemoryStream(data);
            using var deflateStream = new DeflateStream(memoryStream, CompressionMode.Decompress);
            using var outputStream = new MemoryStream((int)entry.UncompressedSize);
            deflateStream.CopyTo(outputStream);
            return outputStream.ToArray();
        }
    }

    /// <summary>
    /// Tries to get an entry by its 64-bit hash.
    /// </summary>
    public bool TryGetEntry(ulong hash, out MypFileEntry? entry)
    {
        return _hashLookup.TryGetValue(hash, out entry);
    }

    public void Dispose()
    {
        _reader.Dispose();
        _stream.Dispose();
    }
}
