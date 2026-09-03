using DotRecast.Core.Numerics;

namespace Holocron.World.Encounters;

/// <summary>
/// Security terminal or power conduit inside flashpoints.
/// </summary>
public sealed class InteractiveConsole
{
    public uint Id { get; init; }
    public string Name { get; init; } = "Security Terminal";
    public RcVec3f Position { get; init; }
    public bool IsHacked { get; private set; }

    public bool Interact(ulong interactorGuid)
    {
        if (IsHacked) return false;
        IsHacked = true;
        Console.WriteLine($"[DUNGEON] Console '{Name}' activated by Entity #{interactorGuid}!");
        return true;
    }
}

/// <summary>
/// Heavy blast door separating flashpoint zones/encounters.
/// Opens when its linked security console is hacked or boss is defeated.
/// </summary>
public sealed class BlastDoor
{
    public uint Id { get; init; }
    public string Name { get; init; } = "Sector Blast Door";
    public RcVec3f Position { get; init; }
    public bool IsLocked { get; private set; } = true;
    public bool IsOpen { get; private set; }
    public uint RequiredConsoleId { get; init; }

    public bool TryOpenWithConsole(InteractiveConsole console)
    {
        if (console.Id == RequiredConsoleId && console.IsHacked)
        {
            IsLocked = false;
            IsOpen = true;
            Console.WriteLine($"[DUNGEON] Blast Door '{Name}' UNLOCKED and OPENED!");
            return true;
        }

        return false;
    }

    public void UnlockOnBossDefeat()
    {
        IsLocked = false;
        IsOpen = true;
        Console.WriteLine($"[DUNGEON] Blast Door '{Name}' UNLOCKED via Emergency Boss Override!");
    }
}
