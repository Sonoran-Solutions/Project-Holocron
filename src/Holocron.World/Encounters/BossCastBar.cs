namespace Holocron.World.Encounters;

/// <summary>
/// Represents an active telegraph/cast bar for high-threat boss abilities.
/// Can be interrupted by players or companion bots with interrupt abilities (e.g. Force Kick).
/// </summary>
public sealed class BossCastBar
{
    public string AbilityName { get; init; } = "Overload Blast";
    public float TotalCastTime { get; init; } = 3.0f;
    public float CastTimeRemaining { get; set; } = 3.0f;
    public float DamageOnComplete { get; init; } = 350.0f;
    public bool IsInterruptible { get; init; } = true;
    public bool IsActive { get; set; } = true;
    public bool WasInterrupted { get; private set; }

    public bool Interrupt(string interrupterName)
    {
        if (!IsActive || !IsInterruptible) return false;

        IsActive = false;
        WasInterrupted = true;
        Console.WriteLine($"[ENCOUNTER] {AbilityName} was INTERRUPTED by {interrupterName}!");
        return true;
    }

    public bool Update(float deltaSeconds, out float damageDealt)
    {
        damageDealt = 0.0f;
        if (!IsActive) return false;

        CastTimeRemaining -= deltaSeconds;
        if (CastTimeRemaining <= 0)
        {
            IsActive = false;
            damageDealt = DamageOnComplete;
            return true; // Cast completed successfully!
        }

        return false;
    }
}
