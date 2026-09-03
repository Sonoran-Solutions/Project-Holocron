using Holocron.Common.Combat;
using Holocron.World.Combat;

namespace Holocron.World.Encounters;

/// <summary>
/// Manages stacking debuffs on tanks and coordinates tank swaps between Main Tank and Off-Tank bots.
/// </summary>
public sealed class TankSwapMechanic
{
    public const string DebuffName = "Armor Sundering";
    public int MaxStacksBeforeSwap { get; init; } = 2;
    public float DebuffDuration { get; init; } = 15.0f;

    public void ApplyBossHit(CombatEntity target)
    {
        var existing = target.ActiveAuras.FirstOrDefault(a => a.Name == DebuffName);
        if (existing == null)
        {
            target.ActiveAuras.Add(new Aura
            {
                Name = DebuffName,
                DurationRemaining = DebuffDuration,
                EffectType = AbilityEffectType.DefenseBuff, // used here as a debuff marker
                ValuePerTick = 1 // 1 stack
            });
        }
        else
        {
            existing.DurationRemaining = DebuffDuration;
            existing.ValuePerTick = Math.Min(5, existing.ValuePerTick + 1); // increment stacks
        }
    }

    public int GetStackCount(CombatEntity tank)
    {
        var aura = tank.ActiveAuras.FirstOrDefault(a => a.Name == DebuffName);
        return aura != null ? (int)aura.ValuePerTick : 0;
    }

    public bool ShouldOffTankSwap(CombatEntity currentTank, CombatEntity offTank)
    {
        int currentStacks = GetStackCount(currentTank);
        int offTankStacks = GetStackCount(offTank);

        // Off-tank should swap when current tank has reached swap threshold and off-tank is clear
        return currentStacks >= MaxStacksBeforeSwap && offTankStacks == 0;
    }
}
