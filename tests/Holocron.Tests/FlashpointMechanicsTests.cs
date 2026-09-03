using DotRecast.Core.Numerics;
using Holocron.Common.Combat;
using Holocron.World.Combat;
using Holocron.World.Encounters;
using Xunit;

namespace Holocron.Tests;

public class FlashpointMechanicsTests
{
    [Fact]
    public void BossCastBar_InterruptedByCompanionBot_PreventsWipeDamage()
    {
        var castBar = new BossCastBar
        {
            AbilityName = "Overload Blast",
            TotalCastTime = 3.0f,
            CastTimeRemaining = 3.0f,
            DamageOnComplete = 400.0f,
            IsInterruptible = true
        };

        // Advance cast 1.0 second
        bool completedEarly = castBar.Update(deltaSeconds: 1.0f, out float earlyDmg);
        Assert.False(completedEarly);
        Assert.Equal(0.0f, earlyDmg);
        Assert.Equal(2.0f, castBar.CastTimeRemaining);

        // Companion bot fires Force Kick interrupt
        bool interrupted = castBar.Interrupt("T7-01 (Tank Bot)");
        Assert.True(interrupted);
        Assert.True(castBar.WasInterrupted);
        Assert.False(castBar.IsActive);

        // Advance past remaining cast time
        bool completed = castBar.Update(deltaSeconds: 2.5f, out float damageDealt);
        Assert.False(completed);
        Assert.Equal(0.0f, damageDealt); // No damage dealt!
    }

    [Fact]
    public void TankSwapMechanic_TriggersOffTankTaunt_AtTwoStacks()
    {
        var mechanic = new TankSwapMechanic { MaxStacksBeforeSwap = 2 };

        var mainTank = new CombatEntity { Guid = 101, Name = "Main Tank", CurrentHealth = 1000, MaxHealth = 1000 };
        var offTank = new CombatEntity { Guid = 102, Name = "Off Tank", CurrentHealth = 1000, MaxHealth = 1000 };
        var boss = new CombatEntity { Guid = 999, Name = "Dread Master" };

        boss.AddThreat(mainTank.Guid, 500.0f);
        boss.AddThreat(offTank.Guid, 300.0f);

        // Boss hits Main Tank once -> 1 stack
        mechanic.ApplyBossHit(mainTank);
        Assert.Equal(1, mechanic.GetStackCount(mainTank));
        Assert.False(mechanic.ShouldOffTankSwap(mainTank, offTank));

        // Boss hits Main Tank second time -> 2 stacks (Swap threshold reached!)
        mechanic.ApplyBossHit(mainTank);
        Assert.Equal(2, mechanic.GetStackCount(mainTank));
        Assert.True(mechanic.ShouldOffTankSwap(mainTank, offTank));

        // Off-Tank executes Force Taunt to swap aggro
        CombatEngine.ExecuteAbility(offTank, boss, AbilityCatalog.ForceTaunt);

        Assert.Equal(offTank.Guid, boss.GetTopThreatTarget());
        Assert.Equal(offTank.Guid, boss.CurrentTargetGuid);
        Assert.True(boss.ThreatTable[offTank.Guid] > boss.ThreatTable[mainTank.Guid]);
    }

    [Fact]
    public void DungeonObjects_ConsoleHacking_OpensBlastDoor()
    {
        var console = new InteractiveConsole
        {
            Id = 42,
            Name = "Bridge Override Terminal",
            Position = new RcVec3f(10, 0, 0)
        };

        var blastDoor = new BlastDoor
        {
            Id = 101,
            Name = "Bridge Security Blast Door",
            Position = new RcVec3f(15, 0, 0),
            RequiredConsoleId = 42
        };

        Assert.True(blastDoor.IsLocked);
        Assert.False(blastDoor.IsOpen);

        // Trying to open before hacking fails
        bool openedPremature = blastDoor.TryOpenWithConsole(console);
        Assert.False(openedPremature);

        // Player interacts with console
        bool hacked = console.Interact(interactorGuid: 1);
        Assert.True(hacked);
        Assert.True(console.IsHacked);

        // Now door opens with hacked console
        bool opened = blastDoor.TryOpenWithConsole(console);
        Assert.True(opened);
        Assert.False(blastDoor.IsLocked);
        Assert.True(blastDoor.IsOpen);
    }
}
