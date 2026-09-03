using DotRecast.Core.Numerics;
using Holocron.Common.Combat;
using Holocron.World.Combat;
using Xunit;

namespace Holocron.Tests;

public class CombatEngineTests
{
    [Fact]
    public void CombatEngine_ExecutesDirectDamage_AppliesDamageAndGeneratesThreat()
    {
        var jedi = new CombatEntity
        {
            Guid = 101,
            Name = "Jedi Knight",
            CurrentHealth = 500,
            MaxHealth = 500,
            Resource = ResourceType.Force,
            CurrentResource = 100,
            MaxResource = 100,
            Position = new RcVec3f(0, 0, 0)
        };

        var enemy = new CombatEntity
        {
            Guid = 901,
            Name = "Sith Trooper",
            CurrentHealth = 300,
            MaxHealth = 300,
            Position = new RcVec3f(2.0f, 0, 0) // 2m distance (in melee range)
        };

        bool canCast = CombatEngine.CanCast(jedi, enemy, AbilityCatalog.BladeStorm, null, out string failReason);
        Assert.True(canCast, $"Failed to cast: {failReason}");

        float damageDealt = CombatEngine.ExecuteAbility(jedi, enemy, AbilityCatalog.BladeStorm);

        Assert.True(damageDealt > 0);
        Assert.Equal(300 - damageDealt, enemy.CurrentHealth);
        Assert.Equal(80, jedi.CurrentResource); // 100 - 20 Force spent
        Assert.True(jedi.Cooldowns.ContainsKey(AbilityCatalog.BladeStorm.Id));
        Assert.Equal(9.0f, jedi.Cooldowns[AbilityCatalog.BladeStorm.Id]); // 9s cooldown

        // Threat table on enemy must track damage from jedi
        Assert.True(enemy.ThreatTable.ContainsKey(jedi.Guid));
        Assert.Equal(damageDealt, enemy.ThreatTable[jedi.Guid]);
    }

    [Fact]
    public void CombatEngine_PreventsCast_WhenOnCooldownOrOutOfRange()
    {
        var caster = new CombatEntity
        {
            Guid = 101,
            Position = new RcVec3f(0, 0, 0)
        };

        var targetFar = new CombatEntity
        {
            Guid = 901,
            Position = new RcVec3f(40.0f, 0, 0) // 40m distance (out of 30m range)
        };

        bool canCastRange = CombatEngine.CanCast(caster, targetFar, AbilityCatalog.LightningStrike, null, out string reasonRange);
        Assert.False(canCastRange);
        Assert.Contains("range", reasonRange, StringComparison.OrdinalIgnoreCase);

        // Put ability on cooldown
        var targetNear = new CombatEntity { Guid = 902, Position = new RcVec3f(15.0f, 0, 0) };
        caster.Cooldowns[AbilityCatalog.LightningStrike.Id] = 5.0f;

        bool canCastCd = CombatEngine.CanCast(caster, targetNear, AbilityCatalog.LightningStrike, null, out string reasonCd);
        Assert.False(canCastCd);
        Assert.Contains("cooldown", reasonCd, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CombatEngine_AppliesDoT_AndTicksDamageOverTime()
    {
        var sorcerer = new CombatEntity
        {
            Guid = 201,
            Position = new RcVec3f(0, 0, 0)
        };

        var enemy = new CombatEntity
        {
            Guid = 903,
            CurrentHealth = 200,
            MaxHealth = 200,
            Position = new RcVec3f(10.0f, 0, 0)
        };

        CombatEngine.ExecuteAbility(sorcerer, enemy, AbilityCatalog.Affliction);

        Assert.Single(enemy.ActiveAuras);
        Assert.Equal("Affliction", enemy.ActiveAuras[0].Name);

        // Advance 3.0 seconds -> DoT should tick 25 damage
        CombatEngine.Tick(enemy, deltaSeconds: 3.0f);

        Assert.Equal(175.0f, enemy.CurrentHealth);
        Assert.True(enemy.ThreatTable[sorcerer.Guid] >= 25.0f);
    }

    [Fact]
    public void CombatEngine_Taunt_SnapsThreatToTop()
    {
        var tank = new CombatEntity { Guid = 100, Position = new RcVec3f(2, 0, 0) };
        var dps = new CombatEntity { Guid = 200, Position = new RcVec3f(5, 0, 0) };

        var boss = new CombatEntity { Guid = 999, Position = new RcVec3f(0, 0, 0) };

        // DPS pulls high threat (500 threat)
        boss.AddThreat(dps.Guid, 500.0f);
        boss.AddThreat(tank.Guid, 100.0f);

        Assert.Equal(dps.Guid, boss.GetTopThreatTarget());

        // Tank uses Force Taunt
        CombatEngine.ExecuteAbility(tank, boss, AbilityCatalog.ForceTaunt);

        // Tank threat should now exceed DPS threat (500 * 1.15 = 575)
        Assert.True(boss.ThreatTable[tank.Guid] > boss.ThreatTable[dps.Guid]);
        Assert.Equal(tank.Guid, boss.GetTopThreatTarget());
        Assert.Equal(tank.Guid, boss.CurrentTargetGuid);
    }
}
