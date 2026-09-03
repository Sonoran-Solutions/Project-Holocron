using DotRecast.Core.Numerics;
using Holocron.Common.Combat;
using Holocron.Common.Navigation;
using Holocron.World.AI;
using Holocron.World.Combat;
using Holocron.World.Encounters;
using Xunit;

namespace Holocron.Tests;

public class BotAgentTests
{
    [Fact]
    public void BotAgent_ClosesDistanceAlongNavMesh_AndAttacksTarget()
    {
        var navMesh = NavMeshService.CreatePlane(-50.0f, -50.0f, 50.0f, 50.0f, y: 0.0f);

        var tankEntity = new CombatEntity
        {
            Guid = 1001,
            Name = "T7-01 (Tank Bot)",
            CurrentHealth = 600,
            MaxHealth = 600,
            Resource = ResourceType.Force,
            CurrentResource = 100,
            MaxResource = 100,
            Position = new RcVec3f(-12.0f, 0, 0) // 12m away
        };

        var enemy = new CombatEntity
        {
            Guid = 2001,
            Name = "Imperial Commando",
            CurrentHealth = 400,
            MaxHealth = 400,
            Position = new RcVec3f(0, 0, 0)
        };

        var bot = new BotAgent(tankEntity, navMesh, BotRole.Tank)
        {
            CurrentTarget = enemy
        };

        var hazards = new List<GroundHazard>();

        // Tick 1: Bot detects target out of range, plans NavMesh path and sets destination
        bot.Tick(deltaSeconds: 1.0f, hazards);
        Assert.True(bot.Movement.HasPath);

        // Tick 2: Bot advances 8m along waypoints into attack range and strikes
        bot.Tick(deltaSeconds: 1.0f, hazards);
        Assert.True(tankEntity.Position.X > -12.0f, "Bot must have moved toward target");
        Assert.True(enemy.CurrentHealth < 400.0f, "Bot should have dealt damage once within attack range");

        // Tick 3: Bot closes remaining distance to melee range
        bot.Tick(deltaSeconds: 1.0f, hazards);
        float dist = Math.Abs(tankEntity.Position.X);
        Assert.True(dist <= 4.0f, $"Bot should reach melee range (<=4m). Actual: {dist:F1}m");
    }

    [Fact]
    public void BotAgent_FleesTelegraphedGroundHazard_AlongNavMesh()
    {
        var navMesh = NavMeshService.CreatePlane(-50.0f, -50.0f, 50.0f, 50.0f, y: 0.0f);

        var botEntity = new CombatEntity
        {
            Guid = 1002,
            Name = "Kira Carsen (DPS Bot)",
            Position = new RcVec3f(1.0f, 0, 1.0f)
        };

        var bot = new BotAgent(botEntity, navMesh, BotRole.DamageDealer);

        // Telegraphed hazard placed right on the bot
        var hazard = new GroundHazard
        {
            Id = 1,
            Name = "Plasma Grenade",
            Center = new RcVec3f(0, 0, 0),
            Radius = 6.0f,
            DamagePerTick = 50.0f
        };
        var hazards = new List<GroundHazard> { hazard };

        Assert.True(hazard.IsInside(botEntity.Position));

        // Tick AI: Bot detects hazard and executes emergency escape
        bot.Tick(deltaSeconds: 0.1f, hazards);

        Assert.True(bot.IsFleeingHazard);

        // Step movement 1.5 seconds to reach the escape point
        bot.Tick(deltaSeconds: 1.5f, hazards);

        // Bot should now be outside the 6m hazard radius
        float distFromCenter = (float)Math.Sqrt(botEntity.Position.X * botEntity.Position.X + botEntity.Position.Z * botEntity.Position.Z);
        Assert.True(distFromCenter > hazard.Radius, $"Bot must escape hazard! Current dist: {distFromCenter:F1}m, radius: {hazard.Radius}m");
        Assert.False(hazard.IsInside(botEntity.Position));
    }

    [Fact]
    public void BotAgent_HealerTriage_HealsLowHpPartyMember()
    {
        var navMesh = NavMeshService.CreatePlane(-50.0f, -50.0f, 50.0f, 50.0f, y: 0.0f);

        var healerEntity = new CombatEntity
        {
            Guid = 1003,
            Name = "Doc (Healer Bot)",
            Position = new RcVec3f(5.0f, 0, 5.0f)
        };

        var tankEntity = new CombatEntity
        {
            Guid = 1004,
            Name = "Jedi Tank",
            CurrentHealth = 150.0f, // 30% HP critical!
            MaxHealth = 500.0f,
            Position = new RcVec3f(0, 0, 0)
        };

        var healerBot = new BotAgent(healerEntity, navMesh, BotRole.Healer);
        healerBot.PartyMembers.Add(tankEntity);

        var hazards = new List<GroundHazard>();

        // Tick AI: Healer should triage the critical tank with Dark Infusion
        healerBot.Tick(deltaSeconds: 0.1f, hazards);

        Assert.True(tankEntity.CurrentHealth > 150.0f, "Healer bot should have restored tank health");
        Assert.Contains("Dark Infusion", healerBot.LastCombatAction);
    }
}
