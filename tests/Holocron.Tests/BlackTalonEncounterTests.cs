using DotRecast.Core.Numerics;
using Holocron.Common.Combat;
using Holocron.Common.Navigation;
using Holocron.World.AI;
using Holocron.World.Combat;
using Holocron.World.Encounters;
using Xunit;

namespace Holocron.Tests;

public class BlackTalonEncounterTests
{
    [Fact]
    public void BlackTalon_FullEncounterSimulation_WithTankHealerDpsBots()
    {
        // 1. Build Encounter Room Navigation Mesh
        var navMesh = NavMeshService.CreatePlane(-40.0f, -40.0f, 40.0f, 40.0f, y: 0.0f);

        // 2. Initialize Boss Encounter at center (0, 0, 0)
        var encounter = new BlackTalonBossEncounter(navMesh, new RcVec3f(0, 0, 0));

        // 3. Assemble 4-player Dungeon Group: Player + 3 Companion Bots
        var player = new CombatEntity
        {
            Guid = 1,
            Name = "Player (Jedi Knight)",
            CurrentHealth = 700,
            MaxHealth = 700,
            ArmorRating = 1000,
            Position = new RcVec3f(-2.0f, 0, 0)
        };

        var tankBotEntity = new CombatEntity
        {
            Guid = 2,
            Name = "Tank Companion",
            CurrentHealth = 800,
            MaxHealth = 800,
            ArmorRating = 1500,
            Position = new RcVec3f(-1.0f, 0, 0)
        };
        var tankBot = new BotAgent(tankBotEntity, navMesh, BotRole.Tank)
        {
            CurrentTarget = encounter.Boss
        };

        var healerBotEntity = new CombatEntity
        {
            Guid = 3,
            Name = "Healer Companion",
            CurrentHealth = 500,
            MaxHealth = 500,
            ArmorRating = 600,
            Position = new RcVec3f(-15.0f, 0, 0) // 15m back
        };
        var healerBot = new BotAgent(healerBotEntity, navMesh, BotRole.Healer)
        {
            CurrentTarget = encounter.Boss
        };

        var dpsBotEntity = new CombatEntity
        {
            Guid = 4,
            Name = "DPS Companion",
            CurrentHealth = 550,
            MaxHealth = 550,
            ArmorRating = 700,
            Position = new RcVec3f(-12.0f, 0, 0)
        };
        var dpsBot = new BotAgent(dpsBotEntity, navMesh, BotRole.DamageDealer)
        {
            CurrentTarget = encounter.Boss
        };

        var party = new List<CombatEntity> { player, tankBotEntity, healerBotEntity, dpsBotEntity };

        // Setup party links for healer bot
        foreach (var member in party)
        {
            healerBot.PartyMembers.Add(member);
        }

        // 4. Start Encounter
        encounter.StartEncounter(party);
        Assert.Equal(EncounterPhase.Phase1_Normal, encounter.Phase);

        // 5. Simulate Encounter Progress Across Server Frames
        float simulatedTime = 0.0f;
        const float timeStep = 0.5f;

        while (encounter.Phase != EncounterPhase.Defeated && simulatedTime < 120.0f)
        {
            // Player attacks
            if (player.GlobalCooldownRemaining <= 0 && !player.IsDead)
            {
                encounter.Boss.CurrentHealth = Math.Max(0, encounter.Boss.CurrentHealth - 45.0f);
                encounter.Boss.AddThreat(player.Guid, 45.0f);
                player.GlobalCooldownRemaining = 1.5f;
            }
            CombatEngine.Tick(player, timeStep);

            // Companion Bots Tick
            tankBot.Tick(timeStep, encounter.ActiveHazards);
            healerBot.Tick(timeStep, encounter.ActiveHazards);
            dpsBot.Tick(timeStep, encounter.ActiveHazards);

            // Boss Encounter Engine Tick
            encounter.Tick(timeStep, party);

            simulatedTime += timeStep;
        }

        // 6. Verify Encounter Mechanics
        Assert.True(encounter.HasSpawnedPhase2Adds, "Phase 2 Adds and Missile Barrage should have triggered at 50% HP");
        Assert.Equal(2, encounter.Adds.Count);
        Assert.True(encounter.IsEnraged, "Phase 3 Enrage should have triggered at 25% HP");
        Assert.Equal(EncounterPhase.Defeated, encounter.Phase);
        Assert.True(encounter.Boss.IsDead, "Boss must be defeated by the party");

        // The party survived and succeeded!
        Assert.False(player.IsDead, "Player should have survived with bot companions");
        Assert.False(tankBotEntity.IsDead, "Tank bot should have survived with healer support");
    }
}
