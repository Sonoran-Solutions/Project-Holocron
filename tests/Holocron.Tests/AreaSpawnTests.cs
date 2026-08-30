using Holocron.Common.Area;
using Holocron.World.Area;
using Xunit;

namespace Holocron.Tests;

public class AreaSpawnTests
{
    [Fact]
    public void AreaManager_RegistersArea_AndInitializesCreatures()
    {
        var area = new AreaDefinition
        {
            AreaId = 1,
            ZoneName = "tython",
            DisplayName = "Tython"
        };

        area.Spawns.Add(new SpawnDefinition
        {
            Id = 101,
            Fqid = "npc.location.tython.mob.flesh_raider",
            ZoneName = "tython",
            PosX = 10.0f,
            PosY = 20.0f,
            PosZ = 5.0f,
            RespawnTimeSeconds = 30,
            Template = new CreatureTemplate
            {
                Entry = 1,
                Name = "Flesh Raider Scout",
                MaxHealth = 200,
                AggroRadius = 15.0f,
                Faction = 3 // Hostile
            }
        });

        var areaManager = new AreaManager();
        areaManager.RegisterArea(area);

        Assert.True(areaManager.TryGetArea("tython", out var tythonArea));
        Assert.Single(tythonArea.Spawns.Creatures);

        var creature = tythonArea.Spawns.Creatures[0];
        Assert.Equal(CreatureState.Idle, creature.State);
        Assert.Equal("Flesh Raider Scout", creature.Template.Name);
        Assert.Equal(200, creature.CurrentHealth);
    }

    [Fact]
    public void HostileCreature_AggrosPlayer_WhenWithinAggroRadius()
    {
        var areaManager = new AreaManager();
        var area = new AreaDefinition { ZoneName = "korriban", DisplayName = "Korriban" };

        area.Spawns.Add(new SpawnDefinition
        {
            Id = 201,
            Fqid = "npc.location.korriban.mob.k_slug",
            ZoneName = "korriban",
            PosX = 0.0f,
            PosY = 0.0f,
            PosZ = 0.0f,
            Template = new CreatureTemplate
            {
                Entry = 2,
                Name = "K'lor'slug",
                Faction = 3,
                AggroRadius = 12.0f
            }
        });

        areaManager.RegisterArea(area);
        areaManager.TryGetArea("korriban", out var korribanArea);
        var creature = korribanArea.Spawns.Creatures[0];

        // 1. Player is far away (30m) -> Creature stays Idle
        var playersFar = new List<(ulong Guid, string ZoneName, float X, float Y, float Z)>
        {
            (1001, "korriban", 30.0f, 0.0f, 0.0f)
        };
        areaManager.Tick(deltaSeconds: 0.1f, playersFar);
        Assert.Equal(CreatureState.Idle, creature.State);
        Assert.Null(creature.TargetGuid);

        // 2. Player approaches to 8m (inside 12m aggro radius) -> Creature aggros!
        var playersClose = new List<(ulong Guid, string ZoneName, float X, float Y, float Z)>
        {
            (1001, "korriban", 8.0f, 0.0f, 0.0f)
        };
        areaManager.Tick(deltaSeconds: 0.1f, playersClose);
        Assert.Equal(CreatureState.InCombat, creature.State);
        Assert.Equal(1001UL, creature.TargetGuid);
    }

    [Fact]
    public void Creature_DiesAndRespawns_AfterRespawnTimer()
    {
        var spawn = new SpawnDefinition
        {
            Id = 301,
            Fqid = "npc.location.tython.mob.flesh_raider",
            ZoneName = "tython",
            PosX = 50.0f,
            PosY = 50.0f,
            PosZ = 0.0f,
            RespawnTimeSeconds = 10,
            Template = new CreatureTemplate
            {
                Name = "Flesh Raider",
                MaxHealth = 100
            }
        };

        var creature = new CreatureInstance(999, spawn);

        // 1. Take lethal damage
        creature.TakeDamage(100, attackerGuid: 5001);
        Assert.Equal(CreatureState.Dead, creature.State);
        Assert.Equal(0, creature.CurrentHealth);
        Assert.Equal(10.0f, creature.RespawnTimerRemaining);

        // 2. Tick 5 seconds -> Still dead
        var spawnMgr = new SpawnManager();
        spawnMgr.LoadSpawns(new[] { spawn });
        var managedCreature = spawnMgr.Creatures[0];
        managedCreature.TakeDamage(100, attackerGuid: 5001);

        spawnMgr.Tick(deltaSeconds: 5.0f, new List<(ulong, float, float, float)>());
        Assert.Equal(CreatureState.Dead, managedCreature.State);
        Assert.Equal(5.0f, managedCreature.RespawnTimerRemaining);

        // 3. Tick another 6 seconds -> Respawns to full health and Idle
        spawnMgr.Tick(deltaSeconds: 6.0f, new List<(ulong, float, float, float)>());
        Assert.Equal(CreatureState.Idle, managedCreature.State);
        Assert.Equal(100, managedCreature.CurrentHealth);
        Assert.Equal(50.0f, managedCreature.PosX);
    }
}
