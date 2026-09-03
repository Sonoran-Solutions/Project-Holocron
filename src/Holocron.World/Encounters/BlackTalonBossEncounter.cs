using DotRecast.Core.Numerics;
using Holocron.Common.Combat;
using Holocron.Common.Navigation;
using Holocron.World.Combat;

namespace Holocron.World.Encounters;

public enum EncounterPhase
{
    NotStarted,
    Phase1_Normal,
    Phase2_AddsAndHazard,
    Phase3_Enrage,
    Defeated
}

/// <summary>
/// Scripted boss encounter for The Black Talon flashpoint: Commander Ghul / GXR-5 Saboteur.
/// Features multi-phase transitions, telegraphed ground AoE hazards, reinforcement adds, and enrage mechanics.
/// </summary>
public sealed class BlackTalonBossEncounter
{
    public CombatEntity Boss { get; }
    public List<CombatEntity> Adds { get; } = new();
    public List<GroundHazard> ActiveHazards { get; } = new();
    public EncounterPhase Phase { get; private set; } = EncounterPhase.NotStarted;

    public bool HasSpawnedPhase2Adds { get; private set; }
    public bool IsEnraged { get; private set; }

    public NavMeshService NavMesh { get; }

    public BlackTalonBossEncounter(NavMeshService navMesh, RcVec3f bossSpawnPos)
    {
        NavMesh = navMesh ?? throw new ArgumentNullException(nameof(navMesh));
        Boss = new CombatEntity
        {
            Guid = 99991,
            Name = "Commander Ghul (Boss)",
            CurrentHealth = 2200.0f,
            MaxHealth = 2200.0f,
            ArmorRating = 500.0f,
            CriticalChance = 0.15f,
            CriticalMultiplier = 1.50f,
            Position = bossSpawnPos,
            Faction = 2
        };
    }

    public void StartEncounter(List<CombatEntity> party)
    {
        Phase = EncounterPhase.Phase1_Normal;
        Boss.InCombat = true;
        foreach (var member in party)
        {
            member.InCombat = true;
            Boss.AddThreat(member.Guid, 1.0f);
        }
    }

    public void Tick(float deltaSeconds, List<CombatEntity> party)
    {
        if (Phase == EncounterPhase.NotStarted || Phase == EncounterPhase.Defeated)
            return;

        if (Boss.IsDead)
        {
            Phase = EncounterPhase.Defeated;
            ActiveHazards.Clear();
            return;
        }

        // 1. Tick Boss stats & GCD
        CombatEngine.Tick(Boss, deltaSeconds);

        // 2. Tick Ground Hazards
        for (int i = ActiveHazards.Count - 1; i >= 0; i--)
        {
            var hazard = ActiveHazards[i];
            hazard.DurationRemaining -= deltaSeconds;
            hazard.TickTimer -= deltaSeconds;

            if (hazard.TickTimer <= 0 && hazard.DurationRemaining > 0)
            {
                foreach (var member in party)
                {
                    if (!member.IsDead && hazard.IsInside(member.Position))
                    {
                        member.CurrentHealth = Math.Max(0, member.CurrentHealth - hazard.DamagePerTick);
                    }
                }
                hazard.TickTimer = hazard.TickInterval;
            }

            if (hazard.IsExpired)
            {
                ActiveHazards.RemoveAt(i);
            }
        }

        // 3. Phase Transitions
        float hpPercent = Boss.HealthPercent;

        // Phase 2 Trigger: at 50% HP, spawn Missile Barrage AoE hazard and 2 reinforcement adds
        if (hpPercent <= 0.50f && !HasSpawnedPhase2Adds)
        {
            TriggerPhase2(party);
        }

        // Phase 3 Trigger: at 25% HP, boss soft enrages
        if (hpPercent <= 0.25f && !IsEnraged)
        {
            TriggerPhase3Enrage();
        }

        // 4. Boss Combat AI
        ExecuteBossAi(party, deltaSeconds);
    }

    private void TriggerPhase2(List<CombatEntity> party)
    {
        Phase = EncounterPhase.Phase2_AddsAndHazard;
        HasSpawnedPhase2Adds = true;

        // Drop telegraphed Missile Barrage hazard around the boss position
        var barrage = new GroundHazard
        {
            Id = 1,
            Name = "Orbital Missile Barrage",
            Center = Boss.Position,
            Radius = 7.0f,
            DamagePerTick = 35.0f,
            TickInterval = 1.0f,
            DurationRemaining = 10.0f
        };
        ActiveHazards.Add(barrage);

        // Spawn 2 Marine adds at flanks targeting threat
        var add1 = new CombatEntity
        {
            Guid = 99992,
            Name = "Black Talon Marine [Add 1]",
            CurrentHealth = 250.0f,
            MaxHealth = 250.0f,
            Position = new RcVec3f(Boss.Position.X - 6.0f, Boss.Position.Y, Boss.Position.Z + 4.0f),
            Faction = 2,
            InCombat = true
        };

        var add2 = new CombatEntity
        {
            Guid = 99993,
            Name = "Black Talon Marine [Add 2]",
            CurrentHealth = 250.0f,
            MaxHealth = 250.0f,
            Position = new RcVec3f(Boss.Position.X + 6.0f, Boss.Position.Y, Boss.Position.Z + 4.0f),
            Faction = 2,
            InCombat = true
        };

        foreach (var member in party)
        {
            add1.AddThreat(member.Guid, 1.0f);
            add2.AddThreat(member.Guid, 1.0f);
        }

        Adds.Add(add1);
        Adds.Add(add2);
    }

    private void TriggerPhase3Enrage()
    {
        Phase = EncounterPhase.Phase3_Enrage;
        IsEnraged = true;
        Boss.CriticalChance = 0.30f;
        Boss.CriticalMultiplier = 1.75f;
    }

    private void ExecuteBossAi(List<CombatEntity> party, float deltaSeconds)
    {
        ulong? topThreat = Boss.GetTopThreatTarget();
        CombatEntity? target = party.FirstOrDefault(p => p.Guid == topThreat && !p.IsDead);
        target ??= party.FirstOrDefault(p => !p.IsDead);

        if (target == null) return;
        Boss.CurrentTargetGuid = target.Guid;

        if (Boss.GlobalCooldownRemaining <= 0)
        {
            float rawDamage = IsEnraged ? 60.0f : 40.0f;
            float mitigation = target.ArmorRating / (target.ArmorRating + 1500.0f);
            float damageDealt = rawDamage * (1.0f - Math.Clamp(mitigation, 0.0f, 0.70f));

            target.CurrentHealth = Math.Max(0, target.CurrentHealth - damageDealt);
            Boss.GlobalCooldownRemaining = 1.5f;
        }

        // Execute Add attacks targeting their threat table
        foreach (var add in Adds)
        {
            if (add.IsDead) continue;
            CombatEngine.Tick(add, deltaSeconds);

            if (add.GlobalCooldownRemaining <= 0)
            {
                ulong? addTop = add.GetTopThreatTarget();
                var addTarget = party.FirstOrDefault(p => p.Guid == addTop && !p.IsDead) ?? party.FirstOrDefault(p => !p.IsDead);
                if (addTarget != null)
                {
                    float mitigation = addTarget.ArmorRating / (addTarget.ArmorRating + 1500.0f);
                    float damageDealt = 18.0f * (1.0f - Math.Clamp(mitigation, 0.0f, 0.70f));
                    addTarget.CurrentHealth = Math.Max(0, addTarget.CurrentHealth - damageDealt);
                    add.GlobalCooldownRemaining = 2.0f;
                }
            }
        }
    }
}
