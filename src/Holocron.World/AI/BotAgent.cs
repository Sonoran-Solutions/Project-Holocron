using DotRecast.Core.Numerics;
using Holocron.Common.Combat;
using Holocron.Common.Navigation;
using Holocron.World.Combat;
using Holocron.World.Encounters;
using Holocron.World.Navigation;

namespace Holocron.World.AI;

public enum BotRole
{
    Tank,
    Healer,
    DamageDealer
}

/// <summary>
/// Autonomous companion bot bridging real-time NavMesh locomotion and CombatEngine mechanics.
/// </summary>
public sealed class BotAgent
{
    public CombatEntity Entity { get; }
    public MovementGenerator Movement { get; }
    public BotRole Role { get; set; }
    public NavMeshService NavMesh { get; set; }

    public CombatEntity? CurrentTarget { get; set; }
    public List<CombatEntity> PartyMembers { get; } = new();

    public bool IsFleeingHazard => Movement.Type == MovementType.Flee && Movement.HasPath;
    public string LastCombatAction { get; private set; } = "None";

    public BotAgent(CombatEntity entity, NavMeshService navMesh, BotRole role)
    {
        Entity = entity ?? throw new ArgumentNullException(nameof(entity));
        NavMesh = navMesh ?? throw new ArgumentNullException(nameof(navMesh));
        Movement = new MovementGenerator { Speed = 8.0f };
        Role = role;
    }

    /// <summary>
    /// Executes one server AI tick: handles ground hazard evasion, movement navigation, and combat ability rotations.
    /// </summary>
    public void Tick(float deltaSeconds, IReadOnlyList<GroundHazard> activeHazards)
    {
        if (Entity.IsDead) return;

        // 1. Check for telegraphed ground hazards
        GroundHazard? dangerousHazard = null;
        foreach (var hazard in activeHazards)
        {
            if (hazard.IsInside(Entity.Position))
            {
                dangerousHazard = hazard;
                break;
            }
        }

        if (dangerousHazard != null && !IsFleeingHazard)
        {
            // Trigger emergency evacuation along navmesh
            Movement.FleeFromHazard(NavMesh, Entity.Position, dangerousHazard.Center, dangerousHazard.Radius);
            LastCombatAction = $"Fleeing hazard '{dangerousHazard.Name}'";
        }

        // 2. Advance movement along navigation mesh
        if (Movement.HasPath)
        {
            Entity.Position = Movement.Update(Entity.Position, deltaSeconds);
        }

        // 3. Tick combat cooldowns, GCD, resources, and status auras
        CombatEngine.Tick(Entity, deltaSeconds);

        // If actively fleeing a hazard, prioritize survival over casting
        if (IsFleeingHazard)
        {
            return;
        }

        // 4. Role-based Combat Rotation
        switch (Role)
        {
            case BotRole.Tank:
                ExecuteTankRotation();
                break;
            case BotRole.Healer:
                ExecuteHealerRotation();
                break;
            case BotRole.DamageDealer:
                ExecuteDpsRotation();
                break;
        }
    }

    private void ExecuteTankRotation()
    {
        if (CurrentTarget == null || CurrentTarget.IsDead) return;

        // Check if boss or target is attacking someone else in party
        bool someoneElseHasAggro = CurrentTarget.CurrentTargetGuid.HasValue &&
                                  CurrentTarget.CurrentTargetGuid.Value != Entity.Guid;

        if (someoneElseHasAggro && CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.ForceTaunt, NavMesh, out _))
        {
            CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.ForceTaunt);
            LastCombatAction = "Cast Force Taunt (Stealing Aggro)";
            return;
        }

        // Check distance to target
        float dist = GetDistanceTo(CurrentTarget.Position);
        if (dist > AbilityCatalog.BladeStorm.RangeMax)
        {
            // Close the gap toward target on NavMesh
            Movement.MoveTo(NavMesh, Entity.Position, CurrentTarget.Position);
            LastCombatAction = "Closing gap to melee target";
            return;
        }

        // In range: execute attacks
        if (CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.BladeStorm, NavMesh, out _))
        {
            CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.BladeStorm);
            LastCombatAction = "Cast Blade Storm";
        }
        else if (CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.SaberStrike, NavMesh, out _))
        {
            CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.SaberStrike);
            LastCombatAction = "Cast Saber Strike";
        }
    }

    private void ExecuteHealerRotation()
    {
        // 1. Triage: find party member with lowest HP percent
        CombatEntity? lowestMember = null;
        float lowestPercent = 1.0f;

        foreach (var member in PartyMembers)
        {
            if (!member.IsDead && member.HealthPercent < lowestPercent)
            {
                lowestPercent = member.HealthPercent;
                lowestMember = member;
            }
        }

        if (lowestMember != null && lowestPercent < 0.70f)
        {
            float dist = GetDistanceTo(lowestMember.Position);
            if (dist > AbilityCatalog.DarkInfusion.RangeMax)
            {
                Movement.MoveTo(NavMesh, Entity.Position, lowestMember.Position);
                LastCombatAction = $"Moving into heal range of {lowestMember.Name}";
                return;
            }

            if (CombatEngine.CanCast(Entity, lowestMember, AbilityCatalog.DarkInfusion, NavMesh, out _))
            {
                CombatEngine.ExecuteAbility(Entity, lowestMember, AbilityCatalog.DarkInfusion);
                LastCombatAction = $"Cast Dark Infusion on {lowestMember.Name}";
                return;
            }
        }

        // 2. If party is healthy, assist with ranged DPS
        if (CurrentTarget != null && !CurrentTarget.IsDead)
        {
            float dist = GetDistanceTo(CurrentTarget.Position);
            if (dist > AbilityCatalog.LightningStrike.RangeMax)
            {
                Movement.MoveTo(NavMesh, Entity.Position, CurrentTarget.Position);
                LastCombatAction = "Moving into attack range";
                return;
            }

            if (CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.Affliction, NavMesh, out _) &&
                !CurrentTarget.ActiveAuras.Any(a => a.AbilityId == AbilityCatalog.Affliction.Id))
            {
                CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.Affliction);
                LastCombatAction = "Cast Affliction DoT";
            }
            else if (CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.LightningStrike, NavMesh, out _))
            {
                CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.LightningStrike);
                LastCombatAction = "Cast Lightning Strike";
            }
        }
    }

    private void ExecuteDpsRotation()
    {
        if (CurrentTarget == null || CurrentTarget.IsDead) return;

        float dist = GetDistanceTo(CurrentTarget.Position);
        if (dist > AbilityCatalog.LightningStrike.RangeMax)
        {
            Movement.MoveTo(NavMesh, Entity.Position, CurrentTarget.Position);
            LastCombatAction = "Closing range to target";
            return;
        }

        if (CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.Affliction, NavMesh, out _) &&
            !CurrentTarget.ActiveAuras.Any(a => a.AbilityId == AbilityCatalog.Affliction.Id))
        {
            CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.Affliction);
            LastCombatAction = "Cast Affliction";
        }
        else if (CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.LightningStrike, NavMesh, out _))
        {
            CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.LightningStrike);
            LastCombatAction = "Cast Lightning Strike";
        }
        else if (CombatEngine.CanCast(Entity, CurrentTarget, AbilityCatalog.BladeStorm, NavMesh, out _))
        {
            CombatEngine.ExecuteAbility(Entity, CurrentTarget, AbilityCatalog.BladeStorm);
            LastCombatAction = "Cast Blade Storm";
        }
    }

    private float GetDistanceTo(RcVec3f targetPos)
    {
        float dx = Entity.Position.X - targetPos.X;
        float dy = Entity.Position.Y - targetPos.Y;
        float dz = Entity.Position.Z - targetPos.Z;
        return (float)Math.Sqrt(dx * dx + dy * dy + dz * dz);
    }
}
