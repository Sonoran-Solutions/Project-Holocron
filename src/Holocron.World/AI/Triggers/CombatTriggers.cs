using Holocron.World.AI.Core;

namespace Holocron.World.AI.Triggers;

public sealed class LowHealthTrigger : ITrigger
{
    private readonly float _threshold;
    public string Name => $"LowHealth (< {_threshold * 100}%)";
    public LowHealthTrigger(float threshold = 0.35f) => _threshold = threshold;
    public bool Check(BotContext ctx) => ctx.HealthPercent < _threshold;
}

public sealed class PartyCriticalHealthTrigger : ITrigger
{
    private readonly float _threshold;
    public string Name => $"PartyMemberCritical (< {_threshold * 100}%)";
    public PartyCriticalHealthTrigger(float threshold = 0.40f) => _threshold = threshold;
    public bool Check(BotContext ctx) => ctx.PartyMembers.Any(p => p.HealthPercent < _threshold);
}

public sealed class EnemyCastInterruptibleTrigger : ITrigger
{
    public string Name => "EnemyIsCastingInterruptible";
    public bool Check(BotContext ctx) => ctx.TargetIsCastingInterruptible && ctx.TargetDistance <= 10.0f;
}

public sealed class NonTankHasAggroTrigger : ITrigger
{
    public string Name => "NonTankHasAggro";
    public bool Check(BotContext ctx) => ctx.PartyMembers.Any(p => p.Role != "Tank" && p.HasAggro);
}

public sealed class HasTargetInCombatTrigger : ITrigger
{
    public string Name => "HasTargetInCombat";
    public bool Check(BotContext ctx) => ctx.InCombat && ctx.TargetGuid.HasValue && ctx.TargetDistance <= 30.0f;
}
