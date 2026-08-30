using Holocron.World.AI.Core;

namespace Holocron.World.AI.Actions;

public sealed class UseMedpacAction : IAction
{
    public string Name => "Use Medpac";
    public int Priority => 100;
    public bool CanExecute(BotContext ctx) => ctx.HealthPercent < 0.35f;
    public bool Execute(BotContext ctx)
    {
        ctx.HealthPercent = Math.Min(1.0f, ctx.HealthPercent + 0.40f);
        return true;
    }
}

public sealed class InterruptSpellAction : IAction
{
    public string Name => "Force Kick / Interrupt";
    public int Priority => 95;
    public bool CanExecute(BotContext ctx) => ctx.TargetIsCastingInterruptible && ctx.GlobalCooldownRemaining <= 0;
    public bool Execute(BotContext ctx)
    {
        ctx.TargetIsCastingInterruptible = false;
        ctx.GlobalCooldownRemaining = 1.5f;
        return true;
    }
}

public sealed class TauntAction : IAction
{
    public string Name => "Force Taunt";
    public int Priority => 85;
    public bool CanExecute(BotContext ctx) => ctx.GlobalCooldownRemaining <= 0;
    public bool Execute(BotContext ctx)
    {
        foreach (var p in ctx.PartyMembers) p.HasAggro = false;
        ctx.GlobalCooldownRemaining = 1.5f;
        return true;
    }
}

public sealed class HealCriticalPartyMemberAction : IAction
{
    public string Name => "Benevolence / Dark Infusion Heal";
    public int Priority => 90;
    public bool CanExecute(BotContext ctx) => ctx.GlobalCooldownRemaining <= 0;
    public bool Execute(BotContext ctx)
    {
        var target = ctx.PartyMembers.OrderBy(p => p.HealthPercent).FirstOrDefault();
        if (target != null)
        {
            target.HealthPercent = Math.Min(1.0f, target.HealthPercent + 0.35f);
        }
        ctx.GlobalCooldownRemaining = 1.5f;
        return true;
    }
}

public sealed class BladeStormAction : IAction
{
    public string Name => "Blade Storm / Force Scream";
    public int Priority => 60;
    public bool CanExecute(BotContext ctx) => ctx.GlobalCooldownRemaining <= 0 && ctx.TargetDistance <= 10.0f;
    public bool Execute(BotContext ctx)
    {
        ctx.TargetHealthPercent = Math.Max(0, ctx.TargetHealthPercent - 0.15f);
        ctx.GlobalCooldownRemaining = 1.5f;
        return true;
    }
}

public sealed class SaberStrikeAction : IAction
{
    public string Name => "Slash / Saber Strike";
    public int Priority => 30;
    public bool CanExecute(BotContext ctx) => ctx.GlobalCooldownRemaining <= 0 && ctx.TargetDistance <= 4.0f;
    public bool Execute(BotContext ctx)
    {
        ctx.TargetHealthPercent = Math.Max(0, ctx.TargetHealthPercent - 0.08f);
        ctx.GlobalCooldownRemaining = 1.5f;
        return true;
    }
}
