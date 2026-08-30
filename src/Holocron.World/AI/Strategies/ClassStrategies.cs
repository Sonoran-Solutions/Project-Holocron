using Holocron.World.AI.Actions;
using Holocron.World.AI.Core;
using Holocron.World.AI.Triggers;

namespace Holocron.World.AI.Strategies;

public sealed class JediGuardianTankStrategy : IStrategy
{
    public string Name => "Jedi Guardian (Defense Tank)";
    public IReadOnlyList<(ITrigger Trigger, IAction Action)> Rules { get; }

    public JediGuardianTankStrategy()
    {
        Rules = new List<(ITrigger, IAction)>
        {
            (new LowHealthTrigger(0.35f), new UseMedpacAction()),
            (new EnemyCastInterruptibleTrigger(), new InterruptSpellAction()),
            (new NonTankHasAggroTrigger(), new TauntAction()),
            (new HasTargetInCombatTrigger(), new BladeStormAction()),
            (new HasTargetInCombatTrigger(), new SaberStrikeAction())
        };
    }
}

public sealed class SithSorcererHealerStrategy : IStrategy
{
    public string Name => "Sith Sorcerer (Corruption Healer)";
    public IReadOnlyList<(ITrigger Trigger, IAction Action)> Rules { get; }

    public SithSorcererHealerStrategy()
    {
        Rules = new List<(ITrigger, IAction)>
        {
            (new LowHealthTrigger(0.30f), new UseMedpacAction()),
            (new EnemyCastInterruptibleTrigger(), new InterruptSpellAction()),
            (new PartyCriticalHealthTrigger(0.50f), new HealCriticalPartyMemberAction()),
            (new HasTargetInCombatTrigger(), new BladeStormAction())
        };
    }
}
