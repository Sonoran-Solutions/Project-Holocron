namespace Holocron.World.AI.Core;

/// <summary>
/// Trigger-Action-Strategy-Value (TASV) Bot AI execution engine.
/// Evaluates active strategies on every server tick and selects highest-priority valid action.
/// </summary>
public sealed class BotEngine
{
    private readonly List<IStrategy> _strategies = new();

    public void AddStrategy(IStrategy strategy)
    {
        _strategies.Add(strategy);
    }

    public string? Tick(BotContext context, float deltaSeconds)
    {
        if (context.GlobalCooldownRemaining > 0)
        {
            context.GlobalCooldownRemaining -= deltaSeconds;
            if (context.GlobalCooldownRemaining < 0) context.GlobalCooldownRemaining = 0;
        }

        // Collect all actions whose triggers evaluated to TRUE
        var candidateActions = new List<IAction>();

        foreach (var strategy in _strategies)
        {
            foreach (var (trigger, action) in strategy.Rules)
            {
                if (trigger.Check(context) && action.CanExecute(context))
                {
                    candidateActions.Add(action);
                }
            }
        }

        if (candidateActions.Count == 0)
            return null;

        // Sort by priority descending
        var bestAction = candidateActions.OrderByDescending(a => a.Priority).First();
        bool executed = bestAction.Execute(context);

        return executed ? bestAction.Name : null;
    }
}
