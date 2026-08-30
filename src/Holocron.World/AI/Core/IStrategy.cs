namespace Holocron.World.AI.Core;

public interface IStrategy
{
    string Name { get; }
    IReadOnlyList<(ITrigger Trigger, IAction Action)> Rules { get; }
}
