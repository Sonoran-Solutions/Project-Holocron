namespace Holocron.World.AI.Core;

public interface IAction
{
    string Name { get; }
    int Priority { get; }
    bool CanExecute(BotContext context);
    bool Execute(BotContext context);
}
