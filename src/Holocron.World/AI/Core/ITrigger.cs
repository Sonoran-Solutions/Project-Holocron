namespace Holocron.World.AI.Core;

public interface ITrigger
{
    string Name { get; }
    bool Check(BotContext context);
}
