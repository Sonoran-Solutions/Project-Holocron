using Holocron.World.AI.Core;
using Holocron.World.AI.Strategies;
using Xunit;

namespace Holocron.Tests;

public class BotAiTests
{
    [Fact]
    public void TankBot_Taunts_WhenHealerTakesAggro()
    {
        var botContext = new BotContext
        {
            BotGuid = 1001,
            Name = "Kira Carsen",
            Role = "Tank",
            HealthPercent = 0.80f,
            InCombat = true,
            TargetGuid = 9999,
            TargetDistance = 5.0f
        };

        // Add a healer party member who accidentally pulled aggro
        botContext.PartyMembers.Add(new PartyMemberContext
        {
            Guid = 2002,
            Name = "Doc",
            Role = "Healer",
            HealthPercent = 0.70f,
            HasAggro = true
        });

        var botEngine = new BotEngine();
        botEngine.AddStrategy(new JediGuardianTankStrategy());

        string? executedAction = botEngine.Tick(botContext, deltaSeconds: 0.1f);

        Assert.Equal("Force Taunt", executedAction);
        Assert.False(botContext.PartyMembers[0].HasAggro);
    }

    [Fact]
    public void Bot_Interrupts_WhenEnemyCastsSpell()
    {
        var botContext = new BotContext
        {
            BotGuid = 1001,
            InCombat = true,
            TargetGuid = 9999,
            TargetDistance = 4.0f,
            TargetIsCastingInterruptible = true
        };

        var botEngine = new BotEngine();
        botEngine.AddStrategy(new JediGuardianTankStrategy());

        string? executedAction = botEngine.Tick(botContext, deltaSeconds: 0.1f);

        Assert.Equal("Force Kick / Interrupt", executedAction);
        Assert.False(botContext.TargetIsCastingInterruptible);
    }

    [Fact]
    public void HealerBot_PrioritizesHeal_WhenPartyMemberCritical()
    {
        var botContext = new BotContext
        {
            BotGuid = 2002,
            Role = "Healer",
            InCombat = true,
            HealthPercent = 0.90f
        };

        botContext.PartyMembers.Add(new PartyMemberContext
        {
            Guid = 1001,
            Name = "Player Tank",
            Role = "Tank",
            HealthPercent = 0.25f // Critical health!
        });

        var botEngine = new BotEngine();
        botEngine.AddStrategy(new SithSorcererHealerStrategy());

        string? executedAction = botEngine.Tick(botContext, deltaSeconds: 0.1f);

        Assert.Equal("Benevolence / Dark Infusion Heal", executedAction);
        Assert.True(botContext.PartyMembers[0].HealthPercent > 0.50f);
    }
}
