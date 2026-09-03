using System.Text;
using DotRecast.Core.Numerics;
using Holocron.Common.Combat;

namespace Holocron.World.Characters;

/// <summary>
/// Manages high-level test saves, providing pre-geared Level 80 characters for instant testing
/// without having to play through character creation, tutorials, or leveling.
/// </summary>
public sealed class CharacterSaveManager
{
    private readonly List<CharacterProfile> _characters = new();

    public IReadOnlyList<CharacterProfile> Characters => _characters;

    public CharacterSaveManager()
    {
        InitializePreMadeTestSaves();
    }

    public CharacterProfile? GetCharacterByGuid(ulong guid)
    {
        return _characters.FirstOrDefault(c => c.Guid == guid);
    }

    private void InitializePreMadeTestSaves()
    {
        // 1. Level 80 Jedi Guardian (Tank / DPS)
        var jediGuardian = new CharacterProfile
        {
            Guid = 80001,
            Name = "Master Vaelin",
            Title = "Master of the Jedi Order",
            Level = 80,
            ClassId = 1,
            ClassName = "Jedi Knight",
            AdvancedClassName = "Jedi Guardian",
            Faction = 1, // Republic
            MaxHealth = 42000.0f,
            CurrentHealth = 42000.0f,
            Resource = ResourceType.Focus,
            MaxResource = 12.0f,
            CurrentResource = 12.0f,
            AreaFqid = "tython_main",
            AreaName = "Tython - Jedi Temple",
            SpawnPosition = new RcVec3f(8.5f, 0.0f, 15.0f)
        };
        AddEndgameGear(jediGuardian, "Guardian's Warplate", "Adegan Blue Lightsaber", "Force Shield Generator");
        jediGuardian.UnlockedAbilityIds.AddRange(new uint[] { 1, 2, 3, 4, 5 });
        _characters.Add(jediGuardian);

        // 2. Level 80 Sith Sorcerer (Lightning / Healer)
        var sithSorcerer = new CharacterProfile
        {
            Guid = 80002,
            Name = "Lord Malor",
            Title = "Darth",
            Level = 80,
            ClassId = 6,
            ClassName = "Sith Inquisitor",
            AdvancedClassName = "Sith Sorcerer",
            Faction = 2, // Imperial
            MaxHealth = 36000.0f,
            CurrentHealth = 36000.0f,
            Resource = ResourceType.Force,
            MaxResource = 100.0f,
            CurrentResource = 100.0f,
            AreaFqid = "korriban_main",
            AreaName = "Korriban - Sith Academy",
            SpawnPosition = new RcVec3f(-4.0f, 0.0f, 22.0f)
        };
        AddEndgameGear(sithSorcerer, "Dark Council Vestments", "Corrupted Crimson Saber", "Force Focus Crystal");
        sithSorcerer.UnlockedAbilityIds.AddRange(new uint[] { 10, 11, 12, 13, 14 });
        _characters.Add(sithSorcerer);

        // 3. Level 80 Bounty Hunter Powertech (Pyrotech / Tank)
        var bountyHunter = new CharacterProfile
        {
            Guid = 80003,
            Name = "Mando Fett",
            Title = "Grand Champion of the Great Hunt",
            Level = 80,
            ClassId = 7,
            ClassName = "Bounty Hunter",
            AdvancedClassName = "Powertech",
            Faction = 2, // Imperial
            MaxHealth = 39000.0f,
            CurrentHealth = 39000.0f,
            Resource = ResourceType.Heat,
            MaxResource = 100.0f,
            CurrentResource = 0.0f, // 0 heat = ready to blast
            AreaFqid = "dromund_kaas_main",
            AreaName = "Dromund Kaas - Kaas City",
            SpawnPosition = new RcVec3f(12.0f, 0.0f, -8.0f)
        };
        AddEndgameGear(bountyHunter, "Beskar Mandalorian Armor", "Heavy Disintegrator Blaster", "Wrist Flame Shield");
        _characters.Add(bountyHunter);

        // 4. Level 80 Smuggler Gunslinger (Dual Blaster DPS)
        var smuggler = new CharacterProfile
        {
            Guid = 80004,
            Name = "Captain Rhyse",
            Title = "Voidhound",
            Level = 80,
            ClassId = 3,
            ClassName = "Smuggler",
            AdvancedClassName = "Gunslinger",
            Faction = 1, // Republic
            MaxHealth = 34000.0f,
            CurrentHealth = 34000.0f,
            Resource = ResourceType.Energy,
            MaxResource = 100.0f,
            CurrentResource = 100.0f,
            AreaFqid = "coruscant_main",
            AreaName = "Coruscant - Senate Plaza",
            SpawnPosition = new RcVec3f(0.0f, 0.0f, 30.0f)
        };
        AddEndgameGear(smuggler, "Smuggler's Custom Duster", "Dual Modified Heavy Blasters", "Concealed Vibroknife");
        _characters.Add(smuggler);

        // 5. Level 80 Instant Flashpoint Character: Loaded directly at The Black Talon bridge!
        var blackTalonWarrior = new CharacterProfile
        {
            Guid = 80005,
            Name = "Darth Vindicator",
            Title = "Executioner of the Empire",
            Level = 80,
            ClassId = 5,
            ClassName = "Sith Warrior",
            AdvancedClassName = "Sith Juggernaut",
            Faction = 2,
            MaxHealth = 44000.0f,
            CurrentHealth = 44000.0f,
            Resource = ResourceType.Rage,
            MaxResource = 12.0f,
            CurrentResource = 12.0f,
            AreaFqid = "black_talon",
            AreaName = "The Black Talon - Transport Cruiser",
            SpawnPosition = new RcVec3f(0.0f, 0.0f, 0.0f) // Directly facing the boss deck!
        };
        AddEndgameGear(blackTalonWarrior, "Juggernaut Dread Warplate", "Flawless Red Lightsaber", "Heavy Repulsor Shield");
        blackTalonWarrior.UnlockedAbilityIds.AddRange(new uint[] { 1, 2, 3, 4, 5 });
        _characters.Add(blackTalonWarrior);

        // 6. Level 80 Instant Flashpoint Character: Loaded directly at The Esseles!
        var esselesCommando = new CharacterProfile
        {
            Guid = 80006,
            Name = "Havoc Commander",
            Title = "Hero of the Republic",
            Level = 80,
            ClassId = 4,
            ClassName = "Trooper",
            AdvancedClassName = "Commando",
            Faction = 1,
            MaxHealth = 41000.0f,
            CurrentHealth = 41000.0f,
            Resource = ResourceType.Energy,
            MaxResource = 100.0f,
            CurrentResource = 100.0f,
            AreaFqid = "esseles",
            AreaName = "The Esseles - Ambassador Cruiser",
            SpawnPosition = new RcVec3f(0.0f, 0.0f, 0.0f)
        };
        AddEndgameGear(esselesCommando, "Havoc Squad Heavy Power Armor", "Rotary Assault Cannon", "Field Generator");
        _characters.Add(esselesCommando);
    }

    private static void AddEndgameGear(CharacterProfile character, string armorName, string mainHandName, string offHandName)
    {
        character.Gear.Add(new EquippedItem { SlotId = 1, SlotName = "Head", ItemName = $"{armorName} Helm", ArmorValue = 180 });
        character.Gear.Add(new EquippedItem { SlotId = 2, SlotName = "Chest", ItemName = $"{armorName} Cuirass", ArmorValue = 350 });
        character.Gear.Add(new EquippedItem { SlotId = 3, SlotName = "Hands", ItemName = $"{armorName} Gauntlets", ArmorValue = 160 });
        character.Gear.Add(new EquippedItem { SlotId = 4, SlotName = "Waist", ItemName = $"{armorName} Belt", ArmorValue = 120 });
        character.Gear.Add(new EquippedItem { SlotId = 5, SlotName = "Legs", ItemName = $"{armorName} Greaves", ArmorValue = 280 });
        character.Gear.Add(new EquippedItem { SlotId = 6, SlotName = "Feet", ItemName = $"{armorName} Boots", ArmorValue = 150 });
        character.Gear.Add(new EquippedItem { SlotId = 7, SlotName = "MainHand", ItemName = mainHandName, ArmorValue = 0 });
        character.Gear.Add(new EquippedItem { SlotId = 8, SlotName = "OffHand", ItemName = offHandName, ArmorValue = 100 });
    }

    public string GenerateSqlSeed()
    {
        var sb = new StringBuilder();
        sb.AppendLine("-- Project Holocron: Pre-made Level 80 Test Characters with Endgame Gear");
        sb.AppendLine("USE `holocron_characters`;");
        sb.AppendLine();

        foreach (var c in _characters)
        {
            sb.AppendLine($"INSERT INTO `characters` (`guid`, `account_id`, `name`, `level`, `gender`, `species`, `class_id`, `discipline_id`, `zone_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`)");
            sb.AppendLine($"VALUES ({c.Guid}, {c.AccountId}, '{c.Name}', {c.Level}, 0, 1, {c.ClassId}, 1, 1, {c.SpawnPosition.X}, {c.SpawnPosition.Y}, {c.SpawnPosition.Z}, {c.Orientation})");
            sb.AppendLine($"ON DUPLICATE KEY UPDATE `level`={c.Level}, `name`='{c.Name}';");
            sb.AppendLine();
        }

        return sb.ToString();
    }
}
