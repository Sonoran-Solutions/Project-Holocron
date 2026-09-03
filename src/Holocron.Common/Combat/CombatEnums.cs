namespace Holocron.Common.Combat;

public enum ResourceType
{
    Force,      // Jedi Knight/Consular, Sith Warrior/Inquisitor (0-100, standard regen)
    Rage,       // Sith Warrior (0-12, builds up from attacks)
    Focus,      // Jedi Knight (0-12, builds up from attacks)
    Energy,     // Smuggler / Imperial Agent (0-100, regen rate scales with pool)
    Heat        // Bounty Hunter (0-100, builds up, vents down to 0)
}

public enum AbilityEffectType
{
    DirectDamage,
    PeriodicDamage, // DoT
    DirectHeal,
    PeriodicHeal,   // HoT
    Taunt,
    Interrupt,
    CrowdControl,   // Stun / Mezz
    DefenseBuff
}

public enum DamageType
{
    Kinetic,   // Mitigated by armor
    Energy,    // Mitigated by armor
    Internal,  // Bypasses armor
    Elemental  // Bypasses armor
}
