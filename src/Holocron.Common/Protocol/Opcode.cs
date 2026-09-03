namespace Holocron.Common.Protocol;

/// <summary>
/// Known HeroEngine / SWTOR protocol opcodes mapped from reverse engineering references.
/// </summary>
public enum Opcode : uint
{
    // Handshake & Transport Core
    SMSG_HANDSHAKE                      = 0x11,
    CMSG_HANDSHAKE                      = 0x01,
    CMSG_PING                           = 0x02,
    SMSG_PING                           = 0x03,
    CMSG_REQUEST_CLOSE                  = 0x06,
    MSG_REQUEST_SIGNATURE               = 0x04,
    MSG_SIGNATURE                       = 0x05,
    SMSG_SIGNATURE_RESPONSE             = 0x08,

    // Proxy & Handoff
    CMSG_REQUEST_INTRODUCE_CONNECTION   = 0x07,
    SMSG_REQUEST_INTRODUCE_CONNECTION   = 0x09,
    SMSG_CLIENT_INFORMATION             = 0x0A,
    CMSG_SERVICE_REQUEST                = 0x0B,

    // Time Sync
    CMSG_TIME_SERVER_REQUEST            = 0x0C,
    SMSG_TIME_SERVER_REPLY              = 0x0D,

    // Subsystem & Debug
    CMSG_ERROR_DEBUG                    = 0x0E,
    CMSG_LIST_MODULES                   = 0x0F,
    CMSG_GAME_STATE                     = 0x10,
    CMSG_WORLD_HACKNOTIFY               = 0x12,
    SMSG_WORLD_HACK_PACK                = 0x13,
    SMSG_NOTIFY_GAUNTLET_VERSION        = 0x14,
    SMSG_SHOULD_SEND_SCRIPT_ERRORS      = 0x15,
    SMSG_NOTIFY_ID                      = 0x16,
    SMSG_SHOULD_SEND_MISSING_ASSETS     = 0x17,

    // Character Lifecycle
    CMSG_CHARACTER_LIST                 = 0x20,
    SMSG_CHARACTER_LIST                 = 0x21,
    CMSG_CHARACTER_CREATE               = 0x22,
    SMSG_CHARACTER_REJECT_NEW           = 0x23,
    CMSG_CHARACTER_SELECT               = 0x24,
    SMSG_CHARACTER_SELECTED             = 0x25,
    SMSG_CHARACTER_REJECT_SELECTION     = 0x26,
    CMSG_CHARACTER_DELETE               = 0x27,
    SMSG_CHARACTER_DELETE_STATUS        = 0x28,
    SMSG_SEND_TO_CHARACTER_SELECT       = 0x29,

    // Area, Movement & Visibility
    SMSG_TRAVEL_PENDING                 = 0x30,
    SMSG_TRAVEL_STATUS                  = 0x31,
    SMSG_SEND_TO_AREA                   = 0x32,
    SMSG_AWARENESS_RANGE                = 0x33,
    SMSG_SPAWN_OBJECT                   = 0x34,
    SMSG_DESTROY_OBJECT                 = 0x35,
    SMSG_MOVEMENT_UPDATE                = 0x36,
    CMSG_MOVEMENT_UPDATE                = 0x37,

    // Combat & Abilities
    CMSG_CAST_ABILITY                   = 0x38,
    SMSG_CAST_RESULT                    = 0x39,
    SMSG_COMBAT_EVENT                   = 0x3A,

    // Chat
    CMSG_CHAT_MESSAGE                   = 0x40,
    SMSG_RECV_CHAT_MESSAGE              = 0x41,

    // HeroEngine Remote Object Callbacks
    MSG_HERO_RPC                        = 0x34287945,
    MSG_CHARACTER_METADATA              = 0x874B000B
}
