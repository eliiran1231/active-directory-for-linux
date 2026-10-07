// Portable SID constants and conversion predicates verified against detached Windows recordings.
// Managed constructor validation follows dotnet/runtime v9.0.0 SID.cs (MIT;
// see ../AccessControl/RULES-LICENSE.txt). No OS, account lookup or ambient authority is used.
#pragma warning disable CA1416 // The shared WellKnownSidType enum is a portable numeric value.
using System.Security.Principal;
using AdForLinux.DirectoryServices.Security.Core;

namespace AdForLinux.Security.Principal;

public sealed partial class SecurityIdentifier
{
    private static readonly IReadOnlyDictionary<int, string> WellKnownValues = new Dictionary<int, string>
    {
        [0] = "S-1-0-0",
        [1] = "S-1-1-0",
        [2] = "S-1-2-0",
        [3] = "S-1-3-0",
        [4] = "S-1-3-1",
        [5] = "S-1-3-2",
        [6] = "S-1-3-3",
        [7] = "S-1-5",
        [8] = "S-1-5-1",
        [9] = "S-1-5-2",
        [10] = "S-1-5-3",
        [11] = "S-1-5-4",
        [12] = "S-1-5-6",
        [13] = "S-1-5-7",
        [14] = "S-1-5-8",
        [15] = "S-1-5-9",
        [16] = "S-1-5-10",
        [17] = "S-1-5-11",
        [18] = "S-1-5-12",
        [19] = "S-1-5-13",
        [20] = "S-1-5-14",
        [22] = "S-1-5-18",
        [23] = "S-1-5-19",
        [24] = "S-1-5-20",
        [25] = "S-1-5-32",
        [26] = "S-1-5-32-544",
        [27] = "S-1-5-32-545",
        [28] = "S-1-5-32-546",
        [29] = "S-1-5-32-547",
        [30] = "S-1-5-32-548",
        [31] = "S-1-5-32-549",
        [32] = "S-1-5-32-550",
        [33] = "S-1-5-32-551",
        [34] = "S-1-5-32-552",
        [35] = "S-1-5-32-554",
        [36] = "S-1-5-32-555",
        [37] = "S-1-5-32-556",
        [51] = "S-1-5-64-10",
        [52] = "S-1-5-64-21",
        [53] = "S-1-5-64-14",
        [54] = "S-1-5-15",
        [55] = "S-1-5-1000",
        [56] = "S-1-5-32-557",
        [57] = "S-1-5-32-558",
        [58] = "S-1-5-32-559",
        [59] = "S-1-5-32-560",
        [60] = "S-1-5-32-561",
        [61] = "S-1-5-32-562",
        [62] = "S-1-5-32-568",
        [63] = "S-1-5-17",
        [64] = "S-1-5-32-569",
        [65] = "S-1-16-0",
        [66] = "S-1-16-4096",
        [67] = "S-1-16-8192",
        [68] = "S-1-16-12288",
        [69] = "S-1-16-16384",
        [70] = "S-1-5-33",
        [71] = "S-1-3-4",
        [74] = "S-1-5-22",
        [76] = "S-1-5-32-573",
        [78] = "S-1-5-32-574",
        [79] = "S-1-16-8448",
        [81] = "S-1-2-1",
        [82] = "S-1-5-65-1",
        [84] = "S-1-15-2-1",
        [85] = "S-1-15-3-1",
        [86] = "S-1-15-3-2",
        [87] = "S-1-15-3-3",
        [88] = "S-1-15-3-4",
        [89] = "S-1-15-3-5",
        [90] = "S-1-15-3-6",
        [91] = "S-1-15-3-7",
        [92] = "S-1-15-3-9",
        [93] = "S-1-15-3-8",
        [94] = "S-1-15-3-10",
    };
    private static readonly IReadOnlyDictionary<int, uint> DomainRelativeRids = new Dictionary<int, uint>
    {
        [38] = 500,
        [39] = 501,
        [40] = 502,
        [41] = 512,
        [42] = 513,
        [43] = 514,
        [44] = 515,
        [45] = 516,
        [46] = 517,
        [47] = 518,
        [48] = 519,
        [49] = 520,
        [50] = 553,
        [72] = 571,
        [73] = 572,
        [75] = 521,
        [77] = 498,
    };
    private static readonly IReadOnlyDictionary<string, string> SddlAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["AA"] = "S-1-5-32-579",
        ["AC"] = "S-1-15-2-1",
        ["AN"] = "S-1-5-7",
        ["AO"] = "S-1-5-32-548",
        ["AS"] = "S-1-18-1",
        ["AU"] = "S-1-5-11",
        ["BA"] = "S-1-5-32-544",
        ["BG"] = "S-1-5-32-546",
        ["BO"] = "S-1-5-32-551",
        ["BU"] = "S-1-5-32-545",
        ["CD"] = "S-1-5-32-574",
        ["CG"] = "S-1-3-1",
        ["CO"] = "S-1-3-0",
        ["CY"] = "S-1-5-32-569",
        ["ED"] = "S-1-5-9",
        ["ER"] = "S-1-5-32-573",
        ["ES"] = "S-1-5-32-576",
        ["HA"] = "S-1-5-32-578",
        ["HI"] = "S-1-16-12288",
        ["HO"] = "S-1-5-32-584",
        ["IS"] = "S-1-5-32-568",
        ["IU"] = "S-1-5-4",
        ["LS"] = "S-1-5-19",
        ["LU"] = "S-1-5-32-559",
        ["LW"] = "S-1-16-4096",
        ["ME"] = "S-1-16-8192",
        ["MP"] = "S-1-16-8448",
        ["MU"] = "S-1-5-32-558",
        ["NO"] = "S-1-5-32-556",
        ["NS"] = "S-1-5-20",
        ["NU"] = "S-1-5-2",
        ["OW"] = "S-1-3-4",
        ["PO"] = "S-1-5-32-550",
        ["PS"] = "S-1-5-10",
        ["PU"] = "S-1-5-32-547",
        ["RA"] = "S-1-5-32-575",
        ["RC"] = "S-1-5-12",
        ["RD"] = "S-1-5-32-555",
        ["RE"] = "S-1-5-32-552",
        ["RM"] = "S-1-5-32-580",
        ["RU"] = "S-1-5-32-554",
        ["SH"] = "S-1-5-32-585",
        ["SI"] = "S-1-16-16384",
        ["SO"] = "S-1-5-32-549",
        ["SS"] = "S-1-18-2",
        ["SU"] = "S-1-5-6",
        ["SY"] = "S-1-5-18",
        ["UD"] = "S-1-5-84-0-0-0-0-0",
        ["WD"] = "S-1-1-0",
        ["WR"] = "S-1-5-33",
    };

    public SecurityIdentifier(WellKnownSidType sidType, SecurityIdentifier? domainSid)
    {
        var type = (int)sidType;
        if (type < 0 || type > 94 || type == 21)
            throw new ArgumentException("The SID type cannot be constructed.", nameof(sidType));
        if (type is >= 38 and <= 50)
        {
            ArgumentNullException.ThrowIfNull(domainSid);
            if (!domainSid.IsAccountSid() || domainSid._sid.SubAuthorityCount != 4)
                throw new ArgumentException("A Windows account domain SID is required.", nameof(domainSid));
        }
        if (WellKnownValues.TryGetValue(type, out var value))
        {
            _sid = Sid.Parse(value);
            return;
        }
        if (DomainRelativeRids.TryGetValue(type, out var rid) && domainSid is not null
            && domainSid._sid.SubAuthorityCount < Sid.MaxSubAuthorities)
        {
            _sid = Sid.Parse(domainSid.Value + "-" + rid.ToString(System.Globalization.CultureInfo.InvariantCulture));
            return;
        }
        throw new ArgumentException("The SID type and domain combination is invalid.", "sidType/domainSid");
    }

    public bool IsWellKnown(WellKnownSidType type)
    {
        if (WellKnownValues.TryGetValue((int)type, out var value)) return Value == value;
        if ((int)type == 21)
            return _sid.IdentifierAuthority == 5 && _sid.SubAuthorityCount == 3 && _sid.GetSubAuthority(0) == 5;
        return DomainRelativeRids.TryGetValue((int)type, out var rid) && IsAccountSid()
            && _sid.SubAuthorityCount == 5 && _sid.GetSubAuthority(4) == rid;
    }

    internal static string? GetSddlAlias(SecurityIdentifier sid)
    {
        foreach (var pair in SddlAliases)
            if (pair.Value == sid.Value) return pair.Key;
        return null;
    }
}
