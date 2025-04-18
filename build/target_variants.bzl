targets = [
    # keep sorted
    "canoe",
    "monaco",
    "parrot",
    "sun",
    "vienna",
]

la_variants = [
    # keep sorted
    "consolidate",
    "perf",
]

gki_targets = [
    # keep sorted
    "anorak",
    "autoghgvm",
    "autogvm",
    "blair",
    "neo-la",
    "niobe",
    "pitti",
    "sdmsteppeauto",
    "seraph",
]

gki_variants = [
    # keep sorted
    "consolidate",
    "gki",
]

gki_perf_targets = [
    # keep sorted
    "gen3auto",
    "pineapple",
]

gki_perf_variants = [
    # keep sorted
    "consolidate",
    "gki",
    "perf"
]

def get_all_la_variants():
    tv = [ (t, v) for t in targets for v in la_variants ]
    tv = tv + [ (t, v) for t in gki_targets for v in gki_variants ]
    tv = tv + [ (t, v) for t in gki_perf_targets for v in gki_perf_variants ]

    return tv
