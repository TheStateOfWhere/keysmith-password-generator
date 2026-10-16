# Dictionary attribution and provenance

PasswordForge v0.2 uses a filtered English Speller Database (ESDB, formerly
SCOWL) US-large word list, size 70, by Kevin Atkinson and contributors.

Pinned generated-output repository:
https://github.com/en-wl/wordlist-diff/tree/7f2f4078354752045ee16a041605686561122185

Sources, downloaded October 8, 2026:
- en_US-large.txt, bundled as data/esdb-en_US-large.txt
- scowl.txt, bundled as data/esdb-annotations.txt for suitability annotations
- Copyright, bundled verbatim as data/ESDB-Copyright.txt

The source license permits use, modification, and redistribution with the
required copyright and permission notices. The full Copyright file is retained,
including its additional component notices, because annotation data is included
alongside the generated US word list. ESDB does not endorse PasswordForge.

Adaptation: retain original lowercase ASCII entries of 4–12 letters; remove
all words containing l/i/o; deduplicate; remove data/exclusions.txt entries and
complete word forms marked offensive/vulgar in ESDB. Do not split compound words
into invented entries. Capitalized source entries are omitted. Frequency or
commonness is not an additional selection restriction.

There are 17,195 approved eligible words. The default selects from the full
4–12-letter pool. Source, license, annotation, exclusion, sensitive-word, and
eligible-pool hashes are pinned in data/esdb-provenance.json. The offline build
verifies every pinned input and the final approved output before generating
src/dictionary.ts. Updating these pins requires reviewing the intended changes.

The bundled source and annotation files allow reproducible offline filtering;
the runtime loads only the generated local dictionary. No dictionary APIs or
remote lookups are used. The dictionary is public: its contribution to entropy
comes from uniform selection, not secrecy.

## v0.4.0 approved readability adaptation

The ten exact replacements in data/readability-overrides.json replace ten ESDB
entries with ten entries from the bundled EFF Long Wordlist by Joseph Bonneau /
Electronic Frontier Foundation (2016), under CC BY 4.0. This is a modification
and combination of the two attributed sources, not an EFF endorsement. All
upstream files and license notices remain unchanged. The historical description
below applies to v0.2; v0.4 uses only these ten EFF additions, not the whole list.
Exactly 17,195 eligible entries remain. Both the overrides and EFF input are
checksum-pinned. The replacements improve selected spellings; they do not imply
that all dictionary words are familiar or easy to type.

## Historical EFF material retained from v0.1.1

The original EFF Long Wordlist, by Joseph Bonneau / Electronic Frontier
Foundation (2016), remains bundled as data/eff_large_wordlist.txt for provenance.
It is not the v0.2 generator's dictionary.
Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
License: CC BY 4.0 per https://www.eff.org/copyright
The full license is retained as data/CC-BY-4.0.txt and in dist/licenses/.
EFF does not endorse PasswordForge.
