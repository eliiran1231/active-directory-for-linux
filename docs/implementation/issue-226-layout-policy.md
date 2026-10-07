# Descriptor layout preservation

Raw write representation and Microsoft observable repacking are separate operations.
`DescriptorRewriter.Rewrite` never uses omitted observable bytes as a persistence result.
`RepackObservable` is a detached read projection; raw/original descriptors and intent remain
unchanged. Unknown ACE payload, wrong-kind, reserved ACL-header and ACL-tail projection
restrictions remain in force. Only unreferenced descriptor storage is omitted from this
recorded observable representation.

## Supported raw writes

Descriptors with fully referenced storage retain the existing independently packed rewrite.
For descriptors with leading/intercomponent/trailing bytes or orphan storage:

- Same-size replacements keep component offsets and the original image length. Every byte
  outside changed components and requested header fields remains fixed.
- A terminal component may grow or shrink at its original offset only when its original end
  equals the image end. Removed bytes belong to that known component; original unexplained
  bytes are neither consumed nor shifted. ACLs with their own unexplained trailing payload
  refuse resizing in this mode.
- A fully contained alias may move to new independent, four-byte-aligned storage when its
  original span is still covered by an outer referenced component. Equal spans prefer an
  unchanged anchor. This also permits adding a previously absent component at the end.
  Both cases require the original image to end in referenced storage, not an unexplained
  trailer. Any newly needed alignment padding is added, never taken from an existing gap.
- Publication validates the whole descriptor, rejects remaining overlap and verifies every
  original unreferenced byte at its original absolute offset. Unknown bytes are not archived
  elsewhere to claim preservation. Raw operations retain existing no-op and intent behavior.

Contained owner/group SIDs can be unshared from each other or an ACE. When an edited terminal
ACL shrinks, contained identity SIDs are copied from the immutable source before the new
layout is assembled. The source image is never changed in place. Crossing overlaps without
a containing anchor refuse; relocating both would orphan their former union.

## Concrete remaining refusals

In recorded `layout-trailing-A5-Add`, the DACL starts at byte 84 and has length 44. Four
unexplained `A5` bytes occupy positions 128–131. Adding the second 36-byte ACE would make the
DACL occupy bytes 84–163, overwriting those bytes. Appending a replacement after byte 131
would instead reclassify the trailer as an interior gap and orphan the former DACL. Neither
is an approved preservation operation, so the complete edit refuses atomically. A same-size
mask edit or protection-bit change on that descriptor succeeds while retaining the trailer.
Zero-filled trailers receive the same protection; zero is not evidence of disposable slack.

Interior resizing also refuses: it would need to move adjacent storage, consume unexplained
gaps or introduce orphan component suffixes. Removing a referenced component entirely in a
gapped image refuses rather than changing unknown-storage boundaries. Resizing an ACL with
its own trailing payload in this mode, and crossing shared spans, remain bounded refusals.
These do not prevent fixed-size or other independently safe edits.

## Recorded evidence

`LayoutSequences.cs`, probe commit `6840525d3bd92fa9316524dd183344dc89bf6029`,
[run 37678217815](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37678217815),
recorded 107 observations: 12 layouts × eight imports/operations, plus 11 independently
constructed persistence-candidate imports. Both .NET runtimes agree on all 1,492 observations;
the earlier 1,385 remain unchanged. No layout probe threw. The probe intentionally fails
freshness against the preceding recording baseline while portable tests pass.

The layouts cover zero/nonzero leading/intercomponent/trailing bytes, unaligned offsets,
shared SID storage with original orphan bytes, SIDs embedded in an ACE, and absent/NULL/
empty sections. Operations cover identity replacement, mask replacement, growth/shrink,
removal and protection. Candidate imports include fixed-offset edits, terminal resizing and
contained-SID unsharing. A portable test compares all 11 raw candidates byte-for-byte with
the independently constructed inputs actually imported by Microsoft.

Separate raw-layout replay asserts observable outcomes for supported writes and explicit
atomic refusals for policy boundaries. It checks every original unreferenced byte at its
original position, raw/original immutability and non-overlap. Additional tests exercise prior
intent, retained live state, opaque ACL tails, crossing spans and new allocation alignment.

## Next public-surface dependencies

1. Bind the approved detached public types/rule collections to the internal engine. Preserve
   retained live state across getters and rule edits; expose validation/constructor/exception
   behavior only after directed Windows evidence. Keep raw serialization separate from the
   Microsoft-style observable representation and explicit re-import.
2. Define the SID-to-identity resolver boundary and Windows interop adapters. Detached core
   operations must remain free of implicit LDAP/network work. Interop conversions need
   explicit import/export ownership and tests for unknown data and retained-state lifetime.
3. Wire DirectoryEntry retrieval and commit policy: retrieved section masks, accumulated
   write intent, raw write preparation, failed/no-op behavior and concurrency/error handling.
   Never persist a lossy observable projection. The documented layout refusals must surface
   before a directory write rather than being silently repacked.
4. Validate the public surface on Linux/Windows .NET 8/10 with detached fixtures, then add
   separately authorized directory integration coverage for resolver/write behavior. Public
   packaging/migration and full API parity follow those contracts. Live AD, privilege setup
   and effective-access evaluation are not part of this completed core slice.
