# Attack Surface Locked: 250 Techniques

**Date Locked:** April 11, 2026

This is the **canonical reference attack surface** for deterministic-boundary-firewall by Serhat Soruklu.

Any attack technique **not explicitly listed** in these 250 is currently considered **invalid and out of scope** for testing this version of BoundaryGate.

## Complexity is the enemy of safety, and transparency is its only cure.

by Serhat Soruklu

## Purpose of the Lock

The core of this repository is frozen.  
We want the community to test the actual implementation as it exists today — not to invent increasingly abstract or delusional attack ideas.

This locked list of 250 techniques defines the official, reproducible baseline. It focuses on practical, character-level, encoding, structural, and semantic attacks that can be realistically applied to the current normalizer and refusal logic.

New or more exotic techniques discovered after April 11, 2026 should be used to create improved forks, not to claim that the current locked version has been "bypassed" in unrealistic ways.

## Locked Categories

The 250 techniques are grouped as follows:

1. **Basic Obfuscation & Normalization Evasion** — 50 techniques  
   (zero-width spaces, homoglyphs, leetspeak, spaced letters, punctuation variations, case folding tricks, etc.)

2. **Encoding & Decoding Attacks** — 35 techniques  
   (Base64, ROT13, hex, URL encoding, multi-layer chaining, cipher instructions, etc.)

3. **Unicode / Invisible Character Smuggling** — 55 techniques  
   (zero-width + homoglyph combinations, U+E0000 tag block smuggling, variation selectors, bidirectional overrides, Sneaky Bits, diacritic stacking, etc.)

4. **Semantic, Role-play & Contextual Attacks** — 45 techniques  
   (persona overrides, fictional framing, gradual escalation, semantic paraphrases, many-shot flooding, etc.)

5. **Policy Puppetry & Structured Overrides** — 25 techniques  
   (fake policy updates, manifest patches, hierarchical rule injection, multi-format nesting, admin impersonation, etc.)

6. **Adversarial Suffixes, FlipAttack Variants & Chaos Attacks** — 25 techniques  
   (adversarial suffixes, FlipAttack word/sentence/order reversals, token chaos, many-shot + suffix, imperceptible triggers, etc.)

7. **Agentic, Memory Poisoning & Meta-Firewall Attacks** — 20 techniques  
   (memory/RAG poisoning, zombie persistence, tool backdoors, self-propagating payloads, direct meta-attacks on the firewall, etc.)

## Important Rules for Testing

- Only use techniques from these 250.
- Attacks must be **reproducible** against the published code (run `python3 app.py` or the MCP server).
- Speculative, philosophical, or "what if the model thinks at a universal level" attacks are **not valid** for claiming bypasses on this version.
- Focus on what actually reaches the model or bypasses the pre-egress refusal envelope.

## Challenge Statement

**Community:**  
Use only these 250 locked techniques to test BoundaryGate as it exists on April 11, 2026.  
Document your bypasses clearly (which technique, success rate, which refusal category failed, etc.).  

Then fork the project and build stronger deterministic versions.

Credit the original idea to **Serhat Soruklu** and link back to:  
https://github.com/SerhatSoruklu/deterministic-boundary-firewall

Break it realistically. Make it better.

---

**Locked on April 11, 2026** — This baseline will not be expanded.
