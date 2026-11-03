# Elrich · Moonstone Campaign Ledger (Flask)

A small Flask + SQLite campaign app with accounts, faction selection, campaign signup, and campaign-specific troupe management.

## Run locally

Requires Python 3.10+.

```powershell
cd moonstone-flask
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FLASK_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

Open http://127.0.0.1:5000. SQLite creates `moonstone.db` in this folder on first request. To store it elsewhere, set `MOONSTONE_DATABASE` to a file path. Set `FLASK_HTTPS=1` when serving over HTTPS so the session cookie is marked secure.

## Player and troupe flow

- Registration creates an account with status `new`; it does not ask for a faction.
- A player chooses a faction separately for each campaign when joining: Dominion, Leshavult, Shades, or Commonwealth. The campaign creator joins through the same flow.
- Players can withdraw themselves while a campaign is still new. The campaign creator can withdraw any signed-up player from the player list until the campaign starts; withdrawing removes that player's unstarted troupe from the campaign.
- After joining, a player picks exactly five distinct starting characters that match that campaign's faction and submits the troupe. The troupe and campaign membership become `ready`; the account status also changes to `ready`.
- Campaign organizers can start once all signed-up players are ready, advance every round through Machinations, Encounter, and Troupe Growth, and reverse a phase if needed. Players can edit or remove their current-round choices during Troupe Growth only; previous-round choices are locked. Roster additions follow the campaign parameter: one character **or** one upgrade per round, or one of each.
- Before starting, the organizer draws a round-robin schedule and assigns a distinct pairing set to each campaign round. Opponents do not repeat, and an odd participant count receives a BYE. The current round's pairings are visible to campaign players after the campaign starts. A new signup or withdrawal clears the draw so it can be regenerated for the updated roster.
- From round 2 onward, players can privately submit up to two machinations during Machinations: support, sabotage, one of each, or none. They cannot target themselves or their current opponent, and cannot target the same player twice with the same type. On entering Encounter, each player's default two campaign cards are adjusted by received support and sabotage, clamped to one through three; support beyond the three-card cap is stored as machination points. Only the player's own allowance and points are shown.
- During Encounter, each player selects exactly their campaign-card allowance from cards assigned to their faction. Each player can use a given card once per campaign, while their opponent may also use it once. The current-round pairing list shows the cards used by each player. Both players enter their moonstones and bonus victory points, then confirm the shared result; the organizer can confirm on their behalf. The organizer cannot advance to Troupe Growth until every actual matchup has the required cards, scores, and confirmations. BYE rounds require no Encounter submissions.
- During Encounter, each player selects exactly their campaign-card allowance from cards assigned to their faction. Each card can be used once per campaign, and the campaign page lists card use by round and player. Both players enter their moonstones and bonus victory points, then confirm the shared result; the organizer can confirm on their behalf. The organizer cannot advance to Troupe Growth until all matchups have the required cards, scores, and confirmations. BYE rounds require no Encounter submissions.
- A character or upgrade can be linked to a card reference and assigned one or more factions. The app checks faction eligibility against the player's selected faction.
- Campaign creators can always change campaign name, location, and the addition rule. While the campaign status is `new`, they can also change rounds and the optional player limit (blank means no limit).
- The default addition rule is one character **or** one upgrade per completed round; the alternative allows one character **and** one upgrade after the same round. Each character can carry up to two upgrades. Change `MAX_UPGRADES_PER_CHARACTER` in `app.py` if needed.

The starter card catalogue includes Muridae v3 (Commonwealth and Dominion) and Foxglove (Dominion). The **Manage Cards** page is the shared place to add or correct character, campaign, and upgrade card entries. Cards can be marked inactive to remove them from new troupe choices while retaining existing troupe references. Cards already used by a troupe cannot be hard-deleted; unused cards can be deleted. Upgrade entries use one HTTPS card image URL; a “View card image” link reveals it in the troupe or upgrade form. The image is not shown as a preview and the app stores only its URL, not an uploaded copy of the artwork. MoonstoneDB currently shows character pages with faction labels and card details: https://moonstonedb.8oni.com/characters/ .

## Existing database migration

On startup, the app adds status to existing users, current-round, current-phase, player-limit, and addition-rule fields to campaigns, and status and faction to campaign memberships. Existing memberships inherit the user's previous faction when that field exists, otherwise they default to Dominion. Existing campaigns default to no player limit, the Machinations phase, and the either/or addition rule. Existing memberships need troupe setup before the organizer can start their campaign.

## Included

- Password-hashed registration, sign in/out, session handling, and CSRF checks.
- Campaign creation, signed player count, optional capacity enforcement, and join only while campaign status is `new`.
- Campaign player list with faction and troupe size; ready troupes have a read-only character and upgrade details page.
- Organizer campaign parameter editing with status-dependent fields.
- Central card catalogue management for character, campaign, and upgrade cards.
- Five-character initial troupe submission with faction validation.
- Organizer start and phase progression through Machinations, Encounter, and Troupe Growth.
- Post-round character recruitment and faction-eligible upgrades following the selected either/or or both rule, with a per-character cap.
- Responsive pages and SQLite persistence.

Set a fresh `FLASK_SECRET_KEY` before exposing the app beyond local development. For production, run behind an HTTPS-capable WSGI server rather than Flask's development server.
