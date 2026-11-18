# Demo clips

Screen recordings of the site, used in the root README. They show a local build,
driven by a script, with a drawn pointer. Nothing in them is live data from a
real host: the tool is Cursor's catalog entry and the plan is never run.

| File | What it shows |
|---|---|
| `start-from-the-alert.gif` / `.mp4` | Naming a tool on the landing page, choosing where the AI ran and its role, and its evidence appearing by volatility |
| `collection-plan.gif` / `.mp4` | A collection plan grouped by volatility, with the export switched between the native script, Velociraptor and KAPE |

The GIFs are what the README embeds, because GitHub plays a committed GIF inline
and does not play a committed video. The MP4s are the same clips at full size.

## Re-recording

```bash
python3 artifacts/scripts/build_site.py
node docs/media/record-demo.js artifacts/docs/site/index.html /tmp/rec
cd /tmp/rec
for n in alert plan; do
  ffmpeg -y -f concat -safe 0 -i $n/frames.txt -vf "fps=25,scale=1920:-2:flags=lanczos" \
    -c:v libx264 -pix_fmt yuv420p -crf 18 -movflags +faststart -an $n.mp4
done
P="split[a][b];[a]palettegen=stats_mode=diff:max_colors"
U="[p];[b][p]paletteuse=dither=none:diff_mode=rectangle"
ffmpeg -y -f concat -safe 0 -i alert/frames.txt -vf "fps=8,scale=1600:-1:flags=lanczos,$P=256$U" alert.gif
ffmpeg -y -f concat -safe 0 -i plan/frames.txt  -vf "fps=8,scale=1440:-1:flags=lanczos,$P=128$U" plan.gif
```

`alert` becomes `start-from-the-alert`, and `plan` becomes `collection-plan`.

The recorder writes lossless screenshots at twice the layout size (2560x1520)
with the time each was on screen, and ffmpeg scales them down. The first clips
were made with Playwright's own video recording at 1280 wide and turned into
800px GIFs with 64 colours; GitHub scales a README image up to the column
width, so on a high-density screen the text was fuzzy. The plan clip is
narrower and uses fewer colours than the alert clip because it scrolls, and
every scrolled frame is new pixels: at 1600 wide it was 4.6 MB.

Recorded on 2026-11-18 against the build with the reworked Hunts tab and the
pinned Collection plan tab.
