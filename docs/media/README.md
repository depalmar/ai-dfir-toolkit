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
for n in alert plan; do
  ffmpeg -y -i /tmp/rec/$n.webm -c:v libx264 -pix_fmt yuv420p -crf 20 -movflags +faststart -an -r 25 /tmp/rec/$n.mp4
  ffmpeg -y -i /tmp/rec/$n.webm -vf "fps=6,scale=800:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" /tmp/rec/$n.gif
done
```

`alert` becomes `start-from-the-alert`, and `plan` becomes `collection-plan`.
Recorded on 2026-11-17 against the build that added the Hunts tab.
