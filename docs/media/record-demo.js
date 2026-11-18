// Records the two demo clips in the README from a local build of the site.
//
//   python3 artifacts/scripts/build_site.py
//   node docs/media/record-demo.js [path/to/index.html] [output dir]
//
// Needs Playwright with Chromium. Writes a folder of frames, <name>/, with a
// frames.txt that ffmpeg reads, and a 2x still <name>.png for each scene;
// README.md in this folder has the ffmpeg lines that turn them into the
// committed GIF and MP4. Re-record when the page's layout changes:
// a demo that shows a tab the site no longer has is worse than no demo.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const SITE = 'file://' + path.resolve(process.argv[2] || path.join(__dirname, '../../artifacts/docs/site/index.html'));
const OUT = path.resolve(process.argv[3] || 'rec');
const W = 1280, H = 760;
const CURSOR = `(() => { const c = document.createElement('div'); c.id = '__cur';
  c.style.cssText = 'position:fixed;left:0;top:0;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:50%;background:rgba(92,58,33,.28);border:2px solid #5C3A21;z-index:2147483647;pointer-events:none;transition:transform .12s;';
  const add = () => document.body && document.body.appendChild(c);
  if (document.body) add(); else document.addEventListener('DOMContentLoaded', add);
  document.addEventListener('mousemove', e => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
  document.addEventListener('mousedown', () => { c.style.transform = 'scale(.6)'; }, true);
  document.addEventListener('mouseup', () => { c.style.transform = 'scale(1)'; }, true); })();`;
async function to(p, sel, opts = {}) {
  const el = typeof sel === 'string' ? p.locator(sel).first() : sel;
  await el.scrollIntoViewIfNeeded();
  const b = await el.boundingBox();
  await p.mouse.move(b.x + b.width * (opts.fx ?? 0.5), b.y + b.height / 2, { steps: 28 });
  await p.waitForTimeout(opts.hold ?? 350);
  if (opts.click !== false) { await p.mouse.down(); await p.waitForTimeout(90); await p.mouse.up(); }
}
const scenes = {
  async alert(p, still) {
    await p.waitForTimeout(900);
    await to(p, '#alTool');
    await p.keyboard.type('Cursor', { delay: 170 });
    await p.waitForTimeout(700);
    await to(p, '#alList [role=option]');
    await p.waitForTimeout(1500);
    await to(p, 'label.alopt:has(input[name=alrole][value=wayin])');
    await p.waitForTimeout(1300);
    if (still) return;
    await to(p, 'label.alopt:has(input[name=alwhere][value=acct])');
    await p.waitForTimeout(1300);
    await to(p, 'label.alopt:has(input[name=alwhere][value=host])');
    await p.waitForTimeout(700);
    await to(p, '#alVol');
    await p.waitForTimeout(1600);
  },
  async plan(p, still) {
    await p.fill('#alTool', 'Cursor'); await p.click('#alList [role=option]'); await p.click('#alAll');
    await p.mouse.move(640, 420);
    await p.waitForTimeout(still ? 200 : 1100);
    await to(p, '#tab-plan', { fx: 0.3 });
    await p.waitForTimeout(1500);
    await to(p, 'button.segbtn:has-text("by volatility")');
    await p.waitForTimeout(1200);
    if (still) return;
    await p.mouse.move(640, 520, { steps: 15 });
    for (let i = 0; i < 14; i++) { await p.mouse.wheel(0, 60); await p.waitForTimeout(90); }
    await p.waitForTimeout(900);
    for (let i = 0; i < 14; i++) { await p.mouse.wheel(0, -60); await p.waitForTimeout(60); }
    await p.waitForTimeout(500);
    await to(p, '#pExport', { click: false });
    await p.selectOption('#pExport', 'velo'); await p.waitForTimeout(1400);
    await p.selectOption('#pExport', 'kape'); await p.waitForTimeout(1400);
    await p.selectOption('#pExport', 'native'); await p.waitForTimeout(800);
    await to(p, '#pDl', { click: false });
    await p.waitForTimeout(1400);
  },
};
// The clip is captured as lossless screenshots at twice the layout size, not
// with Playwright's recordVideo. recordVideo encodes at the layout size and a
// low fixed bitrate, and the first clips made from it were visibly soft: text
// went fuzzy once GitHub scaled an 800px GIF up on a high-density screen. The
// browser's own screencast has the same limit - it sends layout-size frames
// whatever the device scale - so this polls for screenshots while the scene
// runs. A frame identical to the one before it is dropped, and each kept frame
// is written with how long it was on screen, which is what ffmpeg reads.
async function capture(ctx, page, dir, run) {
  fs.mkdirSync(dir, { recursive: true });
  const cdp = await ctx.newCDPSession(page);
  const frames = [];
  let on = true, last = '';
  const loop = (async () => {
    while (on) {
      const t = Date.now() / 1000;
      // The clip's scale is what makes the frame 2x: without it this call
      // returns layout-size pixels whatever the context's device scale. A clip
      // is in page coordinates, so it has to follow the scroll position, or a
      // scrolled page is captured as the blank area above the viewport.
      const { cssVisualViewport: vv } = await cdp.send('Page.getLayoutMetrics');
      const { data } = await cdp.send('Page.captureScreenshot', { format: 'png', optimizeForSpeed: true,
        clip: { x: vv.pageX, y: vv.pageY, width: W, height: H, scale: 2 } });
      if (data !== last) {
        const file = String(frames.length).padStart(5, '0') + '.png';
        fs.writeFileSync(path.join(dir, file), Buffer.from(data, 'base64'));
        frames.push({ file, t });
        last = data;
      }
    }
  })();
  const t0 = Date.now() / 1000;
  await run();
  on = false;
  await loop;
  const end = Date.now() / 1000;
  const lines = ['ffconcat version 1.0'];
  frames.forEach((f, i) => {
    const next = i + 1 < frames.length ? frames[i + 1].t : Math.max(end, f.t + 0.2);
    lines.push(`file '${f.file}'`, `duration ${Math.max(0.02, next - f.t).toFixed(3)}`);
  });
  if (frames.length) lines.push(`file '${frames[frames.length - 1].file}'`);
  fs.writeFileSync(path.join(dir, 'frames.txt'), lines.join('\n') + '\n');
  return { frames: frames.length, seconds: +(end - t0).toFixed(1) };
}
(async () => {
  const b = await chromium.launch();
  for (const name of Object.keys(scenes)) {
    // the clip
    let ctx = await b.newContext({ viewport: { width: W, height: H }, colorScheme: 'light', deviceScaleFactor: 2 });
    await ctx.addInitScript(CURSOR);
    let p = await ctx.newPage();
    await p.goto(SITE);
    const got = await capture(ctx, p, path.join(OUT, name), () => scenes[name](p, false));
    await ctx.close();
    // the still, at 2x, without the pointer
    ctx = await b.newContext({ viewport: { width: W, height: H }, colorScheme: 'light', deviceScaleFactor: 2 });
    p = await ctx.newPage();
    await p.goto(SITE);
    await scenes[name](p, true);
    await p.mouse.move(5, 400);
    await p.waitForTimeout(300);
    await p.screenshot({ path: path.join(OUT, name + '.png') });
    await ctx.close();
    console.log(name, got.frames + ' frames', got.seconds + 's');
  }
  await b.close();
})().catch(e => { console.error(e); process.exit(1); });
