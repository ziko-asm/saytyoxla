# SaytYoxla — React front end

The home page of https://saytyoxla.vercel.app is built from this folder with React + TypeScript + Vite. The previous plain-JavaScript page is kept at `/classic` (`web/static/index.html`).

## Run and build

```bash
cd react-ui
npm install
npm run dev        # http://localhost:5173 — /api requests go to the live service
npm run build      # writes ../web/react, which FastAPI serves at /
```

On Windows PowerShell, if `npm` is blocked, use `npm.cmd`. **After changing anything here, run `npm run build` and commit `web/react/` too**: Vercel serves the built files, it does not build them.

## How the page is split

`index.html` holds everything search engines need as plain HTML: meta tags, JSON-LD, the heading and the how-to (as a fallback inside `#root`), "What we check", the FAQ and the footer. React replaces `#root` with the interactive app when it loads.

| File | What it does |
|---|---|
| `src/App.tsx` | State (`url`, `loading`, `error`, `report`, `guideOpen`), the `scan()` call to `/api/scan`, `?url=` auto-scan |
| `components/ScanForm.tsx` | Form, hint, error, the 4-step how-to |
| `components/Loading.tsx` | Spinner with changing step text (`useEffect` + `setInterval`) |
| `components/ReportView.tsx` | Score ring, grade, chips, findings grouped by category, print/PDF, WhatsApp |
| `components/ScoreRing.tsx` | Counts the score up with `requestAnimationFrame` |
| `components/FindingItem.tsx` | One finding with icon, label and fix |
| `components/Guide.tsx` | The help dialog (focus, Escape, scroll lock) |
| `components/Header.tsx`, `Icon.tsx`, `types.ts` | Header, SVG icon helper, API types |
| `src/SimpleApp.tsx` | The first, minimal version — a good place to start reading |

## Exercises

1. Show the number of problems next to the grade.
2. Keep the last 5 checked sites in `localStorage` and list them under the form.
3. Add a "Copy link" button that copies `https://saytyoxla.vercel.app/?url=<site>`.
4. Write a test for `ReportView` with Vitest and React Testing Library.

## PDF reports
`src/pdf.ts` draws each page on a canvas and stores it as a JPEG, then lays the same text over it invisibly (PDF text
mode 3), so the file can be searched, copied from and read by a screen reader. That text uses a 620-byte font with no
shapes (`BLANK_FONT`): nothing is ever drawn with it, it only gives the characters a width. It was made once with fontTools:

```python
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
fb = FontBuilder(1000, isTTF=True)
fb.setupGlyphOrder([".notdef", "space"]); fb.setupCharacterMap({32: "space"})
fb.setupGlyf({".notdef": TTGlyphPen(None).glyph(), "space": TTGlyphPen(None).glyph()})
fb.setupHorizontalMetrics({".notdef": (500, 0), "space": (500, 0)})
fb.setupHorizontalHeader(ascent=800, descent=-200)
fb.setupNameTable({"familyName": "SaytYoxlaText", "styleName": "Regular"})
fb.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWinAscent=800, usWinDescent=200); fb.setupPost()
fb.save("blank.ttf")      # base64 of this file is BLANK_FONT
```

