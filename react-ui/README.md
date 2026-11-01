# SaytYoxla — React interface (learning project)

A small React + TypeScript + Vite front end for the SaytYoxla API. It is a learning project and is **not deployed**; the live site is still served by `web/` (FastAPI).

## Run it

```bash
cd react-ui
npm install
npm run dev        # http://localhost:5173
```

On Windows PowerShell, if `npm` is blocked, use `npm.cmd` instead.

In development, `vite.config.ts` forwards every `/api/...` request to `https://saytyoxla.vercel.app`, so the browser only talks to localhost and there is no CORS problem.

## What is in `src/App.tsx`

| Idea | Where |
|---|---|
| **State** with `useState` | `url`, `loading`, `error`, `report` |
| **Events** | `onSubmit={check}` on the form, `onChange` on the input |
| **Calling an API** | `fetch('/api/scan', …)` inside `async function check` |
| **Conditional rendering** | `{error && …}`, `{report && …}` |
| **Lists** | `problems.map(...)` with a `key` per item |
| **Types** | `type Report` and `type Finding` describe the JSON the API returns |

## Next exercises

1. Show the number of problems next to the grade.
2. Colour the grade by score (green, yellow, red).
3. Keep the last 5 checked sites in `localStorage` and list them under the form.
4. Split the result into its own component: `<Result report={report} />`.
