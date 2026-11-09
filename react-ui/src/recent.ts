// The last checked sites, kept only in this browser (localStorage). Nothing is sent anywhere.
export const RECENT_KEY = 'saytyoxla-recent'
export const RECENT_MAX = 5

// Newest first, no duplicates (compared without case), at most `max` entries
export function pushRecent(list: string[], host: string, max = RECENT_MAX): string[] {
  const value = host.trim()
  if (!value) return list
  const rest = list.filter((item) => item.toLowerCase() !== value.toLowerCase())
  return [value, ...rest].slice(0, max)
}

// Anything that is not a list of short strings is ignored: the value may have been edited by hand
export function parseRecent(raw: string | null, max = RECENT_MAX): string[] {
  if (!raw) return []
  try {
    const data: unknown = JSON.parse(raw)
    if (!Array.isArray(data)) return []
    return data.filter((x): x is string => typeof x === 'string' && x.length > 0 && x.length <= 300).slice(0, max)
  } catch {
    return []
  }
}

// localStorage can be missing or throw (private mode, blocked site data), so every access is guarded
export function loadRecent(): string[] {
  try {
    return parseRecent(localStorage.getItem(RECENT_KEY))
  } catch {
    return []
  }
}

export function saveRecent(list: string[]): void {
  try {
    if (list.length) localStorage.setItem(RECENT_KEY, JSON.stringify(list))
    else localStorage.removeItem(RECENT_KEY)
  } catch {
    /* the list just will not survive a reload */
  }
}
