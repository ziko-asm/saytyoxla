// Uses the SVG symbols defined once in index.html (#i-check, #i-x, ...)
export function Icon({ name }: { name: string }) {
  return (
    <svg className="ico" aria-hidden="true">
      <use href={`#${name}`} />
    </svg>
  )
}
