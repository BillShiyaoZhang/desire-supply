const paths: Record<string, string> = {
  inbox: "M4 4h16v16H4z M4 13h5l2 3h2l2-3h5",
  person: "M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M4 21v-2a8 8 0 0 1 16 0v2",
  document: "M14 3H5v18h14V8z M14 3v6h5 M8 13h8 M8 17h6",
  check: "M15 4h4v17H5V4h4 M9 3h6v4H9z M8 14l3 3 5-6",
  wallet: "M4 5h15v4 M4 5v15h17V9H4 M21 13h-6v4h6",
  people: "M14 7a3 3 0 1 1-6 0 3 3 0 0 1 6 0 M3 21v-3a8 8 0 0 1 16 0v3 M17 4a3 3 0 0 1 0 6 M21 21v-3a8 8 0 0 0-2-5",
  shield: "M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M8 12l3 3 5-6",
  review: "M20 11a8 8 0 1 1-3-6 M20 3v6h-6 M12 8v5l3 2",
  building: "M5 21V3h14v18 M3 21h18 M9 7h1 M14 7h1 M9 11h1 M14 11h1 M10 21v-5h4v5",
  timeline: "M5 3v18 M3 5h4 M3 12h4 M3 19h4 M11 5h10 M11 12h7 M11 19h10",
  lock: "M6 10h12v11H6z M8 10V7a4 4 0 0 1 8 0v3 M12 14v3",
};

export function WorkspaceIcon({ name }: { name: string }) {
  return <svg className="nav-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] ?? paths.document} /></svg>;
}
