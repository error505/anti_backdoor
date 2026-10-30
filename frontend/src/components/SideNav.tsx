export interface NavItem<Id extends string> {
  id: Id;
  label: string;
  group: string;
}

interface Props<Id extends string> {
  items: NavItem<Id>[];
  active: Id;
  onSelect: (id: Id) => void;
}

/** Grouped navigation. Wide screens get a sidebar; narrow screens wrap into rows, so nothing ever scrolls sideways. */
export function SideNav<Id extends string>({ items, active, onSelect }: Props<Id>) {
  const groups = [...new Set(items.map((item) => item.group))];
  return (
    <nav className="sidenav" aria-label="Sections">
      {groups.map((group) => (
        <div className="nav-group" key={group}>
          <div className="nav-heading">{group}</div>
          {items.filter((item) => item.group === group).map((item) => (
            <button key={item.id} type="button" className={item.id === active ? "tab active" : "tab"}
              aria-current={item.id === active ? "page" : undefined} onClick={() => onSelect(item.id)}>
              <span className="tab-index">{String(items.indexOf(item) + 1).padStart(2, "0")}</span>
              {item.label}
            </button>
          ))}
        </div>
      ))}
    </nav>
  );
}
