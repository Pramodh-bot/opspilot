import { useEffect, useRef } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth";

export function Layout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);

  // Move focus to the page on route change so keyboard and screen-reader users land on new content.
  useEffect(() => {
    mainRef.current?.focus();
  }, [location.pathname]);

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="site-header">
        <Link to="/" className="brand">
          OpsPilot
        </Link>
        <nav aria-label="Main">
          <NavLink to="/" end>
            Incidents
          </NavLink>
          <NavLink to="/runbooks">Runbooks</NavLink>
        </nav>
        <div className="user-box">
          <span>
            {user?.name} <span className="muted">({user?.role})</span>
          </span>
          <button type="button" className="btn btn-secondary" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>
      <main id="main" tabIndex={-1} ref={mainRef}>
        <Outlet />
      </main>
    </>
  );
}
