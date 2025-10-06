import { Link } from 'react-router-dom';
import './Header.css';

function Header() {
  return (
    <header className="header">
      <div className="container">
        <div className="header-content">
          <Link to="/" className="logo">
            <span className="logo-icon">🛡️</span>
            <span className="logo-text">Lubellion's Hacking Documentation</span>
          </Link>
          <nav className="nav">
            <Link to="/" className="nav-link">Home</Link>
            <Link to="/about" className="nav-link">Tentang</Link>
            <a 
              href="https://github.com" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="nav-link"
            >
              GitHub
            </a>
          </nav>
        </div>
      </div>
    </header>
  );
}

export default Header;
