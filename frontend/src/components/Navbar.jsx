function Navbar() {
  return (
    <header className="navbar">
      <div className="navbar-logo">
        🔐 SecureShare
      </div>

      <div className="navbar-right">
        <span>Welcome, User</span>
        <button>Logout</button>
      </div>
    </header>
  );
}

export default Navbar;