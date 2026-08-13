import Navbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";

function App() {
  return (
    <div className="app">

      <Navbar />

      <div className="layout">

        <Sidebar />

        <main className="main-content">
          <Dashboard />
        </main>

      </div>

    </div>
  );
}

export default App;