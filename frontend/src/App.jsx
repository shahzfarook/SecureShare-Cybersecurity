import { BrowserRouter, Routes, Route } from "react-router-dom";

import Login from "./pages/Login";
import Register from "./pages/Register";

import Navbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";

import Dashboard from "./pages/Dashboard";
import MyFiles from "./pages/MyFiles";
import UploadFile from "./pages/UploadFile";
import SharedFiles from "./pages/SharedFiles";
import Activity from "./pages/Activity";
import ThreatCenter from "./pages/ThreatCenter";

function Layout({ children }) {
  return (
    <div className="app">
      <Navbar />

      <div className="layout">
        <Sidebar />

        <main className="main-content">
          {children}
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* Login */}
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />

        {/* Register */}
        <Route path="/register" element={<Register />} />

        {/* Dashboard */}
        <Route
          path="/dashboard"
          element={
            <Layout>
              <Dashboard />
            </Layout>
          }
        />

        {/* Threats & Vulnerability Center */}
        <Route
          path="/threats"
          element={
            <Layout>
              <ThreatCenter />
            </Layout>
          }
        />

        {/* Other pages */}
        <Route
          path="/files"
          element={
            <Layout>
              <MyFiles />
            </Layout>
          }
        />

        <Route
          path="/upload"
          element={
            <Layout>
              <UploadFile />
            </Layout>
          }
        />

        <Route
          path="/shared"
          element={
            <Layout>
              <SharedFiles />
            </Layout>
          }
        />

        <Route
          path="/activity"
          element={
            <Layout>
              <Activity />
            </Layout>
          }
        />

      </Routes>
    </BrowserRouter>
  );
}

export default App;