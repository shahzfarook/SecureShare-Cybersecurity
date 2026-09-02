import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import Login from "./pages/Login";
import Register from "./pages/Register";

import Navbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";

import Dashboard from "./pages/Dashboard";
import MyFiles from "./pages/MyFiles";
import UploadFile from "./pages/UploadFile";
import SharedFiles from "./pages/SharedFiles";
import AttackSimulator from "./pages/AttackSimulator";
import AttackLogs from "./pages/AttackLogs";

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
        {/* Authentication */}
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />
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

        {/* Attack Simulator */}
        <Route
          path="/simulator"
          element={
            <Layout>
              <AttackSimulator />
            </Layout>
          }
        />

        {/* Attack & Access Logs */}
        <Route
          path="/logs"
          element={
            <Layout>
              <AttackLogs />
            </Layout>
          }
        />

        {/* Seamless Navigation Aliases / Redirects */}
        <Route path="/simulation" element={<Navigate to="/simulator" replace />} />
        <Route path="/threats" element={<Navigate to="/logs" replace />} />
        <Route path="/activity" element={<Navigate to="/logs" replace />} />

        {/* Encrypted File Storage */}
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
      </Routes>
    </BrowserRouter>
  );
}

export default App;