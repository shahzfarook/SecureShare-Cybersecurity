import { BrowserRouter, Routes, Route } from "react-router-dom";

import Navbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";

import Dashboard from "./pages/Dashboard";
import MyFiles from "./pages/MyFiles";
import UploadFile from "./pages/UploadFile";
import SharedFiles from "./pages/SharedFiles";
import Activity from "./pages/Activity";

function App() {
  return (
    <BrowserRouter>
      <div className="app">

        <Navbar />

        <div className="layout">

          <Sidebar />

          <main className="main-content">
            <Routes>

              <Route path="/" element={<Dashboard />} />

              <Route path="/dashboard" element={<Dashboard />} />

              <Route path="/files" element={<MyFiles />} />

              <Route path="/upload" element={<UploadFile />} />

              <Route path="/shared" element={<SharedFiles />} />

              <Route path="/activity" element={<Activity />} />

            </Routes>
          </main>

        </div>

      </div>
    </BrowserRouter>
  );
}

export default App;