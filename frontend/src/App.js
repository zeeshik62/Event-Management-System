import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';
import Login from "./pages/Login.js"
import Signup from "./pages/Signup.js"

function App() {
  return (
    <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
        </Routes>
    </Router>
  );
}

export default App;
