import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';
import Login from "./pages/Login.js"
import Signup from "./pages/Signup.js"

function App() {
  return (
    <Router>
        <Routes>
          <Route path="/Login" element={<Login />} />
          <Route path="/" element={<Signup />} />
        </Routes>
    </Router>
  );
}

export default App;
