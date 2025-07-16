import React from 'react';
import { Routes, Route, Navigate, Link, useNavigate } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';

function App() {
  const token = localStorage.getItem('token');
  const nav = useNavigate();
  const logout = () => {
    localStorage.removeItem('token');
    nav('/login');
  };

  return (
    <div style={{ fontFamily: 'Arial, sans-serif', margin: '2rem' }}>
      <nav style={{ marginBottom: '1rem' }}>
        <Link to="/" style={{ marginRight: '1rem' }}>
          Home
        </Link>
        {token ? (
          <>
            <Link to="/dashboard" style={{ marginRight: '1rem' }}>
              Dashboard
            </Link>
            <button onClick={logout}>Logout</button>
          </>
        ) : (
          <>
            <Link to="/login" style={{ marginRight: '1rem' }}>
              Login
            </Link>
            <Link to="/register">Register</Link>
          </>
        )}
      </nav>

      <Routes>
        <Route path="/" element={<Navigate to={token ? '/dashboard' : '/login'} replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </div>
  );
}

export default App;
