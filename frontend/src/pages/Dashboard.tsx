import React, { useEffect, useState } from 'react';
import api from '../api';

interface User {
  username: string;
  linkedin_id?: string | null;
}

function Dashboard() {
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState('');

  const fetchUser = async () => {
    try {
      const res = await api.get<User>('/user/me');
      setUser(res.data);
    } catch (err: any) {
      setError('Failed to load user data');
    }
  };

  useEffect(() => {
    fetchUser();
  }, []);

  const linkLinkedIn = async () => {
    try {
      const { data } = await api.get<{ url: string }>('/linkedin/url');
      window.location.href = data.url;
    } catch {
      alert('Failed to start LinkedIn linking');
    }
  };

  if (error) return <p style={{ color: 'red' }}>{error}</p>;
  if (!user) return <p>Loading...</p>;

  return (
    <div>
      <h2>Dashboard</h2>
      <p>Welcome, {user.username}</p>
      {user.linkedin_id ? (
        <p>Linked LinkedIn ID: {user.linkedin_id}</p>
      ) : (
        <button onClick={linkLinkedIn}>Link LinkedIn Account</button>
      )}
    </div>
  );
}

export default Dashboard;
