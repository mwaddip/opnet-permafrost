import { useState, useEffect } from 'react';
import { listUsers, addUser, removeUser, updateUserRole, listInvites, createInvite, deleteInvite, getAuthMe } from '../lib/api';

interface User { address: string; role: string; label: string }
interface Invite { code: string; role: string; usesLeft: number; expiresAt: number }

export function UserManager() {
  const [users, setUsers] = useState<User[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [myAddress, setMyAddress] = useState('');
  const [error, setError] = useState('');

  // Add user form
  const [newAddress, setNewAddress] = useState('');
  const [newRole, setNewRole] = useState<'admin' | 'user'>('user');
  const [newLabel, setNewLabel] = useState('');

  // Create invite form
  const [inviteMaxUses, setInviteMaxUses] = useState(3);
  const [inviteExpiryHours, setInviteExpiryHours] = useState(24);

  useEffect(() => {
    listUsers().then(r => setUsers(r.users)).catch(() => {});
    listInvites().then(r => setInvites(r.invites)).catch(() => {});
    getAuthMe().then(r => { if (r.address) setMyAddress(r.address); }).catch(() => {});
  }, []);

  const handleAddUser = async () => {
    if (!newAddress.trim() || !newLabel.trim()) return;
    try {
      await addUser(newAddress.trim(), newRole, newLabel.trim());
      setUsers(await listUsers().then(r => r.users));
      setNewAddress(''); setNewLabel(''); setError('');
    } catch (e) { setError((e as Error).message); }
  };

  const handleRemove = async (address: string) => {
    try {
      await removeUser(address);
      setUsers(prev => prev.filter(u => u.address !== address));
    } catch (e) { setError((e as Error).message); }
  };

  const handleRoleChange = async (address: string, role: string) => {
    try {
      await updateUserRole(address, role);
      setUsers(prev => prev.map(u => u.address === address ? { ...u, role } : u));
    } catch (e) { setError((e as Error).message); }
  };

  const handleCreateInvite = async () => {
    try {
      const expiresAt = Date.now() + inviteExpiryHours * 60 * 60 * 1000;
      await createInvite(inviteMaxUses, expiresAt);
      setInvites(await listInvites().then(r => r.invites));
    } catch (e) { setError((e as Error).message); }
  };

  const handleDeleteInvite = async (code: string) => {
    try {
      await deleteInvite(code);
      setInvites(prev => prev.filter(i => i.code !== code));
    } catch (e) { setError((e as Error).message); }
  };

  return (
    <>
      {error && <div className="warning" style={{ marginBottom: 12 }}>{error}</div>}

      {/* Users */}
      <div className="card">
        <h2>Users</h2>
        {users.length === 0 && <p style={{ color: 'var(--white-dim)', fontSize: 13 }}>No users registered.</p>}
        {users.map(u => (
          <div key={u.address} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--gray-dark)' }}>
            <div>
              <strong style={{ fontSize: 14 }}>{u.label}</strong>
              <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--white-dim)', marginTop: 2 }}>{u.address.slice(0, 18)}...</div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {u.address === myAddress ? (
                <span style={{ fontSize: 12, color: 'var(--white-dim)' }}>you</span>
              ) : (
                <>
                  <select value={u.role} onChange={e => handleRoleChange(u.address, e.target.value)} style={{ fontSize: 12, padding: '4px 8px' }}>
                    <option value="admin">Admin</option>
                    <option value="user">User</option>
                  </select>
                  <button className="btn btn-secondary" style={{ fontSize: 12, padding: '4px 10px', color: 'var(--red)' }} onClick={() => handleRemove(u.address)}>
                    Remove
                  </button>
                </>
              )}
            </div>
          </div>
        ))}

        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--gray-dark)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Add User</h3>
          <div className="form-row">
            <label>
              Wallet Address (0x...)
              <input value={newAddress} onChange={e => setNewAddress(e.target.value)} placeholder="0x..." style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </label>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <div className="form-row" style={{ flex: 1 }}>
              <label>
                Label
                <input value={newLabel} onChange={e => setNewLabel(e.target.value)} placeholder="Name" />
              </label>
            </div>
            <div className="form-row" style={{ width: 100 }}>
              <label>
                Role
                <select value={newRole} onChange={e => setNewRole(e.target.value as 'admin' | 'user')}>
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </label>
            </div>
          </div>
          <button className="btn btn-primary" onClick={handleAddUser} disabled={!newAddress.trim() || !newLabel.trim()}>Add User</button>
        </div>
      </div>

      {/* Invites */}
      <div className="card">
        <h2>Invite Codes</h2>
        {invites.length === 0 && <p style={{ color: 'var(--white-dim)', fontSize: 13 }}>No active invites.</p>}
        {invites.map(inv => (
          <div key={inv.code} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--gray-dark)' }}>
            <div>
              <strong style={{ fontFamily: 'monospace', fontSize: 16, letterSpacing: '0.1em' }}>{inv.code}</strong>
              <div style={{ fontSize: 12, color: 'var(--white-dim)', marginTop: 2 }}>
                {inv.usesLeft} uses left · expires {new Date(inv.expiresAt).toLocaleDateString()}
              </div>
            </div>
            <button className="btn btn-secondary" style={{ fontSize: 12, padding: '4px 10px', color: 'var(--red)' }} onClick={() => handleDeleteInvite(inv.code)}>
              Revoke
            </button>
          </div>
        ))}

        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--gray-dark)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Generate Invite</h3>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <div className="form-row" style={{ flex: 1 }}>
              <label>
                Max Uses
                <input type="number" min={1} max={100} value={inviteMaxUses} onChange={e => setInviteMaxUses(Number(e.target.value))} />
              </label>
            </div>
            <div className="form-row" style={{ flex: 1 }}>
              <label>
                Expires In (hours)
                <input type="number" min={1} max={720} value={inviteExpiryHours} onChange={e => setInviteExpiryHours(Number(e.target.value))} />
              </label>
            </div>
          </div>
          <button className="btn btn-primary" onClick={handleCreateInvite}>Generate Code</button>
        </div>
      </div>
    </>
  );
}
