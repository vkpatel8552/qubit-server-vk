// ═══ ADD THIS NEW ENDPOINT after app.put('/api/auth/profile', ...) ═══

app.post('/api/auth/password', authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Both old and new password required' });
  }
  const users = await readJson(DB.usersFile);
  const user = users[req.user.email];
  if (!user || user.passwordHash !== hashPassword(oldPassword, req.user.email)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  if (!passwordValid(newPassword)) {
    return res.status(400).json({ error: 'New password must be 8+ chars with uppercase, lowercase, number, and symbol' });
  }
  if (oldPassword === newPassword) {
    return res.status(400).json({ error: 'New password must be different from current password' });
  }
  user.passwordHash = hashPassword(newPassword, req.user.email);
  await writeJson(DB.usersFile, users);
  // Invalidate all existing sessions except current one (security best practice)
  const sessions = await readJson(DB.sessionsFile);
  Object.keys(sessions).forEach(t => {
    if (sessions[t].email === req.user.email && t !== req.token) delete sessions[t];
  });
  await writeJson(DB.sessionsFile, sessions);
  res.json({ ok: true, message: 'Password updated successfully' });
});