async function loginAdmin(password) {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  });
  if (res.ok) {
    const data = await res.json();
    localStorage.setItem('adminToken', data.token);
    adminUnlocked = true;
    // ...
  } else {
    // erreur
  }
}