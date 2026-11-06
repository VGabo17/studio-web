async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password, storedHash) {
  const [saltHex, originalHashHex] = storedHash.split(':');
  if (!saltHex || !originalHashHex) return false;
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex === originalHashHex;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const KV = env.SYNTHETIX_KV;

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" }
    });

    // Rutas limpias
    const cleanRoutes = ['/login', '/dashboard', '/admin'];
    if (cleanRoutes.includes(url.pathname)) {
      return env.ASSETS.fetch(new Request(new URL(`${url.pathname}.html`, request.url), request));
    }

    // Helper: Validar sesión
    async function getSessionUser() {
      const auth = request.headers.get("Authorization");
      if (!auth || !auth.startsWith("Bearer ")) return null;
      const token = auth.replace("Bearer ", "").trim();
      const session = await KV.get(`session:${token}`);
      return session ? JSON.parse(session) : null;
    }

    // ------------------------------------------------------------------------
    // AUTH: REGISTRO
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      try {
        const { username, email, password, discord } = await request.json();
        if (!username || !email || !password) return json({ error: "Faltan campos" }, 400);

        const normEmail = email.toLowerCase().trim();
        const normUser = username.toLowerCase().trim();

        if (await KV.get(`user:${normEmail}`)) return json({ error: "Correo ya registrado" }, 400);
        if (await KV.get(`username:${normUser}`)) return json({ error: "Usuario en uso" }, 400);

        const userCount = await KV.get("stats:user_count");
        const role = userCount === null ? "Founder" : "User";

        const passwordHash = await hashPassword(password);
        const userData = {
          id: crypto.randomUUID(),
          username,
          email: normEmail,
          discord: discord || "",
          role,
          createdAt: new Date().toISOString()
        };

        await KV.put(`user:${normEmail}`, JSON.stringify({ ...userData, passwordHash }));
        await KV.put(`username:${normUser}`, normEmail);
        await KV.put("stats:user_count", String((parseInt(userCount || "0", 10)) + 1));

        // Agregar a la lista de usuarios para el Founder
        const usersListRaw = await KV.get("users:list") || "[]";
        const usersList = JSON.parse(usersListRaw);
        usersList.push({ id: userData.id, username, email: normEmail, role, discord: userData.discord });
        await KV.put("users:list", JSON.stringify(usersList));

        const token = crypto.randomUUID();
        await KV.put(`session:${token}`, JSON.stringify(userData), { expirationTtl: 604800 });

        return json({ success: true, token, user: userData });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // ------------------------------------------------------------------------
    // AUTH: LOGIN
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      try {
        const { email, password } = await request.json();
        const normEmail = email.toLowerCase().trim();

        const raw = await KV.get(`user:${normEmail}`);
        if (!raw) return json({ error: "Credenciales inválidas" }, 401);

        const user = JSON.parse(raw);
        if (!(await verifyPassword(password, user.passwordHash))) {
          return json({ error: "Credenciales inválidas" }, 401);
        }

        const token = crypto.randomUUID();
        const { passwordHash, ...safeUser } = user;
        await KV.put(`session:${token}`, JSON.stringify(safeUser), { expirationTtl: 604800 });

        return json({ success: true, token, user: safeUser });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // ------------------------------------------------------------------------
    // AUTH: ME
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "Sesión inválida" }, 401);
      return json({ success: true, user });
    }

    // ------------------------------------------------------------------------
    // FOUNDER: GESTIÓN DE USUARIOS
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/founder/users' && request.method === 'GET') {
      const currentUser = await getSessionUser();
      if (!currentUser || (currentUser.role !== 'Founder' && currentUser.role !== 'Admin')) {
        return json({ error: "Acceso denegado" }, 403);
      }

      const users = await KV.get("users:list") || "[]";
      return json({ success: true, users: JSON.parse(users) });
    }

    // FOUNDER: CAMBIAR ROL
    if (url.pathname === '/api/founder/set-role' && request.method === 'POST') {
      const currentUser = await getSessionUser();
      if (!currentUser || currentUser.role !== 'Founder') {
        return json({ error: "Solo el Founder puede cambiar roles" }, 403);
      }

      const { email, newRole } = await request.json();
      const validRoles = ['User', 'Client', 'Soporte', 'Dev', 'Admin', 'Founder'];
      if (!validRoles.includes(newRole)) return json({ error: "Rol no válido" }, 400);

      const targetRaw = await KV.get(`user:${email}`);
      if (!targetRaw) return json({ error: "Usuario no encontrado" }, 404);

      const targetUser = JSON.parse(targetRaw);
      targetUser.role = newRole;
      await KV.put(`user:${email}`, JSON.stringify(targetUser));

      // Actualizar en users:list
      const usersList = JSON.parse(await KV.get("users:list") || "[]");
      const idx = usersList.findIndex(u => u.email === email);
      if (idx !== -1) {
        usersList[idx].role = newRole;
        await KV.put("users:list", JSON.stringify(usersList));
      }

      return json({ success: true, message: `Rol actualizado a ${newRole}` });
    }

    // ------------------------------------------------------------------------
    // TICKETS: CREAR Y LISTAR
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/tickets' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const allTickets = JSON.parse(await KV.get("tickets:all") || "[]");
      // Founder y Soporte ven todos los tickets; los usuarios solo los suyos
      const filtered = (user.role === 'Founder' || user.role === 'Admin' || user.role === 'Soporte') 
        ? allTickets 
        : allTickets.filter(t => t.authorEmail === user.email);

      return json({ success: true, tickets: filtered });
    }

    if (url.pathname === '/api/tickets' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const { title, category, message } = await request.json();
      if (!title || !message) return json({ error: "Completa los campos" }, 400);

      const allTickets = JSON.parse(await KV.get("tickets:all") || "[]");
      const ticketId = "TK-" + Math.floor(1000 + Math.random() * 9000);

      const newTicket = {
        id: ticketId,
        title,
        category,
        message,
        author: user.username,
        authorEmail: user.email,
        status: "Abierto",
        createdAt: new Date().toLocaleDateString()
      };

      allTickets.unshift(newTicket);
      await KV.put("tickets:all", JSON.stringify(allTickets));

      return json({ success: true, ticket: newTicket });
    }

    // Fallback a archivos estáticos
    return env.ASSETS.fetch(request);
  }
};
