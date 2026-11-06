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

    const cleanRoutes = ['/login', '/dashboard', '/admin'];
    if (cleanRoutes.includes(url.pathname)) {
      return env.ASSETS.fetch(new Request(new URL(`${url.pathname}.html`, request.url), request));
    }

    async function getSessionUser() {
      const auth = request.headers.get("Authorization");
      if (!auth || !auth.startsWith("Bearer ")) return null;
      const token = auth.replace("Bearer ", "").trim();
      const session = await KV.get(`session:${token}`);
      return session ? JSON.parse(session) : null;
    }

    // REGISTRO
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

        const usersList = JSON.parse(await KV.get("users:list") || "[]");
        usersList.push({ id: userData.id, username, email: normEmail, role, discord: userData.discord });
        await KV.put("users:list", JSON.stringify(usersList));

        const token = crypto.randomUUID();
        await KV.put(`session:${token}`, JSON.stringify(userData), { expirationTtl: 604800 });

        return json({ success: true, token, user: userData });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // LOGIN
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

    // ME
    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "Sesión inválida" }, 401);
      return json({ success: true, user });
    }

    // FOUNDER: GESTIÓN DE USUARIOS
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
      const targetRaw = await KV.get(`user:${email}`);
      if (!targetRaw) return json({ error: "Usuario no encontrado" }, 404);

      const targetUser = JSON.parse(targetRaw);
      targetUser.role = newRole;
      await KV.put(`user:${email}`, JSON.stringify(targetUser));

      const usersList = JSON.parse(await KV.get("users:list") || "[]");
      const idx = usersList.findIndex(u => u.email === email);
      if (idx !== -1) {
        usersList[idx].role = newRole;
        await KV.put("users:list", JSON.stringify(usersList));
      }
      return json({ success: true, message: `Rol actualizado a ${newRole}` });
    }

    // ------------------------------------------------------------------------
    // SISTEMA REAL DE TICKETS (CON CHAT Y MENSAJES EN VIVO)
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/tickets' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const ticketId = url.searchParams.get("id");
      if (ticketId) {
        const ticketData = await KV.get(`ticket:${ticketId}`);
        if (!ticketData) return json({ error: "Ticket no encontrado" }, 404);
        return json({ success: true, ticket: JSON.parse(ticketData) });
      }

      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const isStaff = (user.role === 'Founder' || user.role === 'Admin' || user.role === 'Soporte');
      const filtered = isStaff ? index : index.filter(t => t.authorEmail === user.email);

      return json({ success: true, tickets: filtered });
    }

    // CREAR TICKET
    if (url.pathname === '/api/tickets' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const { title, category, message } = await request.json();
      if (!title || !message) return json({ error: "Completa todos los campos" }, 400);

      const ticketId = "TK-" + Math.floor(1000 + Math.random() * 9000);
      const now = new Date().toLocaleString();

      const ticketObject = {
        id: ticketId,
        title,
        category,
        author: user.username,
        authorEmail: user.email,
        status: "Abierto",
        createdAt: now,
        messages: [
          {
            sender: user.username,
            role: user.role,
            text: message,
            time: now
          }
        ]
      };

      // Guardar ticket individual con sus mensajes
      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticketObject));

      // Guardar en el índice global
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      index.unshift({
        id: ticketId,
        title,
        category,
        author: user.username,
        authorEmail: user.email,
        status: "Abierto",
        createdAt: now
      });
      await KV.put("tickets:index", JSON.stringify(index));

      return json({ success: true, ticket: ticketObject });
    }

    // RESPONDER A UN TICKET
    if (url.pathname === '/api/tickets/reply' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const { ticketId, text } = await request.json();
      if (!ticketId || !text) return json({ error: "Mensaje vacío" }, 400);

      const raw = await KV.get(`ticket:${ticketId}`);
      if (!raw) return json({ error: "Ticket no existe" }, 404);

      const ticket = JSON.parse(raw);
      ticket.messages.push({
        sender: user.username,
        role: user.role,
        text,
        time: new Date().toLocaleString()
      });

      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticket));
      return json({ success: true, ticket });
    }

    // CAMBIAR ESTADO DE UN TICKET
    if (url.pathname === '/api/tickets/status' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || (user.role !== 'Founder' && user.role !== 'Admin' && user.role !== 'Soporte')) {
        return json({ error: "Sin permisos" }, 403);
      }

      const { ticketId, newStatus } = await request.json();
      const raw = await KV.get(`ticket:${ticketId}`);
      if (!raw) return json({ error: "Ticket no encontrado" }, 404);

      const ticket = JSON.parse(raw);
      ticket.status = newStatus;
      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticket));

      // Actualizar índice
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const idx = index.findIndex(t => t.id === ticketId);
      if (idx !== -1) {
        index[idx].status = newStatus;
        await KV.put("tickets:index", JSON.stringify(index));
      }

      return json({ success: true });
    }

    return env.ASSETS.fetch(request);
  }
};
