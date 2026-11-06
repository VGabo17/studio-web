async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256
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
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256
  );
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex === originalHashHex;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const KV = env.SYNTHETIX_KV;

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status, headers: { "Content-Type": "application/json" }
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

    // ------------------------------------------------------------------------
    // ANUNCIO GLOBAL PÚBLICO
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/announcement' && request.method === 'GET') {
      const announcement = await KV.get("global:announcement") || "{}";
      return json({ success: true, data: JSON.parse(announcement) });
    }

    // ------------------------------------------------------------------------
    // AUTH: REGISTRO / LOGIN / ME
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      try {
        const { username, email, password, discord } = await request.json();
        if (!username || !email || !password) return json({ error: "Faltan datos" }, 400);

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
          createdAt: new Date().toLocaleDateString()
        };

        await KV.put(`user:${normEmail}`, JSON.stringify({ ...userData, passwordHash }));
        await KV.put(`username:${normUser}`, normEmail);
        await KV.put("stats:user_count", String((parseInt(userCount || "0", 10)) + 1));

        const usersList = JSON.parse(await KV.get("users:list") || "[]");
        usersList.push(userData);
        await KV.put("users:list", JSON.stringify(usersList));

        const token = crypto.randomUUID();
        await KV.put(`session:${token}`, JSON.stringify(userData), { expirationTtl: 604800 });

        return json({ success: true, token, user: userData });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

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

    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "Sesión inválida" }, 401);
      return json({ success: true, user });
    }

    // ------------------------------------------------------------------------
    // COTIZACIONES: GUARDADO EN KV + DISCORD
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/quote' && request.method === 'POST') {
      try {
        const data = await request.json();
        const quoteId = "QT-" + Math.floor(1000 + Math.random() * 9000);
        const quoteObj = {
          id: quoteId,
          name: data.name || "Anónimo",
          discord: data.discord || "N/A",
          service: data.service || "General",
          details: data.details || "Sin detalles",
          status: "Pendiente",
          date: new Date().toLocaleDateString()
        };

        // Guardar en KV para el CRM del Founder
        const quotes = JSON.parse(await KV.get("quotes:all") || "[]");
        quotes.unshift(quoteObj);
        await KV.put("quotes:all", JSON.stringify(quotes));

        // Enviar a Discord si hay Webhook
        const WEBHOOK_URL = env.DISCORD_WEBHOOK || "";
        if (WEBHOOK_URL) {
          await fetch(WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: "Synthetix Studio CRM",
              embeds: [{
                title: `⚡ Nueva Cotización [${quoteId}]`,
                color: 0xa855f7,
                fields: [
                  { name: "👤 Cliente", value: quoteObj.name, inline: true },
                  { name: "💬 Discord", value: quoteObj.discord, inline: true },
                  { name: "🛠 Servicio", value: quoteObj.service, inline: true },
                  { name: "📝 Detalles", value: quoteObj.details }
                ],
                footer: { text: "Synthetix Studio" },
                timestamp: new Date().toISOString()
              }]
            })
          });
        }
        return json({ success: true, quoteId });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // ------------------------------------------------------------------------
    // FOUNDER: GESTIÓN DE COTIZACIONES (CRM)
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/founder/quotes' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Acceso denegado" }, 403);
      const quotes = await KV.get("quotes:all") || "[]";
      return json({ success: true, quotes: JSON.parse(quotes) });
    }

    if (url.pathname === '/api/founder/quote-status' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Acceso denegado" }, 403);

      const { id, status } = await request.json();
      const quotes = JSON.parse(await KV.get("quotes:all") || "[]");
      const idx = quotes.findIndex(q => q.id === id);
      if (idx !== -1) {
        quotes[idx].status = status;
        await KV.put("quotes:all", JSON.stringify(quotes));
      }
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // PROYECTOS / SOFTWARE VAULT
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/projects' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const all = JSON.parse(await KV.get("projects:all") || "[]");
      const filtered = user.role === 'Founder' ? all : all.filter(p => p.clientEmail === user.email);
      return json({ success: true, projects: filtered });
    }

    if (url.pathname === '/api/founder/project-create' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Acceso denegado" }, 403);

      const { title, clientEmail, progress, downloadUrl, notes } = await request.json();
      const all = JSON.parse(await KV.get("projects:all") || "[]");

      const newProj = {
        id: "PRJ-" + Math.floor(1000 + Math.random() * 9000),
        title,
        clientEmail,
        progress: parseInt(progress) || 0,
        downloadUrl: downloadUrl || "",
        notes: notes || "",
        updatedAt: new Date().toLocaleDateString()
      };

      all.unshift(newProj);
      await KV.put("projects:all", JSON.stringify(all));
      return json({ success: true, project: newProj });
    }

    // ------------------------------------------------------------------------
    // FOUNDER: CAMBIO DE ANUNCIO GLOBAL
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/founder/set-announcement' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Acceso denegado" }, 403);

      const { text, active } = await request.json();
      await KV.put("global:announcement", JSON.stringify({ text, active }));
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // FOUNDER: USUARIOS & ROLES
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/founder/users' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Acceso denegado" }, 403);
      const users = await KV.get("users:list") || "[]";
      return json({ success: true, users: JSON.parse(users) });
    }

    if (url.pathname === '/api/founder/set-role' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Acceso denegado" }, 403);

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
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // TICKETS (CHAT REAL)
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/tickets' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const ticketId = url.searchParams.get("id");
      if (ticketId) {
        const data = await KV.get(`ticket:${ticketId}`);
        return json({ success: true, ticket: JSON.parse(data) });
      }

      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const filtered = user.role === 'Founder' ? index : index.filter(t => t.authorEmail === user.email);
      return json({ success: true, tickets: filtered });
    }

    if (url.pathname === '/api/tickets' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const { title, category, message } = await request.json();
      const ticketId = "TK-" + Math.floor(1000 + Math.random() * 9000);
      const now = new Date().toLocaleString();

      const ticketObject = {
        id: ticketId, title, category,
        author: user.username, authorEmail: user.email,
        status: "Abierto", createdAt: now,
        messages: [{ sender: user.username, role: user.role, text: message, time: now }]
      };

      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticketObject));
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      index.unshift({ id: ticketId, title, category, author: user.username, authorEmail: user.email, status: "Abierto", createdAt: now });
      await KV.put("tickets:index", JSON.stringify(index));

      return json({ success: true, ticket: ticketObject });
    }

    if (url.pathname === '/api/tickets/reply' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const { ticketId, text } = await request.json();
      const raw = await KV.get(`ticket:${ticketId}`);
      if (!raw) return json({ error: "No existe" }, 404);

      const ticket = JSON.parse(raw);
      ticket.messages.push({ sender: user.username, role: user.role, text, time: new Date().toLocaleString() });
      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticket));
      return json({ success: true });
    }

    if (url.pathname === '/api/tickets/status' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Sin permiso" }, 403);

      const { ticketId, newStatus } = await request.json();
      const raw = await KV.get(`ticket:${ticketId}`);
      if (!raw) return json({ error: "No existe" }, 404);

      const ticket = JSON.parse(raw);
      ticket.status = newStatus;
      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticket));

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
