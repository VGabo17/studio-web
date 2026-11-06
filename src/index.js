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
    // RESOURCE VAULT: SUBIDA DIRECTA DE .JAR Y DESCARGA NATIVA
    // ------------------------------------------------------------------------
    // 1. Listar recursos
    if (url.pathname === '/api/vault' && request.method === 'GET') {
      const resources = await KV.get("vault:resources") || "[]";
      return json({ success: true, resources: JSON.parse(resources) });
    }

    // 2. Descargar archivo .jar directo
    if (url.pathname === '/api/vault/download' && request.method === 'GET') {
      const id = url.searchParams.get("id");
      if (!id) return new Response("ID faltante", { status: 400 });

      const fileBuffer = await KV.get(`vault:file:${id}`, { type: "arrayBuffer" });
      if (!fileBuffer) return new Response("Archivo no encontrado o expirado", { status: 404 });

      const resources = JSON.parse(await KV.get("vault:resources") || "[]");
      const item = resources.find(r => r.id === id);
      const filename = item ? `${item.name.replace(/\s+/g, '_')}-v${item.version}.jar` : "plugin.jar";

      return new Response(fileBuffer, {
        headers: {
          "Content-Type": "application/java-archive",
          "Content-Disposition": `attachment; filename="${filename}"`
        }
      });
    }

    // 3. Subir archivo .jar binario (Solo Founder o Dev)
    if (url.pathname === '/api/vault/upload' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || (user.role !== 'Founder' && user.role !== 'Dev')) {
        return json({ error: "Permiso denegado. Solo Staff puede subir plugins." }, 403);
      }

      try {
        const formData = await request.formData();
        const file = formData.get("file");
        const name = formData.get("name");
        const version = formData.get("version") || "1.0.0";
        const mcVersions = formData.get("mcVersions") || "1.16 - 1.21";
        const description = formData.get("description") || "";

        if (!file || typeof file === 'string' || !name) {
          return json({ error: "Debes adjuntar un archivo .jar válido y un nombre." }, 400);
        }

        const resId = "RES-" + Math.floor(1000 + Math.random() * 9000);
        const arrayBuffer = await file.arrayBuffer();

        // Guardar el archivo binario real en KV
        await KV.put(`vault:file:${resId}`, arrayBuffer);

        // Guardar metadata en el índice
        const resources = JSON.parse(await KV.get("vault:resources") || "[]");
        const newResource = {
          id: resId,
          name,
          version,
          mcVersions,
          description,
          fileSize: `${(file.size / 1024).toFixed(1)} KB`,
          author: user.username,
          createdAt: new Date().toLocaleDateString()
        };

        resources.unshift(newResource);
        await KV.put("vault:resources", JSON.stringify(resources));

        return json({ success: true, resource: newResource });
      } catch (err) {
        return json({ error: "Fallo al procesar el archivo: " + err.message }, 500);
      }
    }

    // 4. Eliminar recurso del Vault
    if (url.pathname === '/api/vault/delete' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || (user.role !== 'Founder' && user.role !== 'Admin')) {
        return json({ error: "Sin permiso" }, 403);
      }
      const { id } = await request.json();
      await KV.delete(`vault:file:${id}`);
      const resources = JSON.parse(await KV.get("vault:resources") || "[]");
      const updated = resources.filter(r => r.id !== id);
      await KV.put("vault:resources", JSON.stringify(updated));
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // DISCORD OAUTH2
    // ------------------------------------------------------------------------
    const CLIENT_ID = env.DISCORD_CLIENT_ID || "";
    const CLIENT_SECRET = env.DISCORD_CLIENT_SECRET || "";
    const REDIRECT_URI = `${url.origin}/api/auth/discord/callback`;

    if (url.pathname === '/api/auth/discord' && request.method === 'GET') {
      if (!CLIENT_ID) return new Response("Configura DISCORD_CLIENT_ID", { status: 500 });
      return Response.redirect(`https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify%20email`, 302);
    }

    if (url.pathname === '/api/auth/discord/callback' && request.method === 'GET') {
      const code = url.searchParams.get('code');
      if (!code) return Response.redirect(`${url.origin}/login?error=no_code`, 302);

      try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
            grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI
          })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) throw new Error();

        const userRes = await fetch('https://discord.com/api/users/@me', {
          headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const dUser = await userRes.json();
        const email = dUser.email || `${dUser.id}@discord.user`;

        let userData = null;
        const existing = await KV.get(`user:${email}`);
        if (existing) {
          userData = JSON.parse(existing);
        } else {
          const userCount = await KV.get("stats:user_count");
          const role = userCount === null ? "Founder" : "User";
          userData = {
            id: crypto.randomUUID(),
            username: dUser.global_name || dUser.username,
            email,
            discord: dUser.username,
            role,
            createdAt: new Date().toLocaleDateString()
          };
          await KV.put(`user:${email}`, JSON.stringify(userData));
          await KV.put(`username:${dUser.username.toLowerCase()}`, email);
          await KV.put("stats:user_count", String((parseInt(userCount || "0", 10)) + 1));
          const usersList = JSON.parse(await KV.get("users:list") || "[]");
          usersList.push(userData);
          await KV.put("users:list", JSON.stringify(usersList));
        }

        const sessionToken = crypto.randomUUID();
        await KV.put(`session:${sessionToken}`, JSON.stringify(userData), { expirationTtl: 604800 });

        return new Response(`
          <!DOCTYPE html><html><body><script>
            localStorage.setItem('synthetix_token', '${sessionToken}');
            localStorage.setItem('synthetix_user', JSON.stringify(${JSON.stringify(userData)}));
            window.location.href = '/dashboard';
          </script></body></html>
        `, { headers: { 'Content-Type': 'text/html' } });
      } catch (e) {
        return Response.redirect(`${url.origin}/login?error=discord_failed`, 302);
      }
    }

    // AUTH REGULAR
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
          id: crypto.randomUUID(), username, email: normEmail,
          discord: discord || "", role, createdAt: new Date().toLocaleDateString()
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

    // PROJECTS
    if (url.pathname === '/api/projects' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      const all = JSON.parse(await KV.get("projects:all") || "[]");
      const isStaff = (user.role === 'Founder' || user.role === 'Dev' || user.role === 'Admin');
      const filtered = isStaff ? all : all.filter(p => p.clientEmail === user.email);
      return json({ success: true, projects: filtered });
    }

    if (url.pathname === '/api/founder/project-create' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || (user.role !== 'Founder' && user.role !== 'Dev')) return json({ error: "Denegado" }, 403);
      const { title, clientEmail, progress, downloadUrl } = await request.json();
      const all = JSON.parse(await KV.get("projects:all") || "[]");
      const newProj = {
        id: "PRJ-" + Math.floor(1000 + Math.random() * 9000),
        title, clientEmail, progress: parseInt(progress) || 0,
        downloadUrl: downloadUrl || "", author: user.username, updatedAt: new Date().toLocaleDateString()
      };
      all.unshift(newProj);
      await KV.put("projects:all", JSON.stringify(all));
      return json({ success: true });
    }

    // FOUNDER: USERS
    if (url.pathname === '/api/founder/users' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Denegado" }, 403);
      const users = await KV.get("users:list") || "[]";
      return json({ success: true, users: JSON.parse(users) });
    }

    if (url.pathname === '/api/founder/set-role' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Denegado" }, 403);
      const { email, newRole } = await request.json();
      const targetRaw = await KV.get(`user:${email}`);
      if (!targetRaw) return json({ error: "No encontrado" }, 404);
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

    // CRM COTIZACIONES
    if (url.pathname === '/api/quote' && request.method === 'POST') {
      try {
        const data = await request.json();
        const quoteId = "QT-" + Math.floor(1000 + Math.random() * 9000);
        const quoteObj = {
          id: quoteId, name: data.name || "Anónimo", discord: data.discord || "N/A",
          service: data.service || "General", details: data.details || "Sin detalles",
          status: "Pendiente", date: new Date().toLocaleDateString()
        };
        const quotes = JSON.parse(await KV.get("quotes:all") || "[]");
        quotes.unshift(quoteObj);
        await KV.put("quotes:all", JSON.stringify(quotes));
        return json({ success: true, quoteId });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    if (url.pathname === '/api/founder/quotes' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Denegado" }, 403);
      const quotes = await KV.get("quotes:all") || "[]";
      return json({ success: true, quotes: JSON.parse(quotes) });
    }

    if (url.pathname === '/api/founder/quote-status' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || user.role !== 'Founder') return json({ error: "Denegado" }, 403);
      const { id, status } = await request.json();
      const quotes = JSON.parse(await KV.get("quotes:all") || "[]");
      const idx = quotes.findIndex(q => q.id === id);
      if (idx !== -1) {
        quotes[idx].status = status;
        await KV.put("quotes:all", JSON.stringify(quotes));
      }
      return json({ success: true });
    }

    // TICKETS
    if (url.pathname === '/api/tickets' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);

      const ticketId = url.searchParams.get("id");
      if (ticketId) {
        const data = await KV.get(`ticket:${ticketId}`);
        return json({ success: true, ticket: JSON.parse(data) });
      }

      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const isStaff = (user.role === 'Founder' || user.role === 'Admin' || user.role === 'Soporte' || user.role === 'Dev');
      const filtered = isStaff ? index : index.filter(t => t.authorEmail === user.email);
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
      if (!raw) return json({ error: "No existe el ticket" }, 404);

      const ticket = JSON.parse(raw);
      if (ticket.status === 'Cerrado') {
        return json({ error: "Este ticket está cerrado y archivado." }, 400);
      }

      ticket.messages.push({ sender: user.username, role: user.role, text, time: new Date().toLocaleString() });
      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticket));
      return json({ success: true });
    }

    if (url.pathname === '/api/tickets/status' && request.method === 'POST') {
      const user = await getSessionUser();
      const isStaff = (user.role === 'Founder' || user.role === 'Admin' || user.role === 'Soporte');
      if (!user || !isStaff) return json({ error: "Sin permiso" }, 403);

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

    if (url.pathname === '/api/tickets/delete' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || (user.role !== 'Founder' && user.role !== 'Admin')) {
        return json({ error: "Acceso denegado" }, 403);
      }

      const { ticketId } = await request.json();
      await KV.delete(`ticket:${ticketId}`);

      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const updated = index.filter(t => t.id !== ticketId);
      await KV.put("tickets:index", JSON.stringify(updated));

      return json({ success: true });
    }

    return env.ASSETS.fetch(request);
  }
};
