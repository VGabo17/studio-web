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

    const cleanRoutes = ['/login', '/dashboard', '/services', '/vault', '/terms'];
    if (cleanRoutes.includes(url.pathname)) {
      return env.ASSETS.fetch(new Request(new URL(`${url.pathname}.html`, request.url), request));
    }

    async function getSessionUser() {
      let token = null;
      const auth = request.headers.get("Authorization");
      if (auth && auth.startsWith("Bearer ")) {
        token = auth.replace("Bearer ", "").trim();
      } else if (url.searchParams.get("token")) {
        token = url.searchParams.get("token");
      }
      if (!token) return null;
      const session = await KV.get(`session:${token}`);
      return session ? JSON.parse(session) : null;
    }

    // ------------------------------------------------------------------------
    // RESOURCE VAULT MULTI-FORMATO (JAR, ZIP, SCHEM, YML)
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/vault' && request.method === 'GET') {
      const resources = await KV.get("vault:resources") || "[]";
      return json({ success: true, resources: JSON.parse(resources) });
    }

    // Descarga directa con control de permisos por Rol
    if (url.pathname === '/api/vault/download' && request.method === 'GET') {
      const id = url.searchParams.get("id");
      if (!id) return new Response("ID faltante", { status: 400 });

      const resources = JSON.parse(await KV.get("vault:resources") || "[]");
      const item = resources.find(r => r.id === id);
      if (!item) return new Response("Recurso no encontrado", { status: 404 });

      // Verificación de acceso VIP / Privado
      if (item.accessTier === 'vip') {
        const user = await getSessionUser();
        const isVip = user && (user.role === 'VIP' || user.role === 'Client' || user.role === 'Dev' || user.role === 'Founder' || user.role === 'Admin');
        if (!isVip) {
          return new Response("Acceso bloqueado: Este recurso es exclusivo para usuarios con rango VIP o Clientes.", { status: 403 });
        }
      }

      const fileBuffer = await KV.get(`vault:file:${id}`, { type: "arrayBuffer" });
      if (!fileBuffer) return new Response("Archivo no encontrado en la base de datos", { status: 404 });

      const ext = item.fileExtension || "zip";
      const filename = `${item.name.replace(/[^a-zA-Z0-9_-]/g, '_')}-v${item.version}.${ext}`;
      
      let contentType = "application/octet-stream";
      if (ext === 'jar') contentType = "application/java-archive";
      if (ext === 'zip') contentType = "application/zip";
      if (ext === 'yml') contentType = "text/yaml";

      return new Response(fileBuffer, {
        headers: {
          "Content-Type": contentType,
          "Content-Disposition": `attachment; filename="${filename}"`
        }
      });
    }

    // Subida Multi-formato (Solo Dev o Founder)
    if (url.pathname === '/api/vault/upload' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || (user.role !== 'Founder' && user.role !== 'Dev' && user.role !== 'Admin')) {
        return json({ error: "Permiso denegado. Solo Staff puede subir recursos." }, 403);
      }

      try {
        const formData = await request.formData();
        const file = formData.get("file");
        const name = formData.get("name");
        const category = formData.get("category") || "Plugin"; // Plugin, Setup, Config, Mapa, Bot
        const accessTier = formData.get("accessTier") || "free"; // free, vip, premium
        const version = formData.get("version") || "1.0.0";
        const mcVersions = formData.get("mcVersions") || "1.16 - 1.21";
        const description = formData.get("description") || "";
        const price = formData.get("price") || "Gratis";

        if (!file || typeof file === 'string' || !name) {
          return json({ error: "Debes adjuntar un archivo válido y un título." }, 400);
        }

        const ext = file.name.split('.').pop().toLowerCase();
        const resId = "RES-" + Math.floor(1000 + Math.random() * 9000);
        const arrayBuffer = await file.arrayBuffer();

        // Almacenar archivo binario en KV
        await KV.put(`vault:file:${resId}`, arrayBuffer);

        // Guardar metadata
        const resources = JSON.parse(await KV.get("vault:resources") || "[]");
        const newResource = {
          id: resId,
          name,
          category,
          accessTier,
          price,
          version,
          mcVersions,
          description,
          fileExtension: ext,
          fileSize: `${(file.size / 1024).toFixed(1)} KB`,
          author: user.username,
          createdAt: new Date().toLocaleDateString()
        };

        resources.unshift(newResource);
        await KV.put("vault:resources", JSON.stringify(resources));

        return json({ success: true, resource: newResource });
      } catch (err) {
        return json({ error: "Error al procesar subida: " + err.message }, 500);
      }
    }

    if (url.pathname === '/api/vault/delete' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user || (user.role !== 'Founder' && user.role !== 'Admin')) return json({ error: "Denegado" }, 403);
      const { id } = await request.json();
      await KV.delete(`vault:file:${id}`);
      const resources = JSON.parse(await KV.get("vault:resources") || "[]");
      const updated = resources.filter(r => r.id !== id);
      await KV.put("vault:resources", JSON.stringify(updated));
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // AUTHENTICATION
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      try {
        const { username, email, password } = await request.json();
        if (!username || !email || !password) return json({ error: "Completa los campos" }, 400);

        const normEmail = email.toLowerCase().trim();
        const normUser = username.toLowerCase().trim();

        if (await KV.get(`user:${normEmail}`)) return json({ error: "Correo ya registrado" }, 400);
        if (await KV.get(`username:${normUser}`)) return json({ error: "Usuario en uso" }, 400);

        const userCount = await KV.get("stats:user_count");
        const role = userCount === null ? "Founder" : "User";

        const passwordHash = await hashPassword(password);
        const userData = {
          id: crypto.randomUUID(), username, email: normEmail,
          role, createdAt: new Date().toLocaleDateString()
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
    // PEDIDOS WEB DIRECTOS
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/orders/create' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "Inicia sesión para ordenar." }, 401);

      const { planTitle, price, details } = await request.json();
      const ticketId = "ORD-" + Math.floor(1000 + Math.random() * 9000);
      const now = new Date().toLocaleString();

      const orderTicket = {
        id: ticketId,
        title: `Pedido: ${planTitle} (${price})`,
        category: "Pedido Web",
        author: user.username,
        authorEmail: user.email,
        status: "Abierto",
        createdAt: now,
        messages: [{
          sender: "Sistema",
          role: "Synthetix",
          text: `⚡ Pedido para "${planTitle}" (${price}). Requerimientos: ${details || 'Sin especificaciones'}. Puedes coordinar aquí mismo con el staff.`,
          time: now
        }]
      };

      await KV.put(`ticket:${ticketId}`, JSON.stringify(orderTicket));
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      index.unshift({
        id: ticketId, title: orderTicket.title, category: "Pedido Web",
        author: user.username, authorEmail: user.email, status: "Abierto", createdAt: now
      });
      await KV.put("tickets:index", JSON.stringify(index));

      return json({ success: true, orderId: ticketId });
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
      if (!raw) return json({ error: "No existe" }, 404);

      const ticket = JSON.parse(raw);
      if (ticket.status === 'Cerrado') {
        return json({ error: "Este ticket está cerrado." }, 400);
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
      if (!user || (user.role !== 'Founder' && user.role !== 'Admin')) return json({ error: "Denegado" }, 403);
      const { ticketId } = await request.json();
      await KV.delete(`ticket:${ticketId}`);
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const updated = index.filter(t => t.id !== ticketId);
      await KV.put("tickets:index", JSON.stringify(updated));
      return json({ success: true });
    }

    // PROYECTOS & USUARIOS
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

    return env.ASSETS.fetch(request);
  }
};
