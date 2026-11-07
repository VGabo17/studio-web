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
    const R2 = env.SYNTHETIX_BUCKET;

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
    // DRM ANTI-LEAK: CREAR, VERIFICAR, LISTAR, TOGGLE Y BORRAR
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/license/verify' && request.method === 'GET') {
      const key = url.searchParams.get("key");
      const clientIp = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      if (!key) return json({ valid: false, error: "Clave no provista" }, 400);

      const rawLic = await KV.get(`license:${key}`);
      if (!rawLic) return json({ valid: false, error: "Licencia no válida" }, 403);

      const lic = JSON.parse(rawLic);
      if (lic.status === 'Revocada') {
        return json({ valid: false, error: "Licencia revocada por Synthetix Studio." }, 403);
      }

      if (!lic.ips.includes(clientIp)) {
        lic.ips.push(clientIp);
        await KV.put(`license:${key}`, JSON.stringify(lic));
      }

      return json({ valid: true, plugin: lic.resourceName, client: lic.clientEmail, status: "Activa" });
    }

    if (url.pathname === '/api/licenses' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      const isFounder = (user.role || '').toLowerCase() === 'founder';
      const all = JSON.parse(await KV.get("licenses:all") || "[]");
      return json({ success: true, licenses: isFounder ? all : all.filter(l => l.clientEmail === user.email) });
    }

    // CREACIÓN DE LICENCIAS CORREGIDA (Insensible a mayúsculas)
    if (url.pathname === '/api/founder/licenses/create' && request.method === 'POST') {
      const user = await getSessionUser();
      const isFounder = user && ((user.role || '').toLowerCase() === 'founder');
      if (!isFounder) return json({ error: "Denegado: Se requiere rol Founder." }, 403);

      const { clientEmail, resourceName } = await request.json();
      if (!clientEmail || !resourceName) return json({ error: "Debes ingresar correo y plugin." }, 400);

      const randPart = () => Math.random().toString(36).substring(2, 6).toUpperCase();
      const licenseKey = `SYNTH-${randPart()}-${randPart()}`;

      const licObject = {
        key: licenseKey,
        clientEmail: clientEmail.toLowerCase().trim(),
        resourceName: resourceName.trim(),
        status: "Activa",
        ips: [],
        createdAt: new Date().toLocaleDateString()
      };

      await KV.put(`license:${licenseKey}`, JSON.stringify(licObject));
      const all = JSON.parse(await KV.get("licenses:all") || "[]");
      all.unshift(licObject);
      await KV.put("licenses:all", JSON.stringify(all));

      return json({ success: true, license: licObject });
    }

    if (url.pathname === '/api/founder/licenses/toggle' && request.method === 'POST') {
      const user = await getSessionUser();
      const isFounder = user && ((user.role || '').toLowerCase() === 'founder');
      if (!isFounder) return json({ error: "Denegado" }, 403);

      const { key } = await request.json();
      const raw = await KV.get(`license:${key}`);
      if (!raw) return json({ error: "No existe" }, 404);

      const lic = JSON.parse(raw);
      lic.status = lic.status === 'Activa' ? 'Revocada' : 'Activa';
      await KV.put(`license:${key}`, JSON.stringify(lic));

      const all = JSON.parse(await KV.get("licenses:all") || "[]");
      const idx = all.findIndex(l => l.key === key);
      if (idx !== -1) {
        all[idx].status = lic.status;
        await KV.put("licenses:all", JSON.stringify(all));
      }
      return json({ success: true, status: lic.status });
    }

    if (url.pathname === '/api/founder/licenses/delete' && request.method === 'POST') {
      const user = await getSessionUser();
      const isFounder = user && ((user.role || '').toLowerCase() === 'founder');
      if (!isFounder) return json({ error: "Denegado" }, 403);

      const { key } = await request.json();
      await KV.delete(`license:${key}`);
      const all = JSON.parse(await KV.get("licenses:all") || "[]");
      await KV.put("licenses:all", JSON.stringify(all.filter(l => l.key !== key)));
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // RESOURCE VAULT
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/vault' && request.method === 'GET') {
      const resources = await KV.get("vault:resources") || "[]";
      return json({ success: true, resources: JSON.parse(resources) });
    }

    if (url.pathname === '/api/vault/download' && request.method === 'GET') {
      const id = url.searchParams.get("id");
      if (!id) return new Response("ID requerido", { status: 400 });
      const resources = JSON.parse(await KV.get("vault:resources") || "[]");
      const item = resources.find(r => r.id === id);
      if (!item) return new Response("No encontrado", { status: 404 });

      if (item.accessTier === 'vip') {
        const user = await getSessionUser();
        const isVip = user && (user.role === 'VIP' || user.role === 'Client' || user.role === 'Dev' || (user.role || '').toLowerCase() === 'founder' || user.role === 'Admin');
        if (!isVip) return new Response("Acceso exclusivo VIP.", { status: 403 });
      }

      const ext = item.fileExtension || "zip";
      const filename = `${item.name.replace(/[^a-zA-Z0-9_-]/g, '_')}-v${item.version}.${ext}`;
      let contentType = ext === 'jar' ? "application/java-archive" : (ext === 'zip' ? "application/zip" : "application/octet-stream");

      if (R2) {
        const r2Object = await R2.get(`files/${id}`);
        if (r2Object) return new Response(r2Object.body, { headers: { "Content-Type": contentType, "Content-Disposition": `attachment; filename="${filename}"` } });
      }
      const kvBuffer = await KV.get(`vault:file:${id}`, { type: "arrayBuffer" });
      if (kvBuffer) return new Response(kvBuffer, { headers: { "Content-Type": contentType, "Content-Disposition": `attachment; filename="${filename}"` } });
      return new Response("Archivo no encontrado", { status: 404 });
    }

    if (url.pathname === '/api/vault/upload' && request.method === 'POST') {
      const user = await getSessionUser();
      const isStaff = user && (user.role === 'Admin' || user.role === 'Dev' || (user.role || '').toLowerCase() === 'founder');
      if (!isStaff) return json({ error: "Denegado" }, 403);

      try {
        const formData = await request.formData();
        const file = formData.get("file");
        const name = formData.get("name");
        const category = formData.get("category") || "Plugin";
        const accessTier = formData.get("accessTier") || "free";
        const version = formData.get("version") || "1.0.0";
        const mcVersions = formData.get("mcVersions") || "1.16 - 1.21";
        const description = formData.get("description") || "";

        if (!file || typeof file === 'string' || !name) return json({ error: "Faltan datos" }, 400);

        const ext = file.name.split('.').pop().toLowerCase();
        const resId = "RES-" + Math.floor(1000 + Math.random() * 9000);
        const arrayBuffer = await file.arrayBuffer();

        if (R2) await R2.put(`files/${resId}`, arrayBuffer);
        else await KV.put(`vault:file:${resId}`, arrayBuffer);

        const resources = JSON.parse(await KV.get("vault:resources") || "[]");
        const sizeKb = file.size / 1024;
        const formattedSize = sizeKb > 1024 ? `${(sizeKb / 1024).toFixed(1)} MB` : `${sizeKb.toFixed(1)} KB`;
        const newResource = { id: resId, name, category, accessTier, version, mcVersions, description, fileExtension: ext, fileSize: formattedSize, author: user.username, createdAt: new Date().toLocaleDateString() };

        resources.unshift(newResource);
        await KV.put("vault:resources", JSON.stringify(resources));
        return json({ success: true, resource: newResource });
      } catch (err) { return json({ error: err.message }, 500); }
    }

    if (url.pathname === '/api/vault/delete' && request.method === 'POST') {
      const user = await getSessionUser();
      const isStaff = user && (user.role === 'Admin' || (user.role || '').toLowerCase() === 'founder');
      if (!isStaff) return json({ error: "Denegado" }, 403);
      const { id } = await request.json();
      if (R2) await R2.delete(`files/${id}`);
      await KV.delete(`vault:file:${id}`);
      const resources = JSON.parse(await KV.get("vault:resources") || "[]");
      await KV.put("vault:resources", JSON.stringify(resources.filter(r => r.id !== id)));
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // PERFIL Y SEGURIDAD
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/profile/change-password' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      const { currentPassword, newPassword } = await request.json();
      const raw = await KV.get(`user:${user.email}`);
      const dbUser = JSON.parse(raw);
      if (!(await verifyPassword(currentPassword, dbUser.passwordHash))) return json({ error: "Contraseña incorrecta" }, 400);
      dbUser.passwordHash = await hashPassword(newPassword);
      await KV.put(`user:${user.email}`, JSON.stringify(dbUser));
      return json({ success: true, message: "¡Contraseña actualizada!" });
    }

    if (url.pathname === '/api/profile/update' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      const { mcNick } = await request.json();
      const raw = await KV.get(`user:${user.email}`);
      const dbUser = JSON.parse(raw);
      dbUser.mcNick = (mcNick || "").trim();
      await KV.put(`user:${user.email}`, JSON.stringify(dbUser));
      const auth = request.headers.get("Authorization");
      const token = auth.replace("Bearer ", "").trim();
      const { passwordHash, ...safeUser } = dbUser;
      await KV.put(`session:${token}`, JSON.stringify(safeUser), { expirationTtl: 604800 });
      return json({ success: true, user: safeUser });
    }

    // ------------------------------------------------------------------------
    // TICKETS CON IMÁGENES
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/tickets/attachment' && request.method === 'GET') {
      const fileId = url.searchParams.get("id");
      if (!fileId) return new Response("Falta archivo", { status: 400 });
      if (R2) {
        const obj = await R2.get(`attachments/${fileId}`);
        if (obj) return new Response(obj.body, { headers: { "Content-Type": obj.httpMetadata?.contentType || "image/jpeg" } });
      }
      const kvBuf = await KV.get(`attachment:${fileId}`, { type: "arrayBuffer" });
      if (kvBuf) return new Response(kvBuf, { headers: { "Content-Type": "image/jpeg" } });
      return new Response("No encontrado", { status: 404 });
    }

    if (url.pathname === '/api/tickets' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      const ticketId = url.searchParams.get("id");
      if (ticketId) {
        const data = await KV.get(`ticket:${ticketId}`);
        return json({ success: true, ticket: JSON.parse(data) });
      }
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const isStaff = (user.role === 'Admin' || user.role === 'Soporte' || user.role === 'Dev' || (user.role || '').toLowerCase() === 'founder');
      return json({ success: true, tickets: isStaff ? index : index.filter(t => t.authorEmail === user.email) });
    }

    if (url.pathname === '/api/tickets' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      const { title, category, message } = await request.json();
      const ticketId = "TK-" + Math.floor(1000 + Math.random() * 9000);
      const now = new Date().toLocaleString();
      const ticketObject = { id: ticketId, title, category, author: user.username, authorEmail: user.email, status: "Abierto", createdAt: now, messages: [{ sender: user.username, role: user.role, text: message, time: now }] };
      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticketObject));
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      index.unshift({ id: ticketId, title, category, author: user.username, authorEmail: user.email, status: "Abierto", createdAt: now });
      await KV.put("tickets:index", JSON.stringify(index));
      return json({ success: true, ticket: ticketObject });
    }

    if (url.pathname === '/api/tickets/reply' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      try {
        const formData = await request.formData();
        const ticketId = formData.get("ticketId");
        const text = formData.get("text") || "";
        const imageFile = formData.get("image");
        const raw = await KV.get(`ticket:${ticketId}`);
        const ticket = JSON.parse(raw);
        if (ticket.status === 'Cerrado') return json({ error: "Ticket cerrado." }, 400);

        let attachmentUrl = null;
        if (imageFile && typeof imageFile !== 'string' && imageFile.size > 0) {
          const ext = imageFile.name.split('.').pop().toLowerCase();
          const imgId = `${ticketId}_${crypto.randomUUID()}.${ext}`;
          const arrayBuffer = await imageFile.arrayBuffer();
          if (R2) await R2.put(`attachments/${imgId}`, arrayBuffer, { httpMetadata: { contentType: imageFile.type } });
          else await KV.put(`attachment:${imgId}`, arrayBuffer);
          attachmentUrl = `/api/tickets/attachment?id=${imgId}`;
        }

        const msgObj = { sender: user.username, role: user.role, text: text.trim(), attachmentUrl, time: new Date().toLocaleString() };
        ticket.messages.push(msgObj);
        await KV.put(`ticket:${ticketId}`, JSON.stringify(ticket));
        return json({ success: true, message: msgObj });
      } catch (err) { return json({ error: err.message }, 500); }
    }

    if (url.pathname === '/api/tickets/status' && request.method === 'POST') {
      const user = await getSessionUser();
      const isStaff = user && (user.role === 'Admin' || user.role === 'Soporte' || (user.role || '').toLowerCase() === 'founder');
      if (!isStaff) return json({ error: "Sin permiso" }, 403);

      const { ticketId, newStatus } = await request.json();
      const raw = await KV.get(`ticket:${ticketId}`);
      const ticket = JSON.parse(raw);
      ticket.status = newStatus;
      await KV.put(`ticket:${ticketId}`, JSON.stringify(ticket));

      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      const idx = index.findIndex(t => t.id === ticketId);
      if (idx !== -1) { index[idx].status = newStatus; await KV.put("tickets:index", JSON.stringify(index)); }
      return json({ success: true });
    }

    if (url.pathname === '/api/tickets/delete' && request.method === 'POST') {
      const user = await getSessionUser();
      const isStaff = user && (user.role === 'Admin' || (user.role || '').toLowerCase() === 'founder');
      if (!isStaff) return json({ error: "Denegado" }, 403);
      const { ticketId } = await request.json();
      await KV.delete(`ticket:${ticketId}`);
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      await KV.put("tickets:index", JSON.stringify(index.filter(t => t.id !== ticketId)));
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // PEDIDOS WEB Y PROYECTOS
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/orders/create' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "Inicia sesión" }, 401);
      const { planTitle, price, details } = await request.json();
      const ticketId = "ORD-" + Math.floor(1000 + Math.random() * 9000);
      const now = new Date().toLocaleString();

      const orderTicket = {
        id: ticketId, title: `Pedido: ${planTitle} (${price})`, category: "Pedido Web",
        author: user.username, authorEmail: user.email, status: "Abierto", createdAt: now,
        messages: [{ sender: "Sistema", role: "Synthetix", text: `⚡ Pedido para "${planTitle}" (${price}). Notas: ${details || 'Sin notas'}.`, time: now }]
      };

      await KV.put(`ticket:${ticketId}`, JSON.stringify(orderTicket));
      const index = JSON.parse(await KV.get("tickets:index") || "[]");
      index.unshift({ id: ticketId, title: orderTicket.title, category: "Pedido Web", author: user.username, authorEmail: user.email, status: "Abierto", createdAt: now });
      await KV.put("tickets:index", JSON.stringify(index));
      return json({ success: true, orderId: ticketId });
    }

    if (url.pathname === '/api/projects' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "No autorizado" }, 401);
      const all = JSON.parse(await KV.get("projects:all") || "[]");
      const isStaff = (user.role === 'Dev' || user.role === 'Admin' || (user.role || '').toLowerCase() === 'founder');
      return json({ success: true, projects: isStaff ? all : all.filter(p => p.clientEmail === user.email) });
    }

    if (url.pathname === '/api/founder/project-create' && request.method === 'POST') {
      const user = await getSessionUser();
      const isFounder = user && ((user.role || '').toLowerCase() === 'founder');
      if (!isFounder) return json({ error: "Denegado" }, 403);
      const { title, clientEmail, progress, downloadUrl } = await request.json();
      const all = JSON.parse(await KV.get("projects:all") || "[]");
      const newProj = { id: "PRJ-" + Math.floor(1000 + Math.random() * 9000), title, clientEmail: clientEmail.toLowerCase().trim(), progress: parseInt(progress) || 0, downloadUrl: downloadUrl || "", author: user.username, updatedAt: new Date().toLocaleDateString() };
      all.unshift(newProj);
      await KV.put("projects:all", JSON.stringify(all));
      return json({ success: true });
    }

    if (url.pathname === '/api/founder/users' && request.method === 'GET') {
      const user = await getSessionUser();
      const isFounder = user && ((user.role || '').toLowerCase() === 'founder');
      if (!isFounder) return json({ error: "Denegado" }, 403);
      const users = await KV.get("users:list") || "[]";
      return json({ success: true, users: JSON.parse(users) });
    }

    if (url.pathname === '/api/founder/set-role' && request.method === 'POST') {
      const user = await getSessionUser();
      const isFounder = user && ((user.role || '').toLowerCase() === 'founder');
      if (!isFounder) return json({ error: "Denegado" }, 403);
      const { email, newRole } = await request.json();
      const targetRaw = await KV.get(`user:${email}`);
      const targetUser = JSON.parse(targetRaw);
      targetUser.role = newRole;
      await KV.put(`user:${email}`, JSON.stringify(targetUser));
      const usersList = JSON.parse(await KV.get("users:list") || "[]");
      const idx = usersList.findIndex(u => u.email === email);
      if (idx !== -1) { usersList[idx].role = newRole; await KV.put("users:list", JSON.stringify(usersList)); }
      return json({ success: true });
    }

    // ------------------------------------------------------------------------
    // RESEÑAS
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/reviews' && request.method === 'GET') {
      const reviews = JSON.parse(await KV.get("reviews:all") || "[]");
      return json({ success: true, reviews });
    }

    if (url.pathname === '/api/reviews/create' && request.method === 'POST') {
      const user = await getSessionUser();
      if (!user) return json({ error: "Inicia sesión" }, 401);
      const { stars, comment, service } = await request.json();
      const reviewObj = { id: "REV-" + Math.floor(1000 + Math.random() * 9000), author: user.username, role: user.role, mcNick: user.mcNick || "steve", stars: Math.min(5, Math.max(1, parseInt(stars) || 5)), comment: (comment || "").trim(), service: service || "Servicio General", date: new Date().toLocaleDateString() };
      const all = JSON.parse(await KV.get("reviews:all") || "[]");
      all.unshift(reviewObj);
      await KV.put("reviews:all", JSON.stringify(all));
      return json({ success: true, review: reviewObj });
    }

    // ------------------------------------------------------------------------
    // AUTENTICACIÓN
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      try {
        const { username, email, password } = await request.json();
        const normEmail = email.toLowerCase().trim();
        const normUser = username.toLowerCase().trim();

        if (await KV.get(`user:${normEmail}`)) return json({ error: "Correo ya registrado" }, 400);
        if (await KV.get(`username:${normUser}`)) return json({ error: "Usuario en uso" }, 400);

        const userCount = await KV.get("stats:user_count");
        const role = userCount === null ? "Founder" : "User";
        const passwordHash = await hashPassword(password);
        const userData = { id: crypto.randomUUID(), username, email: normEmail, role, mcNick: "", createdAt: new Date().toLocaleDateString() };

        await KV.put(`user:${normEmail}`, JSON.stringify({ ...userData, passwordHash }));
        await KV.put(`username:${normUser}`, normEmail);
        await KV.put("stats:user_count", String((parseInt(userCount || "0", 10)) + 1));

        const usersList = JSON.parse(await KV.get("users:list") || "[]");
        usersList.push(userData);
        await KV.put("users:list", JSON.stringify(usersList));

        const token = crypto.randomUUID();
        await KV.put(`session:${token}`, JSON.stringify(userData), { expirationTtl: 604800 });
        return json({ success: true, token, user: userData });
      } catch (err) { return json({ error: err.message }, 500); }
    }

    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      try {
        const { email, password } = await request.json();
        const normEmail = email.toLowerCase().trim();
        const raw = await KV.get(`user:${normEmail}`);
        if (!raw) return json({ error: "Credenciales inválidas" }, 401);

        const user = JSON.parse(raw);
        if (!(await verifyPassword(password, user.passwordHash))) return json({ error: "Credenciales inválidas" }, 401);

        const token = crypto.randomUUID();
        const { passwordHash, ...safeUser } = user;
        await KV.put(`session:${token}`, JSON.stringify(safeUser), { expirationTtl: 604800 });
        return json({ success: true, token, user: safeUser });
      } catch (err) { return json({ error: err.message }, 500); }
    }

    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const user = await getSessionUser();
      if (!user) return json({ error: "Sesión inválida" }, 401);
      return json({ success: true, user });
    }

    return env.ASSETS.fetch(request);
  }
};
