// ----------------------------------------------------------------------------
// CRIPTOGRAFÍA NATIVA WEB CRYPTO (Sin dependencias externas)
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// WORKER ROUTER & API
// ----------------------------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const KV = env.SYNTHETIX_KV;

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" }
    });

    // Enrutador de URLs Limpias (Sin .html)
    const cleanRoutes = ['/login', '/dashboard', '/admin'];
    if (cleanRoutes.includes(url.pathname)) {
      return env.ASSETS.fetch(new Request(new URL(`${url.pathname}.html`, request.url), request));
    }

    // REGISTRO (/api/auth/register)
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      try {
        const { username, email, password, discord } = await request.json();
        
        if (!username || !email || !password) {
          return json({ error: "Faltan campos obligatorios" }, 400);
        }

        const normalizedEmail = email.toLowerCase().trim();
        const normalizedUsername = username.toLowerCase().trim();

        const existingUser = await KV.get(`user:${normalizedEmail}`);
        if (existingUser) {
          return json({ error: "Este correo ya está registrado" }, 400);
        }

        const existingUsername = await KV.get(`username:${normalizedUsername}`);
        if (existingUsername) {
          return json({ error: "Este usuario ya está en uso" }, 400);
        }

        // Si es el primer usuario en KV, se convierte en Founder
        const userCount = await KV.get("stats:user_count");
        const role = userCount === null ? "Founder" : "User";

        const passwordHash = await hashPassword(password);
        const userId = crypto.randomUUID();

        const userData = {
          id: userId,
          username,
          email: normalizedEmail,
          discord: discord || "",
          role,
          createdAt: new Date().toISOString()
        };

        await KV.put(`user:${normalizedEmail}`, JSON.stringify({ ...userData, passwordHash }));
        await KV.put(`username:${normalizedUsername}`, normalizedEmail);
        await KV.put("stats:user_count", String((parseInt(userCount || "0", 10)) + 1));

        const sessionToken = crypto.randomUUID();
        await KV.put(`session:${sessionToken}`, JSON.stringify(userData), { expirationTtl: 604800 });

        return json({
          success: true,
          token: sessionToken,
          user: userData,
          message: role === "Founder" ? "¡Cuenta de Fundador creada con éxito!" : "Cuenta creada con éxito"
        });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // LOGIN (/api/auth/login)
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      try {
        const { email, password } = await request.json();
        const normalizedEmail = email.toLowerCase().trim();

        const rawUser = await KV.get(`user:${normalizedEmail}`);
        if (!rawUser) {
          return json({ error: "Credenciales inválidas" }, 401);
        }

        const user = JSON.parse(rawUser);
        const valid = await verifyPassword(password, user.passwordHash);

        if (!valid) {
          return json({ error: "Credenciales inválidas" }, 401);
        }

        const sessionToken = crypto.randomUUID();
        const { passwordHash, ...safeUserData } = user;
        
        await KV.put(`session:${sessionToken}`, JSON.stringify(safeUserData), { expirationTtl: 604800 });

        return json({
          success: true,
          token: sessionToken,
          user: safeUserData
        });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // OBTENER SESIÓN ACTUAL (/api/auth/me)
    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return json({ error: "No autorizado" }, 401);
      }

      const token = authHeader.replace("Bearer ", "").trim();
      const sessionData = await KV.get(`session:${token}`);

      if (!sessionData) {
        return json({ error: "Sesión inválida o expirada" }, 401);
      }

      return json({ success: true, user: JSON.parse(sessionData) });
    }

    // COTIZACIÓN POR WEBHOOK (/api/quote)
    if (url.pathname === '/api/quote' && request.method === 'POST') {
      try {
        const data = await request.json();
        const WEBHOOK_URL = env.DISCORD_WEBHOOK || "";
        if (WEBHOOK_URL) {
          await fetch(WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: "Synthetix Studio Bot",
              embeds: [{
                title: "⚡ Nueva Solicitud de Proyecto",
                color: 0xa855f7,
                fields: [
                  { name: "👤 Cliente", value: data.name || "Anónimo", inline: true },
                  { name: "💬 Discord", value: data.discord || "N/A", inline: true },
                  { name: "🛠 Servicio", value: data.service || "General", inline: true },
                  { name: "📝 Detalles", value: data.details || "Sin detalles" }
                ],
                footer: { text: "Synthetix Studio • Cloudflare Worker" },
                timestamp: new Date().toISOString()
              }]
            })
          });
        }
        return json({ success: true });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // Servir archivos estáticos del frontend
    return env.ASSETS.fetch(request);
  }
};
