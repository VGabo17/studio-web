import { hashPassword, verifyPassword } from './crypto.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const KV = env.SYNTHETIX_KV;

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" }
    });

    // ------------------------------------------------------------------------
    // ENRUTADOR DE URLS LIMPIAS (Sin .html)
    // ------------------------------------------------------------------------
    const cleanRoutes = ['/login', '/dashboard', '/admin'];
    if (cleanRoutes.includes(url.pathname)) {
      return env.ASSETS.fetch(new Request(new URL(`${url.pathname}.html`, request.url), request));
    }

    // ------------------------------------------------------------------------
    // API: REGISTRO (/api/auth/register)
    // ------------------------------------------------------------------------
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
          return json({ error: "Este correo electrónico ya está registrado" }, 400);
        }

        const existingUsername = await KV.get(`username:${normalizedUsername}`);
        if (existingUsername) {
          return json({ error: "Este nombre de usuario ya está en uso" }, 400);
        }

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
          message: role === "Founder" ? "¡Cuenta Founder creada!" : "Cuenta creada con éxito"
        });
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // ------------------------------------------------------------------------
    // API: LOGIN (/api/auth/login)
    // ------------------------------------------------------------------------
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

    // ------------------------------------------------------------------------
    // API: USUARIO ACTUAL (/api/auth/me)
    // ------------------------------------------------------------------------
    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return json({ error: "No autorizado" }, 401);
      }

      const token = authHeader.replace("Bearer ", "").trim();
      const sessionData = await KV.get(`session:${token}`);

      if (!sessionData) {
        return json({ error: "Sesión expirada o inválida" }, 401);
      }

      return json({ success: true, user: JSON.parse(sessionData) });
    }

    // ------------------------------------------------------------------------
    // API: COTIZACIONES (/api/quote)
    // ------------------------------------------------------------------------
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

    return env.ASSETS.fetch(request);
  }
};
