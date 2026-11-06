export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Endpoint de cotizaciones (Discord Webhook)
    if (url.pathname === '/api/quote' && request.method === 'POST') {
      try {
        const data = await request.json();
        const { name, discord, service, details } = data;

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
                  { name: "👤 Cliente", value: name, inline: true },
                  { name: "💬 Discord", value: discord, inline: true },
                  { name: "🛠 Servicio", value: service, inline: true },
                  { name: "📝 Detalles", value: details || "Sin detalles" }
                ],
                footer: { text: "Synthetix Studio • Cloudflare Worker" },
                timestamp: new Date().toISOString()
              }]
            })
          });
        }

        return new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500 });
      }
    }

    // Para cualquier otra ruta, entrega el diseño (HTML, CSS, JS de public/)
    return env.ASSETS.fetch(request);
  }
};
