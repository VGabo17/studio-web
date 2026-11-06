export async function onRequestPost({ request, env }) {
  try {
    const data = await request.json();
    const { name, discord, service, details } = data;

    if (!name || !discord || !service) {
      return new Response(JSON.stringify({ error: "Faltan campos obligatorios" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    const WEBHOOK_URL = env.DISCORD_WEBHOOK || "";

    if (WEBHOOK_URL) {
      const embedPayload = {
        username: "Synthetix Studio Bot",
        embeds: [{
          title: "⚡ Nueva Solicitud de Proyecto",
          color: 0x00f0ff,
          fields: [
            { name: "👤 Cliente", value: name, inline: true },
            { name: "💬 Discord", value: discord, inline: true },
            { name: "🛠 Servicio", value: service, inline: true },
            { name: "📝 Detalles", value: details || "Sin detalles adicionales" }
          ],
          footer: { text: "Synthetix Studio • Cloudflare Edge API" },
          timestamp: new Date().toISOString()
        }]
      };

      await fetch(WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(embedPayload)
      });
    }

    return new Response(JSON.stringify({ success: true, message: "Enviado con éxito" }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: "Error interno del servidor" }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
