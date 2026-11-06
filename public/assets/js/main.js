import { pingMinecraftServer } from './mc-checker.js';
import { sendQuote } from './quote.js';

document.addEventListener('DOMContentLoaded', () => {
  // Inicializar iconos de Lucide
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // MC Checker Handler
  const pingBtn = document.getElementById('pingBtn');
  const ipInput = document.getElementById('mcServerInput');
  const resultBox = document.getElementById('mcResult');

  if (pingBtn && ipInput && resultBox) {
    pingBtn.addEventListener('click', async () => {
      const ip = ipInput.value.trim();
      resultBox.innerHTML = '<span class="text-purple-400 animate-pulse">Consultando estado del host...</span>';
      
      try {
        const data = await pingMinecraftServer(ip);
        if (data.online) {
          resultBox.innerHTML = `
            <div class="flex items-center justify-between text-emerald-400 font-semibold mb-1">
              <span>● EN LÍNEA</span>
              <span>${data.players.online} / ${data.players.max} Jugadores</span>
            </div>
            <p class="text-purple-300">Versión: <span class="text-white">${data.version || 'Personalizada'}</span></p>
            <p class="text-purple-300">MOTD: <span class="text-white">${data.motd?.clean ? data.motd.clean.join(' ') : 'Sin descripción'}</span></p>
          `;
        } else {
          resultBox.innerHTML = '<span class="text-rose-400 font-semibold">✕ Servidor fuera de línea o IP inaccesible.</span>';
        }
      } catch (err) {
        resultBox.innerHTML = `<span class="text-rose-400 font-semibold">${err.message}</span>`;
      }
    });
  }

  // Quote Form Handler
  const quoteForm = document.getElementById('quoteForm');
  const submitBtn = document.getElementById('submitBtn');
  const statusMsg = document.getElementById('formStatus');

  if (quoteForm) {
    quoteForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const selected = Array.from(document.querySelectorAll('.service-check:checked')).map(cb => cb.value);
      if (selected.length === 0) {
        statusMsg.innerText = "Selecciona al menos un módulo arriba.";
        statusMsg.className = "text-center text-xs text-amber-400 block font-semibold mt-2";
        return;
      }

      submitBtn.disabled = true;
      submitBtn.innerText = "Transmitiendo orden...";

      const payload = {
        name: document.getElementById('name').value,
        discord: document.getElementById('discord').value,
        service: selected.join(" + "),
        details: document.getElementById('details').value
      };

      try {
        await sendQuote(payload);
        statusMsg.innerText = "¡Orden enviada! Te contactaremos vía Discord.";
        statusMsg.className = "text-center text-xs text-purple-300 block font-semibold mt-2";
        quoteForm.reset();
        document.querySelectorAll('.service-check').forEach(cb => cb.checked = false);
      } catch (err) {
        statusMsg.innerText = err.message || "Error al contactar con la API.";
        statusMsg.className = "text-center text-xs text-rose-400 block font-semibold mt-2";
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerText = "Enviar Orden a Synthetix";
      }
    });
  }
});
