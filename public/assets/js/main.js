import { pingMinecraftServer } from './mc-checker.js';
import { sendQuote } from './quote.js';

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) window.lucide.createIcons();

  // Detección de sesión en la portada
  const token = localStorage.getItem('synthetix_token');
  const user = JSON.parse(localStorage.getItem('synthetix_user') || '{}');

  if (token && user.username) {
    const portalLinks = document.querySelectorAll('a[href="/login"]');
    portalLinks.forEach(link => {
      link.href = '/dashboard';
      link.innerHTML = `<i data-lucide="layout-dashboard" class="w-4 h-4 text-purple-400"></i><span class="text-fuchsia-300 font-bold">${user.username} (${user.role})</span>`;
    });
    if (window.lucide) window.lucide.createIcons();
  }

  // MC Checker Handler
  const pingBtn = document.getElementById('pingBtn');
  const ipInput = document.getElementById('mcServerInput');
  const resultBox = document.getElementById('mcResult');

  if (pingBtn && ipInput && resultBox) {
    pingBtn.addEventListener('click', async () => {
      const ip = ipInput.value.trim();
      resultBox.innerHTML = '<span class="text-purple-400 animate-pulse">Consultando host...</span>';
      try {
        const data = await pingMinecraftServer(ip);
        if (data.online) {
          resultBox.innerHTML = `
            <div class="flex items-center justify-between text-emerald-400 font-semibold mb-1">
              <span>● EN LÍNEA</span>
              <span>${data.players.online} / ${data.players.max} Jugadores</span>
            </div>
            <p class="text-purple-300">Versión: <span class="text-white">${data.version || 'Personalizada'}</span></p>
          `;
        } else {
          resultBox.innerHTML = '<span class="text-rose-400 font-semibold">✕ Servidor offline</span>';
        }
      } catch (err) {
        resultBox.innerHTML = `<span class="text-rose-400 font-semibold">${err.message}</span>`;
      }
    });
  }
});
