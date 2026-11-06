import { pingMinecraftServer } from './mc-checker.js';
import { sendQuote } from './quote.js';

document.addEventListener('DOMContentLoaded', async () => {
  if (window.lucide) window.lucide.createIcons();

  // 1. Cargar Anuncio Global del Founder
  try {
    const res = await fetch('/api/announcement');
    const d = await res.json();
    if (d.success && d.data && d.data.active && d.data.text) {
      const banner = document.createElement('div');
      banner.className = "bg-gradient-to-r from-purple-700 via-fuchsia-600 to-purple-700 text-white text-center py-2 px-4 text-xs font-bold tracking-wide shadow-lg flex items-center justify-center space-x-2";
      banner.innerHTML = `<span class="animate-pulse">⚡</span><span>${d.data.text}</span>`;
      document.body.prepend(banner);
    }
  } catch (e) {}

  // 2. Detección de sesión limpia en navbar
  const token = localStorage.getItem('synthetix_token');
  const user = JSON.parse(localStorage.getItem('synthetix_user') || '{}');

  if (token && user.username) {
    const desktopSlot = document.getElementById('desktopAuthSlot');
    if (desktopSlot) {
      desktopSlot.innerHTML = `
        <a href="/dashboard" class="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-purple-950/80 border border-purple-500/40 text-xs font-bold text-white hover:border-purple-400 transition">
          <span class="w-2 h-2 rounded-full bg-fuchsia-400 animate-pulse"></span>
          <span>${user.username}</span>
          <span class="text-[9px] font-mono uppercase bg-purple-900 px-1.5 py-0.5 rounded text-purple-300">${user.role}</span>
        </a>
      `;
    }

    const mobileBtn = document.getElementById('mobileUserBtn');
    if (mobileBtn) {
      mobileBtn.href = '/dashboard';
      mobileBtn.className = "w-10 h-10 rounded-xl bg-purple-950/80 border border-fuchsia-500/60 flex items-center justify-center text-fuchsia-300 relative";
      mobileBtn.innerHTML = `
        <i data-lucide="layout-dashboard" class="w-5 h-5"></i>
        <span class="absolute top-1 right-1 w-2 h-2 rounded-full bg-fuchsia-400 animate-ping"></span>
      `;
    }

    const mobileSlot = document.getElementById('mobileAuthSlot');
    if (mobileSlot) {
      mobileSlot.innerHTML = `
        <a href="/dashboard" class="flex items-center justify-between text-white font-bold py-2.5 px-3 rounded-xl bg-purple-900/60 border border-fuchsia-500/40">
          <div class="flex items-center space-x-2">
            <i data-lucide="layout-dashboard" class="w-4 h-4 text-fuchsia-300"></i>
            <span class="text-sm">${user.username}</span>
          </div>
          <span class="text-[10px] font-mono text-fuchsia-300 bg-purple-950 px-2 py-0.5 rounded uppercase font-bold">${user.role}</span>
        </a>
      `;
    }

    if (window.lucide) window.lucide.createIcons();
  }

  // Menú hamburguesa móvil
  const hBtn = document.getElementById('hamburgerBtn');
  const mMenu = document.getElementById('mobileMenu');
  const hIcon = document.getElementById('hamburgerIcon');

  if (hBtn && mMenu) {
    hBtn.addEventListener('click', () => {
      const isClosed = mMenu.classList.contains('hidden');
      if (isClosed) {
        mMenu.classList.remove('hidden');
        hIcon.setAttribute('data-lucide', 'x');
      } else {
        mMenu.classList.add('hidden');
        hIcon.setAttribute('data-lucide', 'menu');
      }
      if (window.lucide) window.lucide.createIcons();
    });

    document.querySelectorAll('.mobile-nav-link').forEach(link => {
      link.addEventListener('click', () => {
        mMenu.classList.add('hidden');
        hIcon.setAttribute('data-lucide', 'menu');
        if (window.lucide) window.lucide.createIcons();
      });
    });
  }

  // MC Ping Tester
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
