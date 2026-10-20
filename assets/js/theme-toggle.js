(() => {
  const toggle = document.getElementById('theme-toggle');
  const key = 'flavor-theme-override';
  const media = matchMedia('(prefers-color-scheme: dark)');
  let preference;
  try { preference = localStorage.getItem(key) || sessionStorage.getItem(key); } catch (_) {}

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    toggle?.setAttribute('aria-label', theme === 'dark' ? '切换至浅色模式' : '切换至深色模式');
    toggle?.setAttribute('aria-pressed', String(theme === 'dark'));
  }
  applyTheme(document.documentElement.dataset.theme || (media.matches ? 'dark' : 'light'));
  toggle?.addEventListener('click', () => {
    preference = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(key, preference); } catch (_) {}
    try { sessionStorage.setItem(key, preference); } catch (_) {}
    applyTheme(preference);
  });
  media.addEventListener('change', event => {
    if (preference !== 'dark' && preference !== 'light') applyTheme(event.matches ? 'dark' : 'light');
  });

  const hamburger = document.getElementById('hamburger');
  const links = document.getElementById('nav-links');
  const navbar = document.getElementById('navbar');
  function setMenu(open) {
    links?.classList.toggle('is-open', open);
    hamburger?.setAttribute('aria-expanded', String(open));
    hamburger?.setAttribute('aria-label', open ? '关闭导航菜单' : '打开导航菜单');
  }
  hamburger?.addEventListener('click', () => setMenu(hamburger.getAttribute('aria-expanded') !== 'true'));
  links?.addEventListener('click', event => { if (event.target.closest('a')) setMenu(false); });
  document.getElementById('search-btn')?.addEventListener('click', () => setMenu(false));
  document.addEventListener('click', event => { if (!navbar?.contains(event.target)) setMenu(false); });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && hamburger?.getAttribute('aria-expanded') === 'true') {
      setMenu(false);
      hamburger.focus();
    }
  });
  matchMedia('(min-width: 769px)').addEventListener('change', () => setMenu(false));

  const top = document.getElementById('to-top');
  if (top) {
    const update = () => {
      const visible = scrollY > 320;
      top.classList.toggle('is-visible', visible);
      top.setAttribute('aria-hidden', String(!visible));
      top.tabIndex = visible ? 0 : -1;
    };
    update();
    addEventListener('scroll', update, { passive: true });
    top.addEventListener('click', () => scrollTo({ top: 0, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }));
  }
})();
