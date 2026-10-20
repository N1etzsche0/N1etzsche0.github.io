(() => {
  const aside = document.getElementById('toc-aside');
  const button = document.getElementById('toc-btn');
  const close = document.getElementById('toc-close');
  const read = document.querySelector('.read');
  if (!aside || !button) return;
  const compact = matchMedia('(max-width: 1199px)');
  const backdrop = document.createElement('div');
  backdrop.className = 'toc-backdrop';
  backdrop.hidden = true;
  backdrop.setAttribute('aria-hidden', 'true');
  document.body.append(backdrop);
  aside.tabIndex = -1;
  aside.inert = true;
  let open = false;
  let background = [];

  function restoreBackground() {
    for (const [element, inert] of background) element.inert = inert;
    background = [];
    document.body.classList.remove('toc-open');
  }

  function syncMode() {
    restoreBackground();
    const modal = open && compact.matches;
    backdrop.hidden = !modal;
    aside.setAttribute('role', modal ? 'dialog' : 'complementary');
    if (modal) {
      aside.setAttribute('aria-modal', 'true');
      document.body.classList.add('toc-open');
      document.querySelectorAll('.navbar, .read, .site-footer, .skip-link, #toc-btn, #to-top').forEach(element => {
        background.push([element, element.inert]);
        element.inert = true;
      });
      if (!aside.contains(document.activeElement)) (close || aside).focus({ preventScroll: true });
    } else aside.removeAttribute('aria-modal');
  }

  function setOpen(value, restoreFocus = true) {
    open = value;
    if (!value) restoreBackground();
    aside.inert = !value;
    aside.classList.toggle('is-open', value);
    read?.classList.toggle('is-toc-open', value);
    button.setAttribute('aria-expanded', String(value));
    aside.setAttribute('aria-hidden', String(!value));
    syncMode();
    schedule();
    if (value) (close || aside).focus({ preventScroll: true });
    else if (restoreFocus) button.focus({ preventScroll: true });
  }
  button.addEventListener('click', () => setOpen(!open));
  close?.addEventListener('click', () => setOpen(false));
  backdrop.addEventListener('click', () => setOpen(false));
  compact.addEventListener('change', syncMode);
  document.getElementById('search-btn')?.addEventListener('click', () => { if (open) setOpen(false, false); });
  document.addEventListener('keydown', event => {
    if (open && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') setOpen(false);
  }, true);
  document.addEventListener('keydown', event => {
    if (!open || document.querySelector('.search-overlay.is-visible')) return;
    if (event.key === 'Escape') { event.preventDefault(); setOpen(false); }
    if (event.key !== 'Tab' || !compact.matches) return;
    const controls = [...aside.querySelectorAll('a[href], button:not([disabled])')];
    const first = controls[0] || aside;
    const last = controls.at(-1) || aside;
    if (event.shiftKey && (document.activeElement === first || document.activeElement === aside)) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus();
    }
  });
  document.addEventListener('focusin', event => {
    if (open && compact.matches && !aside.contains(event.target) && !document.querySelector('.search-overlay.is-visible')) (close || aside).focus();
  });
  aside.addEventListener('click', event => {
    const link = event.target.closest('a[href^="#"]');
    if (!link || !compact.matches) return;
    const target = document.getElementById(decodeURIComponent(link.hash.slice(1)));
    if (!target) return;
    event.preventDefault();
    setOpen(false, false);
    history.pushState(null, '', link.hash);
    target.tabIndex = -1;
    target.focus({ preventScroll: true });
    target.scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
  });

  let sections = [];
  let active = null;
  let pending = false;
  function reveal(section) {
    if (!open || !section) return;
    const list = aside.querySelector('.toc');
    const item = section.link.getBoundingClientRect();
    const bounds = list.getBoundingClientRect();
    if (item.top < bounds.top || item.bottom > bounds.bottom) list.scrollTop += item.top - bounds.top - 12;
  }
  function enhance() {
    sections = [...aside.querySelectorAll('.toc a[href^="#"]')].map(link => ({
      link,
      heading: document.getElementById(decodeURIComponent(link.hash.slice(1)))
    })).filter(item => item.heading);
    active = null;
    schedule();
  }
  function schedule() {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      let current = null;
      for (const section of sections) {
        if (section.heading.getBoundingClientRect().top <= 116) current = section;
        else break;
      }
      if (current === active) { reveal(current); return; }
      for (const section of sections) {
        const selected = section === current;
        section.link.parentElement.classList.toggle('active-class', selected);
        if (selected) section.link.setAttribute('aria-current', 'location');
        else section.link.removeAttribute('aria-current');
      }
      active = current;
      reveal(current);
    });
  }
  addEventListener('scroll', schedule, { passive: true });
  addEventListener('resize', schedule);
  document.addEventListener('flavor:enhance', enhance);
  enhance();
})();
