(() => {
  const progress = document.getElementById('reading-progress');
  const main = document.querySelector('.read__main');
  if (!main) return;

  function enhance() {
    main.querySelectorAll('.article-content :is(h2, h3, h4)[id]').forEach(heading => {
      if (heading.querySelector('.heading-anchor')) return;
      const anchor = document.createElement('a');
      anchor.className = 'heading-anchor';
      anchor.href = `#${encodeURIComponent(heading.id)}`;
      anchor.setAttribute('aria-label', `定位到：${heading.textContent.trim()}`);
      anchor.setAttribute('data-pagefind-ignore', '');
      anchor.textContent = '#';
      heading.append(anchor);
    });
    schedule();
  }

  let pending = false;
  function schedule() {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      if (!progress) return;
      const content = main.querySelector('.article-content');
      if (!content) { progress.style.transform = 'scaleX(0)'; return; }
      const top = content.getBoundingClientRect().top + scrollY - 110;
      const distance = Math.max(1, content.offsetHeight - innerHeight + 110);
      const fraction = Math.min(1, Math.max(0, (scrollY - top) / distance));
      progress.style.transform = `scaleX(${fraction})`;
    });
  }
  addEventListener('scroll', schedule, { passive: true });
  addEventListener('resize', schedule);
  new ResizeObserver(schedule).observe(main);
  document.addEventListener('flavor:enhance', enhance);
  enhance();
})();
