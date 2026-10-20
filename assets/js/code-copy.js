(() => {
  const copyLabel = window.flavorI18n?.copyCode || '复制代码';
  const icon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
  const blocks = new WeakMap();
  const resize = new ResizeObserver(entries => {
    for (const { target } of entries) {
      if (target.scrollWidth > target.clientWidth) {
        target.tabIndex = 0;
        target.setAttribute('aria-label', '代码，可横向滚动');
      } else {
        target.removeAttribute('tabindex');
        target.removeAttribute('aria-label');
      }
    }
  });

  function enhance(root) {
    root.querySelectorAll('.article-content pre').forEach(pre => {
      // Hugo can render line numbers in a separate table cell.
      if (pre.closest('.lntd') && !pre.closest('.lntd:last-child')) return;
      let block = pre.closest('.highlight');
      if (block?.querySelector('.code-toolbar')) return;
      if (!block) {
        block = document.createElement('div');
        block.className = 'highlight';
        pre.before(block);
        block.append(pre);
      }
      const code = pre.querySelector('code');
      const language = code?.dataset.lang || [...(code?.classList || [])].find(name => name.startsWith('language-'))?.slice(9) || 'text';
      const toolbar = document.createElement('div');
      toolbar.className = 'code-toolbar';
      toolbar.setAttribute('data-pagefind-ignore', '');
      const label = document.createElement('span');
      label.textContent = language;
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'highlight__copy';
      button.setAttribute('aria-label', copyLabel);
      button.innerHTML = icon;
      const status = document.createElement('span');
      status.textContent = '复制';
      status.setAttribute('role', 'status');
      button.append(status);
      toolbar.append(label, button);
      block.prepend(toolbar);
      blocks.set(button, { pre, status, timer: null });
      resize.observe(pre);
    });
  }

  document.addEventListener('click', async event => {
    const button = event.target.closest('.highlight__copy');
    const block = blocks.get(button);
    if (!block || button.disabled) return;
    clearTimeout(block.timer);
    button.classList.remove('copied');
    button.disabled = true;
    try {
      const code = block.pre.querySelector('code') || block.pre;
      await navigator.clipboard.writeText(code.textContent);
      button.classList.add('copied');
      block.status.textContent = '已复制';
      button.setAttribute('aria-label', '代码已复制');
    } catch {
      block.status.textContent = '复制失败';
      button.setAttribute('aria-label', '复制失败，请选择代码后手动复制');
    } finally {
      button.disabled = false;
      block.timer = setTimeout(() => {
        button.classList.remove('copied');
        block.status.textContent = '复制';
        button.setAttribute('aria-label', copyLabel);
      }, 2500);
    }
  });
  enhance(document);
  document.addEventListener('flavor:enhance', event => enhance(event.detail || document));
})();
