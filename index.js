import Terminal from './terminal.js';

document.addEventListener('DOMContentLoaded', () => {
  const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute('content');
  const element = document.getElementById('terminal');
  const terminal = new Terminal(element, csrfToken);
  terminal.open();
  window.addEventListener('unload', () => {
    terminal.dispose();
  });
});
