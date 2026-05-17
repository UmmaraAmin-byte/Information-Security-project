/* ─── Loading screen ────────────────────────────────────────── */
window.addEventListener('load', () => {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) {
    setTimeout(() => {
      overlay.classList.add('hidden');
      setTimeout(() => overlay.remove(), 600);
    }, 1400);
  }
});

/* ─── Typing animation ──────────────────────────────────────── */
function typeText(elementId, text, speed = 80) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = '';
  let i = 0;
  const timer = setInterval(() => {
    if (i < text.length) { el.textContent += text[i++]; }
    else { clearInterval(timer); }
  }, speed);
}

/* ─── Universal toggle for learning panels ──────────────────── */
function toggleLearn(header) {
  const body = header.nextElementSibling;
  if (!body) return;
  const icon = header.querySelector('.fa-chevron-down, .fa-chevron-up');
  const isHidden = !body.style.display || body.style.display === 'none';
  body.style.display = isHidden ? '' : 'none';
  if (icon) {
    icon.classList.toggle('fa-chevron-down', !isHidden);
    icon.classList.toggle('fa-chevron-up', isHidden);
  }
}

/* ─── Debounce ──────────────────────────────────────────────── */
function debounce(fn, wait) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), wait);
  };
}

/* ─── Score bar animation ───────────────────────────────────── */
function animateScoreBars() {
  document.querySelectorAll('.score-bar-fill, .strength-fill').forEach(bar => {
    const target = bar.style.width;
    bar.style.width = '0%';
    requestAnimationFrame(() => {
      setTimeout(() => { bar.style.width = target; }, 100);
    });
  });

  document.querySelectorAll('circle[stroke-dasharray]').forEach(circle => {
    const dashArray = circle.getAttribute('stroke-dasharray');
    circle.setAttribute('stroke-dasharray', '0 263.9');
    requestAnimationFrame(() => {
      setTimeout(() => {
        circle.style.transition = 'stroke-dasharray 0.8s ease';
        circle.setAttribute('stroke-dasharray', dashArray);
      }, 150);
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  typeText('typeTarget', ' authenticate --secure');

  document.querySelectorAll('.input-hacker').forEach(input => {
    input.addEventListener('focus',  () => input.parentElement.classList.add('focused'));
    input.addEventListener('blur',   () => input.parentElement.classList.remove('focused'));
  });

  document.querySelectorAll('.log-tab').forEach(tab => {
    tab.addEventListener('click', function() {
      document.querySelectorAll('.log-tab').forEach(t => t.classList.remove('active'));
      this.classList.add('active');
    });
  });

  document.querySelectorAll('.learn-body').forEach(el => {
    if (!el.style.display) el.style.display = 'none';
  });

  animateScoreBars();
});

/* ─── Matrix rain (auth pages only) ────────────────────────── */
(function() {
  const isAuth = document.querySelector('.auth-wrapper');
  if (!isAuth) return;

  const canvas = document.createElement('canvas');
  canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;opacity:0.04;pointer-events:none;';
  document.body.appendChild(canvas);

  const ctx = canvas.getContext('2d');
  let W, H, drops;

  function setup() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    const cols = Math.floor(W / 16);
    drops = Array(cols).fill(1);
  }

  function draw() {
    ctx.fillStyle = 'rgba(0,0,0,0.05)';
    ctx.fillRect(0, 0, W, H);
    ctx.fillStyle = '#00ff88';
    ctx.font = '14px monospace';
    drops.forEach((y, i) => {
      const ch = String.fromCharCode(0x30A0 + Math.floor(Math.random() * 96));
      ctx.fillText(ch, i * 16, y * 16);
      if (y * 16 > H && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }

  setup();
  setInterval(draw, 50);
  window.addEventListener('resize', setup);
})();
