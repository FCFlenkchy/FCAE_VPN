// === Particles Background ===
const canvas = document.getElementById('particles');
const ctx = canvas.getContext('2d');
let particles = [];
let mouse = { x: -1000, y: -1000 };

function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}
window.addEventListener('resize', resize);
resize();

class Particle {
    constructor() {
        this.reset();
        this.y = Math.random() * canvas.height;
    }
    reset() {
        this.x = Math.random() * canvas.width;
        this.y = -10;
        this.size = Math.random() * 2 + 0.5;
        this.speedY = Math.random() * 0.4 + 0.15;
        this.speedX = (Math.random() - 0.5) * 0.3;
        this.opacity = Math.random() * 0.5 + 0.1;
        this.life = 0;
        this.maxLife = Math.random() * 400 + 200;
    }
    update() {
        this.y += this.speedY;
        this.x += this.speedX + Math.sin(this.life * 0.02) * 0.2;
        this.life++;

        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 150) {
            this.x += dx * 0.003;
            this.y += dy * 0.003;
        }

        if (this.y > canvas.height + 10 || this.x < -10 || this.x > canvas.width + 10 || this.life > this.maxLife) {
            this.reset();
        }
    }
    draw() {
        const alpha = this.opacity * (1 - this.life / this.maxLife);
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(124,92,252,${alpha})`;
        ctx.fill();
    }
}

for (let i = 0; i < 80; i++) {
    const p = new Particle();
    p.y = Math.random() * canvas.height;
    particles.push(p);
}

document.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
});

function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach(p => { p.update(); p.draw(); });

    for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 100) {
                ctx.beginPath();
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(particles[j].x, particles[j].y);
                ctx.strokeStyle = `rgba(124,92,252,${0.06 * (1 - dist / 100)})`;
                ctx.lineWidth = 0.5;
                ctx.stroke();
            }
        }
    }
    requestAnimationFrame(animate);
}
animate();

// === GitHub API: Releases & Contributors ===
const REPO = 'FCFlenkchy/FCAE_VPN';
const API = 'https://api.github.com/repos/' + REPO;

async function loadReleases() {
    try {
        const res = await fetch(API + '/releases?per_page=5');
        if (!res.ok) throw new Error('API limit');
        const releases = await res.json();
        renderReleases(releases);
    } catch (e) {
        document.getElementById('dlTabs').innerHTML = '<span style="color:var(--text2);font-size:.85rem">⚠️ Could not load releases from GitHub. <a href="https://github.com/FCFlenkchy/FCAE_VPN/releases" target="_blank">View releases page</a></span>';
        document.getElementById('dlContent').innerHTML = '';
    }
}

function formatSize(bytes) {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(0) + ' KB';
    return bytes + ' B';
}

function formatDate(dateStr) {
    return new Date(dateStr).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function getPlatformIcon(name) {
    const n = name.toLowerCase();
    if (n.includes('windows')) return '🪟';
    if (n.includes('linux')) return '🐧';
    if (n.includes('macos') || n.includes('darwin')) return '🍎';
    if (n.includes('android')) return '📱';
    return '📦';
}

function renderReleases(releases) {
    const tabsEl = document.getElementById('dlTabs');
    const contentEl = document.getElementById('dlContent');

    if (!releases.length) {
        tabsEl.innerHTML = '<span style="color:var(--text2)">No releases found</span>';
        return;
    }

    tabsEl.innerHTML = releases.map((r, i) =>
        `<button class="dl-tab${i === 0 ? ' act' : ''}" onclick="showRelease(${i})">${r.tag_name} ${!r.prerelease ? '⭐' : ''}</button>`
    ).join('');

    window._releases = releases;
    showRelease(0);
}

function showRelease(idx) {
    const releases = window._releases;
    if (!releases || !releases[idx]) return;
    const r = releases[idx];

    document.querySelectorAll('.dl-tab').forEach((t, i) => t.classList.toggle('act', i === idx));

    const contentEl = document.getElementById('dlContent');
    let bodyHtml = '';
    if (r.body) {
        bodyHtml = '<div class="dl-body">' + r.body
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\r?\n/g, '<br>')
            .replace(/https:\/\/github\.com\/[^\s<]+/g, '<a href="$&" target="_blank">$&</a>')
            + '</div>';
    }

    contentEl.innerHTML = `
        <div class="dl-info">
            <span class="dl-badge ${r.prerelease ? 'dl-pre' : 'dl-stable'}">${r.prerelease ? 'Pre-release' : 'Stable'}</span>
            <span class="dl-date">Released ${formatDate(r.published_at)}</span>
        </div>
        ${bodyHtml}
        <div class="dl-grid">
            ${r.assets.map(a => `
                <a class="dl-card" href="${a.browser_download_url}" target="_blank" rel="noopener">
                    <span class="dlic">${getPlatformIcon(a.name)}</span>
                    <span class="dlinfo">
                        <span class="dlnm">${a.name}</span>
                        <span class="dlsz">${formatSize(a.size)} · ↓ ${a.download_count}</span>
                    </span>
                    <span class="dlarr">↓</span>
                </a>
            `).join('')}
        </div>
    `;
}

// Fetch contributors
async function loadContributors() {
    try {
        const res = await fetch(API + '/contributors?per_page=20');
        if (!res.ok) throw new Error('API limit');
        const contributors = await res.json();
        renderContributors(contributors);
    } catch (e) {
        document.getElementById('contribGrid').innerHTML = '<span style="color:var(--text2);font-size:.85rem">⚠️ Could not load contributors</span>';
    }
}

function renderContributors(contributors) {
    const grid = document.getElementById('contribGrid');
    if (!contributors.length) {
        grid.innerHTML = '<span style="color:var(--text2)">No contributors yet</span>';
        return;
    }
    grid.innerHTML = contributors.map(c => `
        <a class="contrib-card" href="${c.html_url}" target="_blank" rel="noopener">
            <img class="contrib-av" src="${c.avatar_url}&s=104" alt="${c.login}" loading="lazy">
            <span class="contrib-info">
                <span class="contrib-nm">@${c.login}</span>
                <span class="contrib-cm">${c.contributions} commit${c.contributions !== 1 ? 's' : ''}</span>
            </span>
        </a>
    `).join('');
}

// Load everything
loadReleases();
loadContributors();

// Nav scroll effect
window.addEventListener('scroll', () => {
    const nav = document.querySelector('nav');
    if (window.scrollY > 50) {
        nav.style.boxShadow = '0 4px 30px rgba(0,0,0,0.5)';
    } else {
        nav.style.boxShadow = 'none';
    }
});
