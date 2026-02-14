// ==========================================
// VNAMEB - CLOUDFLARE WORKER VERSION
// ==========================================

// --- UTILS & HELPERS ---
async function hashPassword(password) {
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function escapeHtml(s) { 
    if (!s) return ''; 
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); 
}

function getCookie(request, name) {
    const cookieString = request.headers.get('Cookie');
    if (!cookieString) return null;
    const match = cookieString.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return match ? match[2] : null;
}

// --- CSS & GLOBAL STYLES ---
const COMMON_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
  @import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css');

  :root { --primary: #3b82f6; --bg: #0f172a; --glass: rgba(255, 255, 255, 0.05); --border: rgba(255, 255, 255, 0.1); }
  * { box-sizing: border-box; outline: none; }
  body { font-family: 'Outfit', sans-serif; background: var(--bg); color: #f8fafc; margin: 0; min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }
  a { text-decoration: none; color: inherit; transition: 0.2s; }

  .page-enter { animation: pageSlideUp 0.8s cubic-bezier(0.2, 0.8, 0.2, 1) forwards; opacity: 0; transform: translateY(20px); }
  @keyframes pageSlideUp { to { opacity: 1; transform: translateY(0); } }

  .glass-panel { background: var(--glass); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid var(--border); border-radius: 24px; padding: 40px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); position: relative; z-index: 10; }
  
  input, select, textarea { width: 100%; background: rgba(0,0,0,0.3); border: 1px solid var(--border); padding: 14px 16px; border-radius: 12px; color: white; font-family: inherit; margin-top: 8px; transition: 0.3s; }
  input:focus, textarea:focus { border-color: var(--primary); background: rgba(0,0,0,0.5); box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2); }
  
  .btn { display: inline-block; background: var(--primary); color: white; padding: 12px 24px; border-radius: 12px; font-weight: 600; border: none; cursor: pointer; margin-top: 10px; transition: transform 0.2s, box-shadow 0.2s; width: 100%; text-align: center; font-size: 14px; box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.5); }
  .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(59, 130, 246, 0.6); }
  .btn:disabled { opacity: 0.7; cursor: not-allowed; transform: none; box-shadow: none; }

  .switch-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding: 12px; background: rgba(255,255,255,0.03); border-radius: 12px; }
  .switch { position: relative; display: inline-block; width: 52px; height: 28px; flex-shrink: 0; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #334155; transition: .4s; border-radius: 34px; }
  .slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
  input:checked + .slider { background-color: var(--primary); }
  input:checked + .slider:before { transform: translateX(24px); }
  
  input[type=range] { -webkit-appearance: none; background: transparent; padding: 0; margin: 10px 0; }
  input[type=range]::-webkit-slider-thumb { -webkit-appearance: none; height: 16px; width: 16px; border-radius: 50%; background: var(--primary); margin-top: -6px; cursor: pointer; }
  input[type=range]::-webkit-slider-runnable-track { width: 100%; height: 4px; background: #334155; border-radius: 2px; }

  .anim-bg { position: fixed; inset: 0; overflow: hidden; z-index: 0; pointer-events: none; }
  .blob { position: absolute; filter: blur(60px); opacity: 0.4; animation: float 10s infinite alternate; }
  .blob-1 { width: 400px; height: 400px; background: #3b82f6; top: -100px; left: -100px; }
  .blob-2 { width: 300px; height: 300px; background: #60a5fa; bottom: -50px; right: -50px; animation-duration: 15s; }
  @keyframes float { 0% { transform: translate(0, 0); } 100% { transform: translate(50px, 50px); } }

  /* AJAX Toast Notification */
  #toast { visibility: hidden; min-width: 250px; background-color: #10b981; color: #fff; text-align: center; border-radius: 8px; padding: 16px; position: fixed; z-index: 9999; left: 50%; bottom: 30px; transform: translateX(-50%); font-size: 14px; opacity: 0; transition: opacity 0.3s, bottom 0.3s; font-weight: 600; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); }
  #toast.show { visibility: visible; opacity: 1; bottom: 50px; }
  #toast.error { background-color: #ef4444; }

  /* Custom File Upload */
  .custom-file-upload { position: relative; width: 100%; height: 120px; background: rgba(0,0,0,0.3); border: 2px dashed rgba(255,255,255,0.15); border-radius: 12px; overflow: hidden; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: 0.3s; margin-top: 5px; }
  .custom-file-upload:hover { border-color: var(--primary); background: rgba(0,0,0,0.5); }
  .cfu-preview { width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background-size: cover; background-position: center; pointer-events: none; }
  .cfu-placeholder { color: #94a3b8; font-size: 13px; display: flex; flex-direction: column; align-items: center; pointer-events: none; }
`;

// --- WORKER DEFAULT EXPORT ---
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ----- AUTHENTICATION CHECK -----
    let currentUser = null;
    const sessionToken = getCookie(request, 'session_token');
    if (sessionToken) {
        currentUser = await env.DB.prepare("SELECT * FROM users WHERE sessionToken = ?").bind(sessionToken).first();
    }

    // ==========================================
    // 1. HOME / LANDING PAGE
    // ==========================================
    if (path === '/' && request.method === 'GET') {
        return new Response(`<!doctype html><html><head><title>VnameB</title><style>${COMMON_CSS} body{align-items:center;justify-content:center;text-align:center;}</style></head>
        <body>
          <div class="anim-bg"><div class="blob blob-1"></div><div class="blob blob-2"></div></div>
          <div class="glass-panel page-enter" style="width: 100%; max-width: 400px;">
            <h1 style="margin:0 0 10px 0; background: linear-gradient(to right, #fff, #60a5fa); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">VnameB</h1>
            <p style="color:#94a3b8; margin-bottom: 30px;">Your ultimate bio site.</p>
            <div style="display:grid; gap:12px;">
              ${currentUser ? 
                `<a href="/dashboard" class="btn">Go to Dashboard</a>` : 
                `<a href="/login" class="btn">Sign In</a><a href="/register" class="btn" style="background:rgba(255,255,255,0.05); box-shadow:none;">Create Account</a>`
              }
            </div>
          </div>
        </body></html>`, { headers: { 'Content-Type': 'text/html' }});
    }

    // ==========================================
    // 2. AUTHENTICATION PAGES & APIs
    // ==========================================
    if (path === '/register' && request.method === 'GET') {
        if (currentUser) return Response.redirect(url.origin + '/dashboard', 302);
        return new Response(`<!doctype html><html><head><title>Register - VnameB</title><style>${COMMON_CSS} body{align-items:center;justify-content:center;}</style></head>
        <body>
          <div class="anim-bg"><div class="blob blob-1"></div><div class="blob blob-2"></div></div>
          <div class="glass-panel page-enter" style="width:400px">
            <h2 style="text-align:center; margin-bottom:30px;">Create Account</h2>
            <form method="POST" action="/api/register">
              <label style="font-size:12px; color:#cbd5e1">Handle (URL)</label>
              <input name="handle" required placeholder="e.g. bromm">
              <label style="font-size:12px; color:#cbd5e1; margin-top:15px; display:block;">Email</label>
              <input type="email" name="email" required placeholder="mail@example.com">
              <label style="font-size:12px; color:#cbd5e1; margin-top:15px; display:block;">Password</label>
              <input type="password" name="password" required placeholder="••••••">
              <button class="btn" style="margin-top:25px">Register</button>
            </form>
            <div style="text-align:center; margin-top:20px"><a href="/login" style="color:#94a3b8; font-size:14px">Already have an account? <span style="color:var(--primary)">Sign In</span></a></div>
          </div>
        </body></html>`, { headers: { 'Content-Type': 'text/html' }});
    }

    if (path === '/login' && request.method === 'GET') {
        if (currentUser) return Response.redirect(url.origin + '/dashboard', 302);
        return new Response(`<!doctype html><html><head><title>Login - VnameB</title><style>${COMMON_CSS} body{align-items:center;justify-content:center;}</style></head>
        <body>
          <div class="anim-bg"><div class="blob blob-1"></div><div class="blob blob-2"></div></div>
          <div class="glass-panel page-enter" style="width:400px">
            <h2 style="text-align:center; margin-bottom:10px;">Welcome Back</h2>
            <p style="text-align:center; color:#94a3b8; font-size:14px; margin-bottom:30px">Enter your credentials to manage your bio</p>
            <form method="POST" action="/api/login">
              <label style="font-size:12px; color:#cbd5e1">Email</label>
              <input type="email" name="email" required placeholder="mail@example.com">
              <label style="font-size:12px; color:#cbd5e1; margin-top:15px; display:block;">Password</label>
              <input type="password" name="password" required placeholder="••••••">
              <div style="text-align:right; margin-top:10px;">
                  <span style="color:#94a3b8; font-size:12px; cursor:pointer; transition:0.3s;" onmouseover="this.style.color='var(--primary)'" onmouseout="this.style.color='#94a3b8'" onclick="alert('Password reset has not been implemented yet.')">Forgot Password?</span>
              </div>
              <button class="btn" style="margin-top:20px">Sign In</button>
            </form>
            <div style="text-align:center; margin-top:20px; border-top:1px solid rgba(255,255,255,0.05); padding-top:20px">
              <a href="/register" style="color:#94a3b8; font-size:14px">Don't have an account? <span style="color:var(--primary)">Register</span></a>
            </div>
          </div>
        </body></html>`, { headers: { 'Content-Type': 'text/html' }});
    }

    if (path === '/api/register' && request.method === 'POST') {
        const formData = await request.formData();
        const handle = formData.get('handle').replace(/[^a-zA-Z0-9_]/g, ''); // Sadece harf, rakam ve alt tire
        const email = formData.get('email');
        const password = formData.get('password');
        
        const hashedPass = await hashPassword(password);
        const defaultSettings = JSON.stringify({ autoplay: true, showPlayer: true, showGlow: true, layout: 'standard', accentColor: '#3b82f6', linkColor: '#ffffff' });
        
        try {
            await env.DB.prepare("INSERT INTO users (handle, email, passwordHash, settings) VALUES (?, ?, ?, ?)").bind(handle, email, hashedPass, defaultSettings).run();
            return Response.redirect(url.origin + '/login', 302);
        } catch (e) { 
            return new Response("Handle or Email already exists. Please try another.", { status: 400 }); 
        }
    }

    if (path === '/api/login' && request.method === 'POST') {
        const formData = await request.formData();
        const email = formData.get('email');
        const password = formData.get('password');
        
        const hashedPass = await hashPassword(password);
        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        
        if (user && user.passwordHash === hashedPass) {
            const token = crypto.randomUUID();
            await env.DB.prepare("UPDATE users SET sessionToken = ? WHERE id = ?").bind(token, user.id).run();
            return new Response(null, { status: 302, headers: { 'Location': '/dashboard', 'Set-Cookie': `session_token=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax` }});
        }
        return new Response("Invalid email or password", { status: 401 });
    }

    if (path === '/logout') {
        return new Response(null, { status: 302, headers: { 'Location': '/', 'Set-Cookie': `session_token=; HttpOnly; Path=/; Max-Age=0` }});
    }

    // ==========================================
    // 3. DASHBOARD (AJAX POWERED)
    // ==========================================
    if (path === '/dashboard' && request.method === 'GET') {
        if (!currentUser) return Response.redirect(url.origin + '/login', 302);
        
        const s = currentUser.settings ? JSON.parse(currentUser.settings) : {};

        return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Dashboard - VnameB</title>
        <style>
          ${COMMON_CSS}
          .layout{display:grid;grid-template-columns:260px 1fr;gap:40px;max-width:1200px;margin:40px auto;width:95%;position:relative;z-index:10} 
          .nav-item{display:block;padding:15px;border-radius:12px;color:#94a3b8;margin-bottom:8px;cursor:pointer;font-weight:500;transition:0.2s} 
          .nav-item:hover{background:rgba(255,255,255,0.05);color:white}
          .nav-item.active{background:var(--primary);color:white;box-shadow:0 4px 12px rgba(59, 130, 246, 0.3)} 
          .section{display:none;opacity:0;transform:translateY(10px)} 
          .section.active{display:block;animation:tabFadeIn 0.4s cubic-bezier(0.2, 0.8, 0.2, 1) forwards} 
          @keyframes tabFadeIn{to{opacity:1;transform:translateY(0)}}
          .col-2{display:grid;grid-template-columns:1fr 1fr;gap:20px} 
          label{font-size:13px;color:#cbd5e1;font-weight:600;display:block;margin-bottom:5px}
        </style></head>
        <body>
          <div class="anim-bg"><div class="blob blob-1"></div><div class="blob blob-2"></div></div>
          <div id="toast">Saved successfully!</div>

          <div class="layout page-enter">
            <div>
              <div style="background: linear-gradient(45deg, var(--primary), #60a5fa); padding: 20px; border-radius: 16px; margin-bottom: 30px; color: white; font-weight: bold; font-size: 18px; word-break: break-all;">/${escapeHtml(currentUser.handle)}</div>
              <div class="nav-item active" onclick="show('profile', this)">Profile Details</div>
              <div class="nav-item" onclick="show('settings', this)">Card Settings</div>
              <a href="/${currentUser.handle}" target="_blank" class="nav-item" style="color:#4ade80;margin-top:20px"><i class="fas fa-external-link-alt"></i> View Live Site</a>
              <a href="/logout" class="nav-item" style="color:#ef4444;margin-top:10px"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>

            <div class="glass-panel">
              
              <div id="profile" class="section active">
                <h2 style="margin-top:0">Profile Details</h2>
                <form class="ajax-form" data-type="profile">
                  <div class="col-2">
                      <div><label>Display Name</label><input name="name" value="${escapeHtml(currentUser.name||'')}" placeholder="Your Display Name"></div>
                      <div>
                          <label>Biography</label>
                          <textarea name="bio" rows="3" placeholder="Tell them about you...">${escapeHtml(currentUser.bio||'')}</textarea>
                      </div>
                  </div>
                  <div style="margin-top:20px">
                      <label>Avatar URL (Base64 or Image Link)</label>
                      <input name="avatar" value="${escapeHtml(currentUser.avatar||'')}" placeholder="https://...">
                      <p style="font-size:11px; color:#64748b; margin-top:5px;">File uploads directly to DB are disabled to prevent server crash. Paste image URL here.</p>
                  </div>
                  <button type="submit" class="btn" style="margin-top:20px">Save Profile</button>
                </form>
              </div>

              <div id="settings" class="section">
                <h2 style="margin-top:0">Card Settings</h2>
                <form class="ajax-form" data-type="settings">
                  
                  <div class="col-2" style="margin-bottom: 20px;">
                    <div><label>UI Layout</label><select name="layout" style="background:#0f172a"><option value="standard" ${s.layout==='standard'?'selected':''}>Standard (Vertical)</option><option value="wide" ${s.layout==='wide'?'selected':''}>Wide (Horizontal)</option></select></div>
                    <div><label>Accent Color</label><input type="color" name="accentColor" value="${s.accentColor || '#3b82f6'}" style="height:45px; padding:0; cursor:pointer;"></div>
                  </div>

                  <div class="switch-row"><div><label style="margin:0">Show Music Player</label></div><label class="switch"><input type="checkbox" name="showPlayer" ${s.showPlayer?'checked':''}><span class="slider"></span></label></div>
                  <div class="switch-row"><div><label style="margin:0">Click-to-Enter Overlay</label></div><label class="switch"><input type="checkbox" name="autoplay" ${s.autoplay?'checked':''}><span class="slider"></span></label></div>
                  <div class="switch-row"><div><label style="margin:0">Rain Effect</label></div><label class="switch"><input type="checkbox" name="showRain" ${s.showRain?'checked':''}><span class="slider"></span></label></div>
                  <div class="switch-row"><div><label style="margin:0">Mouse Click Ripple Effect</label></div><label class="switch"><input type="checkbox" name="clickEffect" ${s.clickEffect?'checked':''}><span class="slider"></span></label></div>

                  <button type="submit" class="btn" style="margin-top:20px">Save Settings</button>
                </form>
              </div>

            </div>
          </div>

          <script>
            // TAB SWITCHING
            function show(id, el) {
                document.querySelectorAll('.section').forEach(d => d.classList.remove('active'));
                document.getElementById(id).classList.add('active');
                document.querySelectorAll('.nav-item').forEach(d => d.classList.remove('active'));
                el.classList.add('active');
            }

            // TOAST SYSTEM
            function showToast(msg, isError = false) {
                const t = document.getElementById('toast');
                t.innerText = msg;
                if(isError) t.classList.add('error'); else t.classList.remove('error');
                t.classList.add('show');
                setTimeout(() => t.classList.remove('show'), 3000);
            }

            // AJAX FORM SUBMISSION
            document.querySelectorAll('.ajax-form').forEach(form => {
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const btn = form.querySelector('button');
                    const origTxt = btn.innerText;
                    btn.innerText = 'Saving...';
                    btn.disabled = true;
                    
                    const formData = new FormData(form);
                    formData.append('updateType', form.getAttribute('data-type'));

                    try {
                        const res = await fetch('/api/update', { method: 'POST', body: formData });
                        if(res.ok) showToast('Changes saved successfully!');
                        else showToast('Failed to save changes.', true);
                    } catch(err) {
                        showToast('Network error occurred.', true);
                    }
                    
                    btn.innerText = origTxt;
                    btn.disabled = false;
                });
            });
          </script>
        </body></html>`, { headers: { 'Content-Type': 'text/html' }});
    }

    // ==========================================
    // 4. API: AJAX UPDATE ENDPOINT
    // ==========================================
    if (path === '/api/update' && request.method === 'POST') {
        if (!currentUser) return new Response("Unauthorized", { status: 401 });
        
        const formData = await request.formData();
        const updateType = formData.get('updateType');
        
        try {
            if (updateType === 'profile') {
                const name = formData.get('name') || '';
                const bio = formData.get('bio') || '';
                const avatar = formData.get('avatar') || '';
                await env.DB.prepare("UPDATE users SET name = ?, bio = ?, avatar = ? WHERE id = ?").bind(name, bio, avatar, currentUser.id).run();
            } 
            else if (updateType === 'settings') {
                let currentSettings = currentUser.settings ? JSON.parse(currentUser.settings) : {};
                currentSettings.layout = formData.get('layout') || 'standard';
                currentSettings.accentColor = formData.get('accentColor') || '#3b82f6';
                currentSettings.showPlayer = formData.get('showPlayer') === 'on';
                currentSettings.autoplay = formData.get('autoplay') === 'on';
                currentSettings.showRain = formData.get('showRain') === 'on';
                currentSettings.clickEffect = formData.get('clickEffect') === 'on';
                
                await env.DB.prepare("UPDATE users SET settings = ? WHERE id = ?").bind(JSON.stringify(currentSettings), currentUser.id).run();
            }
            return new Response("OK", { status: 200 });
        } catch (error) {
            return new Response("Update failed", { status: 500 });
        }
    }

    // ==========================================
    // 5. PUBLIC PROFILE PAGE (/:handle)
    // ==========================================
    const handleMatch = path.match(/^\/([a-zA-Z0-9_]+)$/);
    if (handleMatch && request.method === 'GET') {
        const handle = handleMatch[1];
        
        // Reserved routes bypass
        if(['login', 'register', 'dashboard', 'logout', 'api'].includes(handle.toLowerCase())) {
            return new Response("Not Found", { status: 404 });
        }

        const user = await env.DB.prepare("SELECT * FROM users WHERE handle = ?").bind(handle).first();
        if (!user) return new Response("User not found", { status: 404 });

        const s = user.settings ? JSON.parse(user.settings) : { accentColor: '#3b82f6', layout: 'standard' };
        
        return new Response(`<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${escapeHtml(user.name || user.handle)}</title>
        <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
          :root { --accent: ${s.accentColor}; }
          body,html{margin:0;padding:0;height:100%;overflow:hidden;font-family:'Outfit',sans-serif;background:#000;color:white}
          #bg-layer{position:absolute;inset:0;z-index:0; background: radial-gradient(circle at center, #1e293b 0%, #0f172a 100%);}
          
          #click-overlay{position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.5);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:opacity 0.8s, visibility 0.8s} 
          #click-overlay.hidden{opacity:0;visibility:hidden;} 
          .click-text{font-size:14px;letter-spacing:3px;text-transform:uppercase;animation:pulse 2s infinite;opacity:0.8}
          
          #stage{position:relative;z-index:10;height:100%;display:flex;align-items:center;justify-content:center;} 
          .card{background:rgba(255,255,255,0.1);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.08);border-radius:24px;overflow:hidden; box-shadow:0 0 50px -10px var(--accent); padding: 40px; text-align:center; width: 350px;}
          
          .avatar{width:120px;height:120px;border-radius:50%;object-fit:cover; border: 3px solid var(--accent); margin-bottom:20px;}
          .name{font-size:24px;font-weight:700;margin-bottom:10px; text-shadow:0 0 10px var(--accent);}
          .bio{font-size:14px;color:#cbd5e1;line-height:1.5; white-space:pre-wrap;}
          
          .rain-container { position: absolute; inset: 0; z-index: 2; pointer-events: none; overflow: hidden; }
          .drop { position: absolute; width: 1px; height: 60px; background: linear-gradient(transparent, rgba(255,255,255,0.8)); top: -100px; animation: fall linear forwards; }
          @keyframes fall { to { transform: translateY(120vh); } }
          @keyframes pulse{0%{opacity:0.4}50%{opacity:1}100%{opacity:0.4}}
        </style></head>
        <body>
          ${s.autoplay ? `<div id="click-overlay"><div class="click-text">Click to Enter</div></div>` : ''}
          
          <div id="bg-layer">
              ${s.showRain ? '<div class="rain-container" id="rainBox"></div>' : ''}
          </div>

          <div id="stage">
            <div class="card">
              <img src="${user.avatar || 'https://via.placeholder.com/150/111'}" class="avatar">
              <div class="name">${escapeHtml(user.name || user.handle)}</div>
              <div class="bio">${escapeHtml(user.bio || 'Welcome to my profile.')}</div>
            </div>
          </div>

          <script>
            document.addEventListener('DOMContentLoaded', () => {
                const overlay = document.getElementById('click-overlay');
                if (${s.autoplay}) {
                    document.addEventListener('click', () => {
                        if (overlay) overlay.classList.add('hidden');
                    });
                }
                
                // Rain Effect Generator
                const rainBox = document.getElementById('rainBox');
                if (rainBox) {
                  setInterval(() => {
                    const d = document.createElement('div'); d.className='drop';
                    d.style.left = Math.random()*100+'vw';
                    const duration = Math.random() * 0.5 + 0.5;
                    d.style.animationDuration = duration + 's';
                    rainBox.appendChild(d); 
                    setTimeout(()=>d.remove(), duration * 1000);
                  }, 40);
                }
            });
          </script>
        </body></html>`, { headers: { 'Content-Type': 'text/html' }});
    }

    // Default Fallback
    return new Response("Endpoint Not Found", { status: 404 });
  }
};