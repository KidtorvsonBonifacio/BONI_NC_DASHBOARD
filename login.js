const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');

if (registerBtn && container){
    registerBtn.addEventListener('click', () => {
        container.classList.add("active");
    });
}

if (loginBtn && container){
    loginBtn.addEventListener('click', () => {
        container.classList.remove("active");
    });
}

 
// Sign In / Sign Up front-end logic
const signInForm = document.querySelector('.form-container.sign-in form');
const signUpForm = document.querySelector('.form-container.sign-up form');

function ensureErrorEl(form){
    let err = form.querySelector('.form-error');
    if (!err){
        err = document.createElement('div');
        err.className = 'form-error';
        form.insertBefore(err, form.querySelector('button'));
    }
    return err;
}

function ensureSuccessEl(form){
    let el = form.querySelector('.form-success');
    if (!el){
        el = document.createElement('div');
        el.className = 'form-success';
        form.insertBefore(el, form.querySelector('button'));
    }
    return el;
}

function showError(errEl, msg){
    if (!errEl) return;
    errEl.textContent = msg;
    errEl.classList.add('show');
}
function hideError(errEl){
    if (!errEl) return;
    errEl.textContent = '';
    errEl.classList.remove('show');
}

function showSuccess(el, msg){
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
}
function hideSuccess(el){
    if (!el) return;
    el.textContent = '';
    el.classList.remove('show');
}

// API base resolver: prefer Flask backend at 127.0.0.1:5000, fall back to same origin
const DEFAULT_BACKEND = 'http://127.0.0.1:5000';
const API_BASE = (function(){
    try{
        const host = window.location.hostname || '';
        // If running on localhost, prefer Flask on port 5000 on the same hostname
        if (host === '127.0.0.1' || host === 'localhost') return `${window.location.protocol}//${host}:5000`;
        // Otherwise, prefer the default local backend if reachable by the browser
        return DEFAULT_BACKEND; // fallback; postJSON will attempt relative origin on failure
    }catch(e){
        return DEFAULT_BACKEND;
    }
})();

// Detect if the app is served under a subpath (e.g. /NCAssessmentDashboard when using XAMPP)
const APP_ROOT = (function(){
    try{
        // Only treat a subpath as APP_ROOT when served over HTTP(S) (not file://)
        if (!window.location.protocol || !window.location.protocol.startsWith('http')) return '';
        const parts = (window.location.pathname || '').split('/');
        // parts: ['', 'NCAssessmentDashboard', 'login', ...]
        if (parts.length > 1 && parts[1]) return '/' + parts[1];
        return '';
    }catch(e){
        return '';
    }
})();

async function postJSON(url, payload){
    // If no url or not API route, just post to url
    if (!url) return { ok:false, status:0, json:null, error: new Error('no url') };
    // Treat any path that contains /api/ as an API route, including /php-auth/api
    const isApi = (url.startsWith('/') && url.indexOf('/api/') !== -1) || url.startsWith('/api');
    const targets = [];
    if (isApi){
        // attempt first to the API_BASE (defaults to 127.0.0.1:5000), then fallback to relative path
        // Try targets in order: prefer app-root (XAMPP/subpath) first, then API_BASE (flask dev), then raw url
        if (APP_ROOT) targets.push(APP_ROOT + url);
        targets.push((API_BASE || DEFAULT_BACKEND) + url);
        targets.push(url);
    } else {
        targets.push(url);
    }

    let lastErr = null;
    for (const t of targets){
        try{
            const res = await fetch(t, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            // Try to parse JSON; if parsing fails, capture the raw text for debugging
            let json = null;
            let text = null;
            try{ text = await res.text(); }catch(e){ text = null; }
            try{ json = text ? JSON.parse(text) : null; }catch(e){ json = null; }
            // If request successful, return immediately
            if (res.ok) return { ok: res.ok, status: res.status, json, text, target: t };
            // If this is an API target and we got a 404, 405 (method not allowed from static host),
            // or 5xx server error, try the next fallback target.
            if (isApi && (res.status === 404 || res.status === 405 || res.status >= 500)){
                console.warn('postJSON: non-ok status, trying next target:', t, res.status);
                lastErr = new Error('non-ok status: ' + res.status);
                // try next target
                continue;
            }
            // Otherwise return the response as-is (e.g., 400, 401, 409 client errors)
            return { ok: res.ok, status: res.status, json, text, target: t };
        }catch(e){
            lastErr = e;
            // try next target
            console.warn('postJSON target failed, trying next:', t, e);
            continue;
        }
    }
    return { ok: false, status: 0, json: null, error: lastErr };
}

// Sign In handler
if (signInForm){
    const errEl = ensureErrorEl(signInForm);
    signInForm.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        hideError(errEl);
        hideSuccess(ensureSuccessEl(signInForm));
        const emailInput = signInForm.querySelector('input[type="email"]');
        const passInput = signInForm.querySelector('input[type="password"]');
        const email = emailInput ? emailInput.value.trim() : '';
        const password = passInput ? passInput.value : '';

        if (!email || !password){
            showError(errEl, 'Please enter your email and password.');
            return;
        }

        // Disable button to prevent double submits
        const submitBtn = signInForm.querySelector('button');
        if (submitBtn) submitBtn.disabled = true;

        // Try the Flask backend login endpoint first (better for local dev),
        // falling back to PHP if needed is handled by postJSON targets.
        const res = await postJSON('/api/login', { email, password });

        if (submitBtn) submitBtn.disabled = false;

        if (!res.ok){
            console.warn('Login response not ok:', res);
            console.warn('Registration response not ok:', res);
            if (!res || res.status === 0 || res.error){
                console.warn('Network error during login:', res.error || res);
                console.warn('Network error during registration:', res.error || res);
                showError(errEl, 'Login service not reachable (check backend)');
                return;
            }
            // network errors or fetch exceptions
            if (!res || res.status === 0 || res.error){
                showError(errEl, 'Registration service not reachable (check backend)');
                return;
            }
            if (res.status === 401){
                showError(errEl, 'Invalid email or password');
            } else if (res.status === 404){
                showError(errEl, 'Login service unavailable (no backend route)');
            } else if (res.json && res.json.error){
                showError(errEl, res.json.error + (res.json.details ? '\nDetails: '+res.json.details : ''));
                    console.error('Login error response:', res.json, 'target:', res.target);
            } else if (res.text){
                showError(errEl, res.text);
                    console.error('Login error text response:', res.text, 'target:', res.target);
            } else {
                showError(errEl, 'Login failed. Please try again.');
            }
            return;
        }

        // Successful login. Store token and role if provided, show feedback and redirect.
        if (res.json){
            if (res.json.token) try{ localStorage.setItem('authToken', res.json.token); }catch(e){}
            if (res.json.role) try{ localStorage.setItem('authRole', res.json.role); }catch(e){}
            // fallback: store user role if nested in 'user' object
            if (!res.json.role && res.json.user && res.json.user.role) try{ localStorage.setItem('authRole', res.json.user.role); }catch(e){}
        }
        const successEl = ensureSuccessEl(signInForm);
        hideError(errEl);
        hideSuccess(ensureSuccessEl(signUpForm));
        const name = res.json && (res.json.name || res.json.full_name || (res.json.user && res.json.user.full_name));
        showSuccess(successEl, name ? `Welcome ${name}! Redirecting...` : 'Login successful. Redirecting...');
        const role = (res.json && (res.json.role || (res.json.user && res.json.user.role))) || null;
        const serverRedirect = res.json && res.json.redirect ? res.json.redirect : null;
        setTimeout(()=>{
            if (serverRedirect) {
                window.location.href = serverRedirect;
                return;
            }
            if (role === 'super_admin') window.location.href = '/dashboard_super';
            else if (role === 'admin') window.location.href = '/dashboard_admin';
            else window.location.href = '../nc-frontend/index.html';
        }, 900);
    });
}

// Sign Up handler
if (signUpForm){
    const errEl = ensureErrorEl(signUpForm);
    const pwStrengthEl = document.getElementById('signup-pw-strength');
    const roleSelect = signUpForm.querySelector('#signup-role');
    const adminKeyInput = signUpForm.querySelector('#signup-adminkey');

    function checkPasswordStrength(pw){
        let score = 0;
        const tests = {
            length: pw.length >= 8,
            lower: /[a-z]/.test(pw),
            upper: /[A-Z]/.test(pw),
            digit: /[0-9]/.test(pw),
            special: /[^A-Za-z0-9]/.test(pw)
        };
        Object.values(tests).forEach(v => { if (v) score++; });
        let label = 'Weak';
        if (score >= 4) label = 'Strong';
        else if (score === 3) label = 'Medium';
        return { score, label, tests };
    }

    // Update strength UI while typing
    const pwInput = document.getElementById('signup-password');
    if (pwInput && pwStrengthEl){
        pwInput.addEventListener('input', () => {
            const v = pwInput.value || '';
            const s = checkPasswordStrength(v);
            pwStrengthEl.classList.remove('weak','medium','strong');
            if (s.score >= 4) {
                pwStrengthEl.classList.add('strong');
                pwStrengthEl.textContent = 'Strong';
            }
            else if (s.score === 3) {
                pwStrengthEl.classList.add('medium');
                pwStrengthEl.textContent = 'Medium';
            }
            else {
                pwStrengthEl.classList.add('weak');
                const missing = [];
                if (!s.tests.length) missing.push('8+ characters');
                if (!s.tests.upper) missing.push('an uppercase letter');
                if (!s.tests.lower) missing.push('a lowercase letter');
                if (!s.tests.digit) missing.push('a number');
                if (!s.tests.special) missing.push('a special character');
                pwStrengthEl.textContent = `Weak — missing: ${missing.join(', ')}`;
            }
        });
    }

    if (roleSelect && adminKeyInput){
        // show/hide admin key when role changes
        const updateAdminKeyVisibility = () => {
            if (roleSelect.value === 'admin'){
                adminKeyInput.classList.add('show');
            } else {
                adminKeyInput.classList.remove('show');
            }
        };
        roleSelect.addEventListener('change', updateAdminKeyVisibility);
        // initialize on load
        updateAdminKeyVisibility();
    }
    signUpForm.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        hideError(errEl);
        const inputs = signUpForm.querySelectorAll('input');
        const fullName = inputs[0] ? inputs[0].value.trim() : '';
        const email = document.getElementById('signup-email') ? document.getElementById('signup-email').value.trim() : (inputs[1] ? inputs[1].value.trim() : '');
        const password = document.getElementById('signup-password') ? document.getElementById('signup-password').value : (inputs[2] ? inputs[2].value : '');
        const role = roleSelect ? (roleSelect.value || 'user') : 'user';
        const adminKey = adminKeyInput ? (adminKeyInput.value || '').trim() : '';

        if (!fullName || !email || !password){
            showError(errEl, 'Please fill in all fields.');
            return;
        }

        // basic email regex
        const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRe.test(email)){
            showError(errEl, 'Please enter a valid email address.');
            return;
        }

        if (password.length < 8){
            showError(errEl, 'Password must be at least 8 characters long.');
            return;
        }

        // Check password strength; require at least 'medium' (score >= 3 /5)
        const strength = checkPasswordStrength(password);
        if (strength.score < 3){
            showError(errEl, 'Password is too weak. Use uppercase, lowercase, numbers, and special characters.');
            return;
        }

        if (role === 'admin' && !adminKey){
            showError(errEl, 'Admin key is required when creating an admin account.');
            return;
        }

        const submitBtn = signUpForm.querySelector('button');
        if (submitBtn) submitBtn.disabled = true;

        // include role and admin key in payload; use /api/register for admin accounts
        const payload = { fullName, email, password, role };
        if (role === 'admin') payload.adminKey = adminKey;
        // Prefer Flask /api/register which will save to configured DB (MySQL/XAMPP when configured).
        const res = await postJSON('/api/register', payload);

        if (submitBtn) submitBtn.disabled = false;

        if (!res.ok){
            if (res.status === 409){
                showError(errEl, 'An account with this email already exists.');
            } else if (res.status === 404){
                showError(errEl, 'Registration service unavailable (no backend route)');
            } else if (res.json && res.json.error){
                showError(errEl, res.json.error + (res.json.details ? '\nDetails: '+res.json.details : ''));
                console.error('Registration error response:', res.json, 'target:', res.target);
            } else if (res.text){
                showError(errEl, res.text);
                console.error('Registration error text response:', res.text, 'target:', res.target);
            } else {
                // Provide more diagnostic info for network/fallback problems
                const errMsg = `Registration failed (status=${res.status || 0})` + (res.error ? `: ${res.error.message || res.error}` : '') + (res.target ? ` — target: ${res.target}` : '');
                showError(errEl, errMsg + '\nSee console for details.');
                console.error('Registration failure details:', res);
            }
            return;
        }

        // Successful account creation — store token and role if provided.
        if (res.json){
            if (res.json.token) try{ localStorage.setItem('authToken', res.json.token); }catch(e){}
            if (res.json.role) try{ localStorage.setItem('authRole', res.json.role); }catch(e){}
            if (!res.json.role && res.json.user && res.json.user.role) try{ localStorage.setItem('authRole', res.json.user.role); }catch(e){}
        }

        // Show success and redirect accordingly
        hideError(errEl);
        const successEl = ensureSuccessEl(signUpForm);
        // prefer explicit role value from form, fallback to response
        const finalRole = role || (res.json && (res.json.role || (res.json.user && res.json.user.role)));
        const serverRedirect = res.json && res.json.redirect ? res.json.redirect : null;
        showSuccess(successEl, 'Registration successful! Redirecting...');
        if (serverRedirect) {
            setTimeout(()=> window.location.href = serverRedirect, 900);
            return;
        }
        if (finalRole === 'admin'){
            setTimeout(()=> window.location.href = '/dashboard_admin', 900);
            return;
        }
        setTimeout(()=> window.location.href = '../nc-frontend/index.html', 900);
    });
}