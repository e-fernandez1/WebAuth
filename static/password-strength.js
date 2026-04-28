(function () {
    const COMMON = new Set([
        "password", "password123", "qwerty123", "letmein123", "iloveyou123",
        "admin1234567", "welcome12345", "monkey123456", "dragon123456",
    ]);

    const input = document.getElementById('password');
    if (!input) return;

    function bytesToHumanTime(seconds) {
        if (!isFinite(seconds)) return 'instantly';
        const minute = 60, hour = 3600, day = 86400, year = 31536000;
        if (seconds < 1) return 'less than a second';
        if (seconds < minute) return Math.round(seconds) + ' seconds';
        if (seconds < hour) return Math.round(seconds / minute) + ' minutes';
        if (seconds < day) return Math.round(seconds / hour) + ' hours';
        if (seconds < year) return Math.round(seconds / day) + ' days';
        if (seconds < year * 1000) return Math.round(seconds / year) + ' years';
        if (seconds < year * 1e6) return Math.round(seconds / year / 1000) + ' thousand years';
        if (seconds < year * 1e9) return Math.round(seconds / year / 1e6) + ' million years';
        return 'centuries';
    }

    function update() {
        const pw = input.value;
        const len = pw.length;
        const hasUpper = /[A-Z]/.test(pw);
        const hasLower = /[a-z]/.test(pw);
        const hasDigit = /\d/.test(pw);
        const hasSymbol = /[^A-Za-z0-9]/.test(pw);
        const isCommon = COMMON.has(pw.toLowerCase());

        setRule('rule-length', len >= 12);
        setRule('rule-upper', hasUpper);
        setRule('rule-lower', hasLower);
        setRule('rule-digit', hasDigit);
        setRule('rule-symbol', hasSymbol);
        setRule('rule-common', !isCommon && len > 0);

        let charset = 0;
        if (hasUpper) charset += 26;
        if (hasLower) charset += 26;
        if (hasDigit) charset += 10;
        if (hasSymbol) charset += 32;
        const entropy = len > 0 && charset > 0 ? len * Math.log2(charset) : 0;

        document.getElementById('entropy').textContent = entropy.toFixed(1);

        // bcrypt at cost 12 ≈ ~5 hashes/sec on commodity hardware (~0.2s per hash)
        const guesses = Math.pow(2, entropy) / 2;
        const seconds = guesses / 5;
        document.getElementById('crack-time').textContent = entropy === 0 ? '—' : bytesToHumanTime(seconds);

        const score = Math.min(100, entropy * 1.4);
        const bar = document.getElementById('strength-bar');
        bar.style.width = score + '%';
        bar.className = 'progress-bar ' +
            (score < 30 ? 'bg-danger' : score < 60 ? 'bg-warning' : score < 85 ? 'bg-info' : 'bg-success');
    }

    function setRule(id, ok) {
        const el = document.getElementById(id);
        if (!el) return;
        if (ok) {
            el.classList.remove('text-muted');
            el.classList.add('text-success');
            el.textContent = '✓' + el.textContent.slice(1);
        } else {
            el.classList.add('text-muted');
            el.classList.remove('text-success');
            el.textContent = '○' + el.textContent.slice(1);
        }
    }

    input.addEventListener('input', update);
    update();
})();
