document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    const modeSelect = document.getElementById('mode');
    const proxyGroup = document.getElementById('proxyGroup');
    const cmdPreview = document.getElementById('cmdPreview');
    const termOutput = document.getElementById('termOutput');
    const btnScan = document.getElementById('btnScan');
    const btnCancel = document.getElementById('btnCancel');
    
    let eventSource = null;

    // Toggle Proxy Field based on mode
    modeSelect.addEventListener('change', (e) => {
        if (e.target.value === 'proxy') {
            proxyGroup.style.display = 'block';
            // Add slight animation
            proxyGroup.style.animation = 'none';
            proxyGroup.offsetHeight; // trigger reflow
            proxyGroup.style.animation = 'slideIn 0.3s ease-out forwards';
        } else {
            proxyGroup.style.display = 'none';
        }
        updateCommandPreview();
    });

    // Update Command Preview on input change
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
        input.addEventListener('input', updateCommandPreview);
    });

    function updateCommandPreview() {
        const target = document.getElementById('target').value.trim().split('\n').join(',');
        const mode = document.getElementById('mode').value;
        const ports = document.getElementById('ports').value.trim();
        const threads = document.getElementById('threads').value;
        const method = document.getElementById('method').value.trim();
        const proxy = document.getElementById('proxy').value.trim();

        let cmd = `python3 scanner.py -m ${mode} -p ${ports} -T ${threads} -M ${method}`;
        
        if (proxy && mode === 'proxy') {
            cmd += ` -P ${proxy}`;
        }

        if (target.includes('/')) {
            cmd += ` -c ${target}`;
        } else if (target) {
            cmd += ` -f targets.txt`; // Simplification for UI
        }

        cmdPreview.textContent = cmd;
    }

    // Initial command preview update
    updateCommandPreview();


    // Helper to append lines to console
    function appendTerminal(text, type = 'normal') {
        const div = document.createElement('div');
        div.className = `term-line ${type}`;
        
        // Very basic rudimentary color parsing since we stripped ANSI server side, 
        // we can stylize based on keywords if we wanted to. Let's just output text for now.
        div.textContent = text;
        
        termOutput.appendChild(div);
        
        // Auto scroll
        termOutput.scrollTop = termOutput.scrollHeight;
    }

    // Form Submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        if (eventSource) {
            eventSource.close();
        }

        // UI State
        btnScan.classList.add('scanning');
        btnScan.disabled = true;
        btnCancel.style.display = 'block';
        
        const formData = {
            target: document.getElementById('target').value.trim(),
            mode: document.getElementById('mode').value,
            ports: document.getElementById('ports').value.trim(),
            threads: document.getElementById('threads').value,
            method: document.getElementById('method').value.trim(),
            proxy: document.getElementById('proxy').value.trim()
        };

        termOutput.innerHTML = '';
        appendTerminal('Initializing scan sequence...', 'scan-info');
        
        try {
            // First, post the parameters to start the scan and get the SSE stream URL/response
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            // Since fetch doesn't natively support SSE streams easily without manually polling chunks,
            // we will read the response stream chunks
            const reader = response.body.getReader();
            const decoder = new TextDecoder('utf-8');
            
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                buffer += decoder.decode(value, { stream: true });
                
                // Process lines from SSE format: `data: {"type": ..., "text": ...}\n\n`
                let doubleNewlineIndex;
                while ((doubleNewlineIndex = buffer.indexOf('\n\n')) >= 0) {
                    const chunk = buffer.slice(0, doubleNewlineIndex);
                    buffer = buffer.slice(doubleNewlineIndex + 2);
                    
                    if (chunk.startsWith('data: ')) {
                        const dataStr = chunk.slice(6);
                        try {
                            const data = JSON.parse(dataStr);
                            
                            if (data.type === 'info') {
                                appendTerminal(data.text, 'scan-info');
                            } else if (data.type === 'cmd') {
                                appendTerminal(data.text, 'scan-info');
                            } else {
                                appendTerminal(data.text);
                            }
                            
                            if (data.text.includes('Scan complete')) {
                                resetUI();
                            }
                        } catch (err) {
                            console.error("Parse error chunk:", dataStr);
                        }
                    }
                }
            }

            resetUI();
            
        } catch (error) {
            appendTerminal(`Error initiating scan: ${error.message}`, 'error');
            resetUI();
        }
    });

    btnCancel.addEventListener('click', () => {
        if (eventSource) {
            eventSource.close();
        }
        appendTerminal('Scan cancelled by user.', 'error');
        resetUI();
        // Since we are reading stream locally via fetch, aborting isn't fully wired here, 
        // to properly abort in python backend we'd need another endpoint. 
        // For visual, this resets UI.
    });

    function resetUI() {
        btnScan.classList.remove('scanning');
        btnScan.disabled = false;
        btnCancel.style.display = 'none';
        appendTerminal('--- Scan workflow terminated ---', 'scan-info');
    }
});
