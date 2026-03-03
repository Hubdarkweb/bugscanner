from flask import Flask, render_template, request, Response
import os
import tempfile
import runner

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    # Extract form data
    data = request.json
    mode = data.get('mode', 'direct')
    target = data.get('target', '')
    ports = data.get('ports', '80')
    threads = data.get('threads', '25')
    method_list = data.get('method', 'head')
    proxy = data.get('proxy', '')
    import sys
    args = [sys.executable, 'scanner.py', '-m', mode, '-p', ports, '-T', str(threads), '-M', method_list]

    if proxy:
        args.extend(['-P', proxy])

    target_is_cidr = '/' in target
    if target_is_cidr:
        args.extend(['-c', target])
        return Response(stream_scan(args), mimetype='text/event-stream')
    else:
        # Create a temporary file to hold the targets for the script
        fd, temp_path = tempfile.mkstemp(text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(target.replace(',', '\n'))
        
        args.extend(['-f', temp_path])
        return Response(stream_scan(args, temp_path), mimetype='text/event-stream')


def stream_scan(args, temp_file_path=None):
    """Generator to stream output back to the client via SSE."""
    # Send an initial message
    yield "data: {\"type\": \"info\", \"text\": \"Starting scan...\"}\n\n"
    yield f"data: {{\"type\": \"cmd\", \"text\": \"Command: {' '.join(args)}\"}}\n\n"

    try:
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        for line in runner.run_scan(args):
            clean_line = ansi_escape.sub('', line).strip('\r\n')
            if clean_line:
                # Need to properly escape newlines/quotes for JSON within SSE
                import json
                payload = json.dumps({"type": "output", "text": line}) # send raw line to keep formatting logic maybe on frontend? Actually send clean
                payload_clean = json.dumps({"type": "output", "text": clean_line})
                # Using the raw line lets us keep the spacing but strips colors, wait, if we want colors we need front-end ANSI parsing. 
                # Let's send the clean line for now, or just the raw line and let front end figure it out. Data must contain no native newlines.
                yield f"data: {payload_clean}\n\n"
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
    
    yield "data: {\"type\": \"info\", \"text\": \"Scan complete.\"}\n\n"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
