from flask import Flask, request, jsonify
import subprocess
import re

app = Flask(__name__)


def get_dns_trace(domain):
    """Executes dig +trace and returns the output as text."""
    try:
        process = subprocess.run(['dig', '+trace', '@1.1.1.1', '-4', domain], capture_output=True, text=True, check=True)
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running dig: {e}")
        return None

def parse_dig_output(dig_output):
    """Parses dig +trace output and extracts DNS server IPs and steps."""
    steps = []
    lines = dig_output.splitlines()
    current_resolver = None
    for line in lines:
        line = line.strip()
        if line.startswith(";; SERVER:"):
            match = re.search(r"SERVER: (\S+)#", line)
            if match:
                current_resolver = match.group(1)
                steps.append({"type": "Query", "server": current_resolver, "query": "Initial Query"})
        elif line.startswith(";; Sending query to"):
            match = re.search(r"Sending query to (\S+)", line)
            if match:
                next_server = match.group(1)
                steps.append({"type": "Query", "server": next_server, "query": "Recursive Query"})
        elif ";; Got answer:" in line:
            pass  # Just an indicator, no server info here
        elif line.startswith(";; Received"):
            match = re.search(r"from (\S+)#", line)
            if match:
                server = match.group(1)
                # Try to infer the type of server based on keywords in previous lines
                server_type = "Intermediate Server"
                if any(".root-servers.net" in prev_line for prev_line in lines[:lines.index(line)]):
                    server_type = "Root Server"
                elif any(".tld" in prev_line.lower() or ".gtld-servers.net" in prev_line for prev_line in lines[:lines.index(line)]):
                    server_type = "TLD Server"
                elif any("ANSWER SECTION" in prev_line for prev_line in lines[:lines.index(line)]):
                    server_type = "Authoritative Server" # Might need refinement
                steps.append({"type": "Response", "server": server, "info": server_type})
        elif line.startswith(";; ANSWER SECTION:"):
            steps.append({"type": "Answer", "server": "Final Answer", "info": "See below"})
            break # Stop parsing after the answer for this basic version
    return steps


def parse_dig_output_own_func(dig_output):
    """Parses dig +trace output and extracts DNS server IPs and steps."""
    steps = {}
    lines = dig_output.splitlines()
    i = 0;
    for line in lines:
        line = line.strip()
        if line.startswith(";; Received"):
            pattern = r"#(\d+)\(([\w.-]+)\) in"
            match = re.search(pattern, line)

            if match:
                port = match.group(1)
                nameserver_name = match.group(2)
                ip_pattern = r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    ip_address = ip_match.group(1)
                    steps[i] = [ip_address, port, nameserver_name]
                    i = i+1
        elif  "IN\tA\t" in line:
            ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                steps["ip"] = ip_match.group(1)
                
    return steps


def visualize_dns_trace_text(steps, domain):
    """Prints the DNS trace in a text-based format."""

    print(f"\nDNS Resolution Path for: {domain}\n")
    ip = ""
    path = {}
    for step in steps:
        if (step == 0):
            print("DNS Resolver(" + steps[step][2] + ")", end = "----> ")
            path["DNS Resolver"] = steps[step][2]
        elif (step == "ip"):
            ip = steps[step]
        else:
            path[steps[step][2]] = steps[step][0]
            print(steps[step][2] + "(" + steps[step][0] + ")", end = "----> ")
    path[domain] = ip
    print(f"{domain}({ip})")
    return path


@app.route('/trace', methods=['GET'])
def dns_trace_endpoint():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Please provide a 'domain' parameter in the URL."}), 400

    dig_output = get_dns_trace(domain)

    if dig_output:
        dns_steps = parse_dig_output_own_func(dig_output)
        path = visualize_dns_trace_text(dns_steps, domain)
        print(path)
        return jsonify({domain: path}), 200
        # return jsonify({"domain": domain, "trace": dns_steps})
    else:
        return jsonify({"error": dig_output}), 500        


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8082) # Run the Flask development server
