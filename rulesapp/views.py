from django.shortcuts import render
from .forms import RuleEntryForm
import os
import random
import logging

# Initialize the logger
logger = logging.getLogger('django')

# Paths for storage files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SID_FILE = os.path.join(BASE_DIR, 'runtime_files', 'used_sids.txt')
RULES_FILE = os.path.join(BASE_DIR, 'runtime_files', 'generated_firewall_rules.rules')
LOG_FILE = os.path.join(BASE_DIR, 'runtime_files', 'firewall_rule_generator.log')

def get_unique_sid():
    """Generate a unique, non-overlapping SID."""
    if os.path.exists(SID_FILE):
        with open(SID_FILE, 'r') as file:
            used_sids = {int(line.strip()) for line in file}
    else:
        used_sids = set()

    while True:
        sid = random.randint(1000001, 9999999)
        if sid not in used_sids:
            break

    with open(SID_FILE, 'a') as file:
        file.write(f"{sid}\n")

    logger.debug(f"Generated unique SID: {sid}")
    return sid


def generate_rules_view(request):
    logger.info(f"Request received: {request.method} {request.path}")

    if request.method == 'POST':
        logger.info("Processing POST request")
        form = RuleEntryForm(request.POST)

        if form.is_valid():
            logger.info("Form is valid")
            # Extract and parse the form data
            action = form.cleaned_data['action']
            sources = form.cleaned_data['source']
            destinations = form.cleaned_data['destination']
            ports = form.cleaned_data['port']
            protocol = form.cleaned_data['protocol']

            logger.debug(f"Action: {action}, Sources: {sources}, Destinations: {destinations}, Ports: {ports}, Protocol: {protocol}")

            generated_rules = []
            with open(RULES_FILE, 'a') as file:
                for source in sources:
                    for destination in destinations:
                        for port in ports:
                            source = source.strip()
                            destination = destination.strip()
                            port = port.strip()

                            sid = get_unique_sid()
                            dynamic_msg = f"Rule for {protocol} traffic from {source} to {destination}:{port}"
                            suricata_rule = (
                                f"{action} {protocol.lower()} {source} any -> {destination} {port} "
                                f"(msg:\"{dynamic_msg}\"; sid:{sid};)"
                            )

                            logger.debug(f"Generated rule: {suricata_rule}")
                            generated_rules.append(suricata_rule)
                            file.write(suricata_rule + '\n')

            logger.info(f"Generated {len(generated_rules)} rules")
            return render(request, 'rulesapp/rules_output.html', {'rules': generated_rules})
        else:
            logger.warning("Form is invalid")
    else:
        logger.info("Processing GET request")
        form = RuleEntryForm()

    return render(request, 'rulesapp/rules_form.html', {'form': form})

