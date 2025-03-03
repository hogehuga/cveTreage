import json
import os
from lib import vulnrich

# Load SSVC Decision Tree
def load_decision_tree(tree_name):
    tree_file = f'./decisionTree/{tree_name}.json'
    if os.path.exists(tree_file):
        with open(tree_file, 'r') as file:
            return json.load(file)
    else:
        raise FileNotFoundError(f"Decision tree file {tree_file} not found.")

# Perform SSVC decision
def ssvc_decision(cve_id, tree, mission_well_being=None, no_check_certificate=False):
    decision_points = vulnrich.ssvc(cve_id, no_check_certificate)
    exploitation, automatable, technical_impact = decision_points

    if mission_well_being:
        outcome = tree["exploitation"][exploitation]["automatable"][automatable]["technical_impact"][technical_impact][mission_well_being]
        return [(cve_id, outcome, exploitation, automatable, technical_impact, mission_well_being)]
    else:
        outcomes = []
        for mwb in ["low", "medium", "high"]:
            outcome = tree["exploitation"][exploitation]["automatable"][automatable]["technical_impact"][technical_impact][mwb]
            outcomes.append(outcome)
        return [(cve_id, "/".join(outcomes), exploitation, automatable, technical_impact)]

# Perform verbose SSVC decision
def verbose_ssvc_decision(cve_id, tree, mission_well_being=None, no_check_certificate=False):
    try:
        decision_points = vulnrich.verbose(cve_id, no_check_certificate)
        exploitation, automatable, technical_impact, severity, score, *_, vector_string, cwe, source = decision_points
    except vulnrich.CVSSv4OnlyException:
        severity = "N/A"
        score = "N/A"
        vector_string = "N/A"
        source = "N/A"
        decision_points = vulnrich.ssvc(cve_id, no_check_certificate)
        exploitation, automatable, technical_impact = decision_points

    if mission_well_being:
        outcome = tree["exploitation"][exploitation]["automatable"][automatable]["technical_impact"][technical_impact][mission_well_being]
        return [(cve_id, severity, str(score), outcome, exploitation, automatable, technical_impact, mission_well_being, vector_string, source)]
    else:
        outcomes = []
        for mwb in ["low", "medium", "high"]:
            outcome = tree["exploitation"][exploitation]["automatable"][automatable]["technical_impact"][technical_impact][mwb]
            outcomes.append(outcome)
        return [(cve_id, severity, str(score), "/".join(outcomes), exploitation, automatable, technical_impact, vector_string, source)]
