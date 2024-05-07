import os

import html_to_json
from constants import (
    get_tmfk_source,
    MITIGATIONS_PATH,
)
from marko.ext.gfm import gfm
from stix2 import CourseOfAction


def handle_description_markup(description_row: dict) -> str:
    mdescription = ""
    if "code" in description_row:
        codes = [c["_value"] for c in description_row["code"]]
        if "_values" in description_row:
            mdescription = description_row["_values"][0]
            for i, code in enumerate(codes):
                mdescription += " " + code + description_row["_values"][i + 1]
        else:
            mdescription = description_row["_value"] + codes[0]
    else:
        mdescription = description_row["_value"]
    return mdescription

def craft_mitigation_url(tmfk_id, mitigation_name, parent_mitigations):
    mid = "/"
    if len(parent_mitigations) != 0:
        mid = f"/{parent_mitigations[0]}/"
    return "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/mitigations" + mid + f"{tmfk_id}%20{mitigation_name.replace(' ', '%20')}/"

def parse_mitigation(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        html_content = gfm(content)
        json_content = html_to_json.convert(html_content)
        mitigation_name = json_content["h1"][0]["_value"]
        tmfk_id = json_content["p"][1]["_values"][0].split(":")[-1].strip()
        mitre_attack_mitigations = []
        parent_mitigations = []
        if "_values" in json_content["p"][1]:
            if "MITRE mitigation: -" not in json_content["p"][1]["_values"]:                  
                t = [a["_value"] for a in json_content["p"][1]["a"]]
                mitre_attack_mitigations = list(filter(lambda x: x.startswith("M") and not x.startswith("MS"), t))
                parent_mitigations = list(filter(lambda x: x.startswith("MS"), t))
        
        parent_mitigation = None
        if len(parent_mitigations) != 0:
            parent_mitigation = parent_mitigations[0]

        mitigation = CourseOfAction(
            allow_custom=True,
            external_references=[
                {
                    "source_name": f"{get_tmfk_source()}",
                    "url": craft_mitigation_url(tmfk_id=tmfk_id, mitigation_name=mitigation_name, parent_mitigations=parent_mitigations),
                    "external_id": tmfk_id,
                }
            ],
            name=mitigation_name,
            description="\n\n".join(
                [handle_description_markup(d) for d in json_content["p"][2:] if "_value" in d and '!!!' not in d["_value"]]
            ),
            x_mitre_ids=mitre_attack_mitigations,
            x_mitre_parent_mitigation=parent_mitigation
        )
       
        tids = []
        for row in json_content["table"][0]["tbody"][0]["tr"]:
            tids.append(row["td"][0]["a"][0]["_value"])

        return mitigation, tids


def handle_folder(folder: str):
    current_path = MITIGATIONS_PATH / folder
    listing = os.listdir(current_path)
    mitigations = {}
    mapping = {}
    for _, file_name in enumerate(listing):
        file_path = current_path / file_name
        mitigation, tids = parse_mitigation(file_path=file_path)
        mapping[mitigation.id] = tids
        mitigations[mitigation.id] = mitigation
    return mitigations, mapping
