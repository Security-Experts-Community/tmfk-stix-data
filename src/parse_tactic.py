import re

import html_to_json
from constants import (
    ATTACK_SPEC_VERSION,
    CREATOR_IDENTITY,
    TMFK_PATH,
    TMFK_TACTICS_MAP,
    TMFK_VERSION,
    Mode,
    get_tmfk_domain,
    get_tmfk_source,
)
from git_tools import get_file_creation_date, get_file_modification_date
from marko.ext.gfm import gfm
from mitreattack.stix20.custom_attack_objects import Tactic


def parse_tactic(file_path: str, tactic_name: str, mode: Mode) -> Tactic:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        html_content = gfm(content)
        json_content = html_to_json.convert(html_content)

        tactic_id = TMFK_TACTICS_MAP[tactic_name]
        tactic_description = json_content["p"][1]["_value"]
        tactic_link = f"https://microsoft.github.io/Threat-Matrix-for-Kubernetes/tactics/{tactic_name}"
        splitted = re.sub(
            "([A-Z][a-z]+)", r" \1", re.sub("([A-Z]+)", r" \1", tactic_name)
        ).split()
        tactic_display_name = " ".join(splitted)
        modified_datetime = get_file_modification_date(
            repo_path=TMFK_PATH,
            file_path=file_path,
        )
        creation_datetime = get_file_creation_date(
            repo_path=TMFK_PATH,
            file_path=file_path,
        )
        return Tactic(
            x_mitre_domains=[get_tmfk_domain(mode=mode)],
            created=creation_datetime,
            modified=modified_datetime,
            created_by_ref=CREATOR_IDENTITY,
            external_references=[
                {
                    "external_id": tactic_id,
                    "url": tactic_link,
                    "source_name": get_tmfk_source(mode=mode),
                },
            ],
            name=tactic_display_name,
            description=tactic_description,
            x_mitre_version=TMFK_VERSION,
            x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
            x_mitre_modified_by_ref=CREATOR_IDENTITY,
            x_mitre_shortname=tactic_display_name.replace(" ", "-").lower(),
        )
