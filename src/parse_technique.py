import html_to_json
from constants import (
    CREATOR_IDENTITY,
    GET_TMFK_DOMAIN,
    GET_TMFK_SOURCE,
    TMFK_PATH,
    TMFK_PLATFORM,
    Mode,
)
from custom_tmfk_objects import Technique
from git_tools import get_file_creation_date, get_file_modification_date
from marko.ext.gfm import gfm


def handle_description_markup(description_row: dict) -> str:
    mdescription = ""
    if "code" in description_row:
        codes = [c["_value"] for c in description_row["code"]]
        mdescription = description_row["_values"][0]
        for i, code in enumerate(codes):
            mdescription += " " + code + description_row["_values"][i + 1]
    else:
        mdescription = description_row["_value"]
    return mdescription


def parse_technique(file_path: str, mode: Mode) -> tuple[Technique, dict]:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        html_content = gfm(content)
        json_content = html_to_json.convert(html_content)
        modified_datetime = get_file_modification_date(
            repo_path=TMFK_PATH, file_path=file_path
        )
        creation_datetime = get_file_creation_date(
            repo_path=TMFK_PATH, file_path=file_path
        )

        technique_name = json_content["h1"][0]["_value"]
        tmfk_id = json_content["p"][1]["_values"][0].split(":")[-1].strip()
        t = [a["_value"] for a in json_content["p"][1]["a"]]
        mitre_attack_techniques = list(filter(lambda x: x.startswith("T"), t))
        tmfk_tactics = [
            t.replace(" ", "-").lower()
            for t in list(filter(lambda x: not x.startswith("T"), t))
        ]

        page_name = technique_name.lower().replace(" ", "%20")
        external_references = [
            {
                "source_name": GET_TMFK_SOURCE(mode=mode),
                "external_id": tmfk_id,
                "url": f"https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/{page_name}",
            },
        ]

        technique = Technique(
            x_mitre_platforms=[TMFK_PLATFORM],
            x_mitre_domains=[GET_TMFK_DOMAIN(mode=mode)],
            created=creation_datetime,
            modified=modified_datetime,
            created_by_ref=CREATOR_IDENTITY,
            external_references=external_references,
            name=technique_name,
            description="\n\n".join(
                [handle_description_markup(d) for d in json_content["p"][2:]]
            ),
            kill_chain_phases=[
                {
                    "kill_chain_name": GET_TMFK_SOURCE(mode=mode),
                    "phase_name": t,
                }
                for t in tmfk_tactics
            ],
            x_mitre_is_subtechnique=False,
            x_mitre_version="1.0",
            x_mitre_modified_by_ref=CREATOR_IDENTITY,
            x_mitre_attack_spec_version="2.1.0",
            x_mitre_ids=mitre_attack_techniques,
        )
        return technique
