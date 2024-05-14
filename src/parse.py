import os
from datetime import datetime
from pathlib import Path

from constants import (
    ATTACK_SPEC_VERSION,
    CREATOR_IDENTITY,
    DEFAULT_CREATOR_JSON,
    MITIGATIONS_PATH,
    TACTICS_PATH,
    TECHNIQUES_PATH,
    TMFK_PATH,
    TMFK_TACTICS_MAP,
    TMFK_VERSION,
    Mode,
    ModeEnumAttribute,
    get_collection_id,
    get_tmfk_domain,
    get_tmfk_source,
)
from custom_tmfk_objects import Collection, ObjectRef, Relationship
from git_tools import get_last_commit_hash, get_first_commit_date
from mitreattack.stix20.custom_attack_objects import Matrix
from parse_mitigation import (
    handle_folder,
    parse_mitigation,
    parse_relationship_created_modified_fields,
)
from parse_tactic import parse_tactic
from parse_technique import parse_technique
from stix2 import Bundle, parse


def parse_tmfk(mode: ModeEnumAttribute) -> None:
    tactics = {}
    objects = []
    techniques = {}

    for tactic_name in TMFK_TACTICS_MAP:
        tactic_file = TACTICS_PATH / tactic_name / "index.md"
        tactic = parse_tactic(tactic_file, tactic_name, mode)
        objects.append(tactic)
        tactics[tactic_name] = tactic

    techniques_listing = os.listdir(TECHNIQUES_PATH)
    for _, file_name in enumerate(list(techniques_listing)):
        file_path = os.path.join(TECHNIQUES_PATH, file_name)
        technique = parse_technique(file_path=file_path, mode=mode)
        techniques[technique.get_id(mode)] = technique
        objects.append(technique)

    mitigations_listing = list(
        filter(
            lambda x: x.endswith(".md") and x != "index.md",
            os.listdir(MITIGATIONS_PATH),
        )
    )

    folders = list(filter(lambda x: "." not in x, os.listdir(MITIGATIONS_PATH)))
    for _, file_name in enumerate(mitigations_listing):
        file_path = os.path.join(MITIGATIONS_PATH, file_name)
        mitigation, ids = parse_mitigation(file_path=file_path)
        objects.append(mitigation)

        for idx in ids:
            technique = techniques[idx]

            relationship_dt = parse_relationship_created_modified_fields(
                repo_path=TMFK_PATH,
                file_path=file_path,
                technique=technique,
            )
            created, modified = relationship_dt["created"], relationship_dt["modified"]

            objects.append(
                Relationship(
                    source_ref=mitigation.id,
                    description=mitigation.description.split(".")[0],
                    relationship_type="mitigates",
                    target_ref=technique.id,
                    created_by_ref=CREATOR_IDENTITY,
                    x_mitre_version=TMFK_VERSION,
                    x_mitre_modified_by_ref=CREATOR_IDENTITY,
                    x_mitre_attack_spec_version="2.1.0",
                    x_mitre_domains=[get_tmfk_domain(mode=mode)],
                    created=created,
                    modified=modified,
                )
            )

    for folder in folders:
        mitigations, ids = handle_folder(folder=folder)
        for key in mitigations:
            objects.append(mitigations[key])

        for idx in ids:
            for t in ids[idx]:
                technique = techniques[t]

                relationship_dt = parse_relationship_created_modified_fields(
                    repo_path=TMFK_PATH,
                    file_path=file_path,
                    technique=technique,
                )
                created, modified = (
                    relationship_dt["created"],
                    relationship_dt["modified"],
                )

                objects.append(
                    Relationship(
                        source_ref=idx,
                        description=mitigations[idx].description.split(".")[0],
                        relationship_type="mitigates",
                        target_ref=technique,
                        created_by_ref=CREATOR_IDENTITY,
                        x_mitre_version=TMFK_VERSION,
                        x_mitre_modified_by_ref=CREATOR_IDENTITY,
                        x_mitre_attack_spec_version="2.1.0",
                        x_mitre_domains=[get_tmfk_domain(mode=mode)],
                        created=created,
                        modified=modified,
                    )
                )

    matrix = Matrix(
        tactic_refs=[tactics[t].id for t in tactics],
        created=get_first_commit_date(repo_path=TMFK_PATH),
        modified=datetime.now(),
        created_by_ref=CREATOR_IDENTITY,
        external_references=[
            {
                "external_id": "tmfk",
                "source_name": get_tmfk_source(mode=mode),
                "url": "https://microsoft.github.io/Threat-Matrix-for-Kubernetes",
            }
        ],
        name="Threat Matrix for Kubernetes",
        description="The purpose of the threat matrix for Kubernetes is to conceptualize the known tactics, techniques, and procedures (TTP) that adversaries may use against Kubernetes environments. Inspired from MITRE ATT&CK, the threat matrix for Kubernetes is designed to give quick insight into a potential TTP that an adversary may be using in their attack campaign. The threat matrix for Kubernetes contains also mitigations specific to Kubernetes environments and attack techniques.",
        x_mitre_version=TMFK_VERSION,
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
        x_mitre_modified_by_ref=CREATOR_IDENTITY,
        spec_version="2.1",
        x_mitre_domains=[get_tmfk_domain(mode=mode)],
        allow_custom=True,
    )
    objects.append(matrix)

    identity = parse(data=DEFAULT_CREATOR_JSON, allow_custom=True)
    objects.append(identity)

    collection = Collection(
        id=get_collection_id(mode=mode),
        spec_version="2.1",
        name="Threat Matrix for Kubernetes",
        description="The purpose of the threat matrix for Kubernetes is to conceptualize the known tactics, techniques, and procedures (TTP) that adversaries may use against Kubernetes environments. Inspired from MITRE ATT&CK, the threat matrix for Kubernetes is designed to give quick insight into a potential TTP that an adversary may be using in their attack campaign. The threat matrix for Kubernetes contains also mitigations specific to Kubernetes environments and attack techniques.",
        created=get_first_commit_date(repo_path=TMFK_PATH),
        modified=datetime.now(),
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
        x_mitre_version=TMFK_VERSION,
        created_by_ref=CREATOR_IDENTITY,
        x_mitre_contents=[
            ObjectRef(object_ref=obj.id, object_modified=obj.modified)
            for obj in objects
        ],
    )

    bundle = Bundle(collection, objects, allow_custom=True)
    commit_hash = get_last_commit_hash(TMFK_PATH)
    output_file_last = (
        Path(__file__).parent.parent / "build" / f"tmfk_{mode.name.lower()}.json"
    )
    with open(output_file_last, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))

    output_file_versioned = (
        Path(__file__).parent.parent
        / "build"
        / f"tmfk_{mode.name.lower()}_{commit_hash}.json"
    )
    with open(output_file_versioned, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))


if __name__ == "__main__":
    for mode in Mode:
        parse_tmfk(mode)
