from generate_ld import url
from typing import List

def build(markdown_path: str, **kwargs) -> list[dict]:
    elements = _build_elements(markdown_path, kwargs["name"])
    main = _build_main(elements, **kwargs)
    return elements + [main]


def _build_main(
    elements: list[dict],
    name: str,
    title: str,
    subtitle: str | None = None,
    approved_on: str | None = None,
    updated_on: str | None = None,
    stale_on: str | None = None,
    retired_on: str | None = None,
) -> dict:
    j = {
        "@id": url.local(f"ohjelmat/{name}"),
        url.atomic("properties/parent"): url.local(),
        url.atomic("properties/isA"): [
            url.local("o/Program"),
            url.local("o/ProgramElement"),
        ],
        url.atomic("properties/name"): title,
        url.local("o/elements"): [e["@id"] for e in elements],
    }
    if subtitle:
        j[url.local("o/subtitle")] = subtitle
    if approved_on:
        j[url.local("o/approvedOn")] = approved_on
    if updated_on:
        j[url.local("o/updatedOn")] = updated_on
    if retired_on:
        j[url.local("o/retiredOn")] = retired_on
    if stale_on:
        j[url.local("o/staleOn")] = stale_on
    return j

def _get_types(element: dict) -> List[str]:
    this_types = []
    for t in element[url.atomic("properties/isA")]:
        this_types += [url.decode(t).replace("o/", "")]
    return this_types

def _get_length(es: List[dict]) -> int:
    i = 0
    for e in es:
        if url.local("o/elements") in e:
            i += _get_length(e[url.local("o/elements")]) + 1
        else:
            i += 1
    return i

def _build_elements(markdown_path: str, parent_name: str) -> list[dict]:
    elements = []
    with open(markdown_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                this_element = _build_element(line, parent_name, _get_length(elements))
                if 'ActionItem' in _get_types(this_element):
                    if 'ActionList' in _get_types(elements[-1]):
                        elements[-1][url.local("o/elements")] += [this_element]
                    else:
                        elements += [_build_actionlist_element(line, parent_name, _get_length(elements))]
                else:
                    elements += [this_element]
    return elements

def _build_actionlist_element(line: str, parent_name: str, num: int) -> dict:
    name = f"{parent_name}e{num}"
    return {
        "@id": url.local(f"ohjelmat/{name}"),
        url.atomic("properties/isA"): [
            url.local("o/ActionList"),
            url.local("o/ProgramElement"),
        ],
        url.local("o/elements"): [_build_element(line, parent_name, num+1)],
    }


def _build_element(line: str, parent_name: str, num: int) -> dict:
    name = f"{parent_name}e{num}"
    if line.startswith("#"):
        return {
            "@id": url.local(f"ohjelmat/{name}"),
            url.atomic("properties/isA"): [
                url.local("o/Heading"),
                url.local("o/ProgramElement"),
            ],
            url.atomic("properties/name"): line.lstrip("# "),
            url.local("o/headingLevel"): len(line) - len(line.lstrip("#")),
        }
    elif line.startswith("* "):
        return {
            "@id": url.local(f"ohjelmat/{name}"),
            url.atomic("properties/isA"): [
                url.local("o/ActionItem"),
                url.local("o/ProgramElement"),
            ],
            url.atomic("properties/description"): line[1:].strip(),
        }
    else:
        return {
            "@id": url.local(f"ohjelmat/{name}"),
            url.atomic("properties/isA"): [
                url.local("o/Paragraph"),
                url.local("o/ProgramElement"),
            ],
            url.atomic("properties/description"): line,
        }
