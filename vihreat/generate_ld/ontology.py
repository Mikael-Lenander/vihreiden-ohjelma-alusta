from generate_ld import url


def build() -> list[dict]:
    return [
        _build_ontology(),
        _build_Program(),
        _build_Paragraph(),
        _build_title(),
        _build_elements(),
        _build_approvedOn(),
        _build_text(),
    ]


def _build_ontology() -> dict:
    return {
        "@id": url.local("o"),
        url.atomic("properties/parent"): url.local(),
        url.atomic("properties/shortname"): "ontology",
        url.atomic("properties/description"): "Vihreiden ohjelma-alustan ontologia.",
        url.atomic("properties/isA"): [url.atomic("class/ontology")],
        url.atomic("properties/classes"): [
            url.local("o/Program"),
            url.local("o/Paragraph"),
        ],
        url.atomic("properties/properties"): [
            url.local("o/title"),
            url.local("o/elements"),
            url.local("o/approvedOn"),
            url.local("o/text"),
        ],
        url.atomic("properties/instances"): [],
    }


def _build_Program() -> dict:
    return {
        "@id": url.local("o/Program"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "program",
        url.atomic("properties/description"): "Ohjelma.",
        url.atomic("properties/isA"): [url.atomic("classes/Class")],
        url.atomic("properties/requires"): [
            url.local("o/title"),
            url.local("o/elements"),
        ],
        url.atomic("properties/recommends"): [url.local("o/approvedOn")],
    }


def _build_Paragraph() -> dict:
    return {
        "@id": url.local("o/Paragraph"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "paragraph",
        url.atomic(
            "properties/description"
        ): "Tekstikappale, joka esiintyy osana ohjelmaa.",
        url.atomic("properties/isA"): [url.atomic("classes/Class")],
        url.atomic("properties/requires"): [
            url.atomic("properties/parent"),
            url.local("o/text"),
        ],
    }


def _build_title() -> dict:
    return {
        "@id": url.local("o/title"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "title",
        url.atomic("properties/description"): "Ohjelman otsikko.",
        url.atomic("properties/datatype"): url.atomic("datatypes/string"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_elements() -> dict:
    return {
        "@id": url.local("o/elements"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "elements",
        url.atomic("properties/description"): "Ohjelman sisältö."
        + "\n\n"
        + "Sisältö ilmaistaan listana, jossa listan jokainen alkio on "
        + "ohjelmatekstin pieni osa, esimerkiksi tekstikappale, otsikko, "
        + "kuva tai luetelmakohta (nämä jälkimmäiset ovat meillä "
        + "_linjauksia_). Nyrkkisääntönä voi pitää, että osat ovat sellaisia, "
        + "että niiden väliin voi tulla Markdownissa tyhjä rivi -- siis "
        + "esimerkiksi kappaletta ei tule jakaa osiin tällä tavalla.",
        url.atomic("properties/datatype"): url.atomic("datatypes/resourceArray"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_approvedOn() -> dict:
    return {
        "@id": url.local("o/approvedOn"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "approvedon",
        url.atomic("properties/description"): "Päivämäärä, jona ohjelma hyväksyttiin.",
        url.atomic("properties/datatype"): url.atomic("datatypes/date"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_text() -> dict:
    return {
        "@id": url.local("o/text"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "text",
        url.atomic("properties/description"): "Tekstisisältö (markdown-muodossa).",
        url.atomic("properties/datatype"): url.atomic("datatypes/markdown"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }
