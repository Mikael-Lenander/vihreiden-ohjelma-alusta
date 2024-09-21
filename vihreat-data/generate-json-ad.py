import os
import yaml
import generate_ld


def generate_ontology():
    ontology = generate_ld.ontology.build()
    generate_ld.io.write(ontology, "ontology")


def generate_programs():
    for md_path, meta_path in iterate_programs():
        with open(meta_path, "r") as f:
            meta = yaml.safe_load(f)
        generate_program(md_path, meta)


def iterate_programs(root = "."):
    for dirpath, dirnames, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith(".md"):
                meta_filename = filename + ".meta.yml"
                if meta_filename in filenames:
                    md_path = f"{dirpath}/{filename}"
                    meta_path = f"{dirpath}/{meta_filename}"
                    yield md_path, meta_path


def generate_program(md_path, meta):
    id = meta["id"]
    species = meta["species"]
    categories = meta["categories"]
    title = meta.get("title", None)

    approved_on = None
    if "approved" in meta:
        approved_on = meta["approved"]["date"].strftime("%Y-%m-%d")

    updated_on = None
    if "updated" in meta:
        updated_on = meta["updated"]["date"].strftime("%Y-%m-%d")

    stale_on = None
    if "stale" in meta:
        stale_on = meta["stale"]["date"].strftime("%Y-%m-%d")

    retired_on = None
    if "retired" in meta:
        retired_on = meta["retired"]["date"].strftime("%Y-%m-%d")

    program = generate_ld.program.build(
        md_path,
        name=meta["id"],
        title=title or species,
        subtitle=species,
        category=categories[0],
        approved_on=approved_on,
        updated_on=updated_on,
        stale_on=stale_on,
        retired_on=retired_on,
    )
    generate_ld.io.write(program, id)


def should_generate_test_programs():
    return os.environ.get("VO_GENEROI_TESTIOHJELMAT", "false") == "true"


def generate_test_programs():
    generate_test_program("px_luo", "luonnos")
    generate_test_program("px_hyv", "voimassa", approved_on="2021-01-01")
    generate_test_program(
        "px_van", "vanhentunut", approved_on="2020-01-01", stale_on="2022-05-03"
    )
    generate_test_program(
        "px_poi",
        "poistunut",
        approved_on="2018-01-01",
        stale_on="2022-05-03",
        retired_on="2023-10-05",
    )


def generate_test_program(name, kind, **kwargs):
    generate_program(
        name,
        "Lorem ipsum dolor sit amet",
        subtitle=f"TESTIOHJELMA ({kind})",
        **kwargs,
    )
    program = generate_ld.program.build(
        "md/tietopoliittinen-ohjelma.md",
        name=name,
        title="Lorem ipsum dolor sit amet",
        subtitle=f"TESTIOHJELMA ({kind})",
        **kwargs,
    )
    generate_ld.io.write(program, id)


if __name__ == "__main__":
    generate_ontology()
    generate_programs()
    if should_generate_test_programs():
        generate_test_programs()
