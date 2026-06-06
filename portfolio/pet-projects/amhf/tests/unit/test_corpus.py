"""Unit tests for amhf.corpus — YAML loader and CorpusEntry validation."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
import yaml
from pydantic import ValidationError

from amhf.corpus import Corpus, CorpusEntry


@pytest.fixture()
def all_corpus_paths(corpus_dir: Path) -> list[Path]:
    return [corpus_dir / f"{cls}.yaml" for cls in ("sqli", "xss", "cmdi", "pathtrav")]


def test_load_each_stub_yaml(corpus_dir: Path) -> None:
    """Каждый из 4 стаб-файлов парсится и содержит >= 5 entries."""
    for cls in ("sqli", "xss", "cmdi", "pathtrav"):
        corpus = Corpus.from_yaml_paths([corpus_dir / f"{cls}.yaml"])
        assert len(corpus) >= 5
        for entry in corpus.entries:
            assert entry.cls == cls
            assert entry.payload  # non-empty


def test_class_keyword_alias_works(corpus_dir: Path) -> None:
    """YAML использует ключ ``class:`` — он должен попасть в .cls без проблем."""
    corpus = Corpus.from_yaml_paths([corpus_dir / "sqli.yaml"])
    sample = corpus.entries[0]
    assert sample.cls == "sqli"
    # populate_by_name=True — поле также доступно через .cls.
    assert hasattr(sample, "cls")


def test_filter_class(all_corpus_paths: list[Path]) -> None:
    """filter_class=xss возвращает только XSS-entries."""
    corpus = Corpus.from_yaml_paths(all_corpus_paths, filter_class="xss")
    assert len(corpus) >= 5
    assert all(e.cls == "xss" for e in corpus.entries)


def test_max_payloads(all_corpus_paths: list[Path]) -> None:
    """max_payloads урезает выборку (сверху)."""
    corpus = Corpus.from_yaml_paths(all_corpus_paths, max_payloads=3)
    assert len(corpus) == 3


def test_bad_yaml_missing_id(tmp_path: Path) -> None:
    """Запись без обязательного ``id`` ломает валидацию pydantic."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "- class: sqli\n  payload: \"x\"\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        Corpus.from_yaml_paths([bad])


def test_bad_yaml_unknown_extra_field(tmp_path: Path) -> None:
    """extra-поля запрещены — ловим ValidationError."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "- id: x\n"
        "  class: sqli\n"
        "  payload: \"y\"\n"
        "  unknown_field: 123\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        Corpus.from_yaml_paths([bad])


def test_corpus_root_must_be_list(tmp_path: Path) -> None:
    """Корень YAML должен быть списком."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("just_a_string\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a YAML list"):
        Corpus.from_yaml_paths([bad])


def test_empty_corpus_rejected(tmp_path: Path) -> None:
    """from_yaml_paths падает, если после фильтра ничего не осталось."""
    p = tmp_path / "empty.yaml"
    p.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="No corpus entries loaded"):
        Corpus.from_yaml_paths([p])


def test_sample_deterministic(corpus_dir: Path) -> None:
    """sample(rng) детерминирован при фикс. seed."""
    corpus = Corpus.from_yaml_paths([corpus_dir / "sqli.yaml"])
    rng_a = np.random.default_rng(42)
    rng_b = np.random.default_rng(42)
    assert corpus.sample(rng_a).id == corpus.sample(rng_b).id


def test_by_class_lookup(all_corpus_paths: list[Path]) -> None:
    corpus = Corpus.from_yaml_paths(all_corpus_paths)
    sqli_entries = corpus.by_class("sqli")
    assert len(sqli_entries) >= 5
    assert all(e.cls == "sqli" for e in sqli_entries)
    # by_class returns a copy — mutating shouldn't leak.
    sqli_entries.clear()
    assert len(corpus.by_class("sqli")) >= 5


def test_sample_class(all_corpus_paths: list[Path]) -> None:
    corpus = Corpus.from_yaml_paths(all_corpus_paths)
    rng = np.random.default_rng(0)
    sample = corpus.sample_class("xss", rng)
    assert sample.cls == "xss"
    with pytest.raises(KeyError):
        corpus.sample_class("not-a-class", rng)


def test_corpus_construction_empty_rejected() -> None:
    with pytest.raises(ValueError, match="at least one entry"):
        Corpus([])


def test_yaml_to_corpus_entry_direct() -> None:
    """Direct CorpusEntry validation from a parsed YAML scalar."""
    data = yaml.safe_load(
        "id: foo\n"
        "class: sqli\n"
        "payload: \"' or 1=1\"\n"
        "expected_markers: [AMHF_FLAG_]\n"
    )
    entry = CorpusEntry.model_validate(data)
    assert entry.cls == "sqli"
    assert entry.payload == "' or 1=1"
    assert entry.expected_markers == ["AMHF_FLAG_"]
    assert entry.difficulty == "easy"  # default
