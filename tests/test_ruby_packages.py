"""Ruby gems are recognised and scored within their own ecosystem."""

import json

import pytest
from click.testing import CliRunner

from taintrace.cli import cli
from taintrace.db import KnownPackagesDB


@pytest.mark.parametrize("name", ["rails", "nokogiri", "devise", "pg", "redis", "sidekiq"])
def test_common_gems_are_known(name):
    assert KnownPackagesDB().is_known(name, "ruby")


def test_ruby_similarity_stays_in_its_ecosystem():
    db = KnownPackagesDB()
    assert "nokogiri" in {name for name, _ in db.get_similar("nokogirii", ecosystem="ruby")}
    assert "requests" not in {name for name, _ in db.get_similar("raquests", ecosystem="ruby")}
    assert not db.is_known("rails", "python")
    assert not db.is_known("requests", "ruby")


def test_check_gemfile_recognises_gems_and_flags_typo(tmp_path):
    lockfile = tmp_path / "Gemfile.lock"
    lockfile.write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    rails (7.1.3)\n      actionpack (= 7.1.3)\n"
        "    nokogiri (1.16.5)\n    nokogirii (1.16.5)\n"
        "\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n  nokogiri\n  nokogirii\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["check", str(lockfile), "--format", "json"])
    assert result.exit_code == 1, result.output
    output = json.loads(result.output)
    results = {item["package"]: item for item in output["results"]}
    assert output["summary"]["total"] == 3
    assert output["summary"]["suspects"] == 1
    assert results["rails"]["risk_score"] == 0
    assert results["nokogiri"]["risk_score"] == 0
    assert "nokogiri" in results["nokogirii"]["similar_to"]
